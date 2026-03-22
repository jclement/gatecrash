package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
	"github.com/jclement/gatecrash/internal/token"
)

type contextKey string

const ctxKeyTunnelID contextKey = "tunnel_id"

// newSSHServer creates and configures the SSH server.
func (s *Server) newSSHServer() (*ssh.Server, error) {
	hostKeyPath := filepath.Join(filepath.Dir(s.configPath), "host_key")

	sshSrv := &ssh.Server{
		Addr:        fmt.Sprintf("%s:%d", s.cfg.Server.BindAddr, s.cfg.Server.SSHPort),
		IdleTimeout: 90 * time.Second, // Client sends heartbeats every 30s; 3 missed = dead
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			tunnelID, valid := token.Validate(password, s.cfg.LookupSecretHash)
			if !valid {
				slog.Warn("SSH auth failed", "remote", ctx.RemoteAddr())
				return false
			}

			// Check tunnel exists in registry
			t := s.registry.FindByID(tunnelID)
			if t == nil {
				slog.Warn("SSH auth: unknown tunnel", "tunnel", tunnelID, "remote", ctx.RemoteAddr())
				return false
			}

			ctx.SetValue(ctxKeyTunnelID, tunnelID)
			slog.Info("SSH auth success", "tunnel", tunnelID, "remote", ctx.RemoteAddr())
			return true
		},
		// Reject all session requests (we don't allow shell access)
		Handler: func(sess ssh.Session) {
			fmt.Fprintln(sess, "gatecrash tunnel server - shell access not available")
			sess.Exit(1)
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			protocol.ChannelControl: s.handleControlChannel,
			"default": func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
				newChan.Reject(gossh.UnknownChannelType, "unsupported channel type")
			},
		},
		ConnectionFailedCallback: func(conn net.Conn, err error) {
			slog.Debug("SSH connection failed", "remote", conn.RemoteAddr(), "error", err)
		},
	}

	// Load or generate host key
	hostKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	sshSrv.AddHostKey(hostKey)
	s.hostFingerprint = gossh.FingerprintSHA256(hostKey.PublicKey())

	return sshSrv, nil
}

// handleControlChannel handles the gatecrash-control channel opened by clients.
func (s *Server) handleControlChannel(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	tunnelID, ok := ctx.Value(ctxKeyTunnelID).(string)
	if !ok || tunnelID == "" {
		newChan.Reject(gossh.Prohibited, "no tunnel ID")
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		slog.Error("failed to accept control channel", "tunnel", tunnelID, "error", err)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	tunnel := s.registry.FindByID(tunnelID)
	if tunnel == nil {
		slog.Error("tunnel not found after auth", "tunnel", tunnelID)
		return
	}

	// Register the SSH connection with the tunnel
	tunnel.AddClient(conn, conn.RemoteAddr().String())
	slog.Info("tunnel client connected", "tunnel", tunnelID, "remote", conn.RemoteAddr(), "clients", tunnel.ClientCount())
	s.sse.Broadcast("tunnel-connect", tunnelID)

	defer func() {
		tunnel.RemoveClient(conn)
		slog.Info("tunnel client disconnected", "tunnel", tunnelID, "remote", conn.RemoteAddr(), "clients", tunnel.ClientCount())
		s.sse.Broadcast("tunnel-disconnect", tunnelID)
	}()

	// Read control messages until the channel closes
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return // Connection closed
		}
		_ = n
	}
}

func loadOrGenerateHostKey(path string) (gossh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		return gossh.ParsePrivateKey(data)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	pemData, err := gossh.MarshalPrivateKey(priv, "gatecrash host key")
	if err != nil {
		return nil, fmt.Errorf("marshaling key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(pemData), 0o600); err != nil {
		return nil, fmt.Errorf("writing key: %w", err)
	}

	slog.Info("generated SSH host key", "path", path)

	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	return signer, nil
}
