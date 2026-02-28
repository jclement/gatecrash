package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// Config holds the client configuration.
type Config struct {
	ServerAddr string // host:port of the SSH server
	Token      string // tunnel token (tunnel_id:secret)
	TargetHost string // target service host
	TargetPort int    // target service port
	HostKey    string // optional SSH host key fingerprint (SHA256:...)
	TargetTLS  string // "", "tls", or "tls-insecure"
}

// Client connects to the gatecrash server and handles tunnel requests.
type Client struct {
	cfg        Config
	version    string
	httpClient *http.Client
}

// New creates a new client instance.
func New(cfg Config, version string) *Client {
	c := &Client{cfg: cfg, version: version}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TargetTLS == "tls-insecure" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	c.httpClient = &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return c
}

// Run connects to the server and handles requests. Reconnects on failure.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		connStart := time.Now()
		err := c.connect(ctx)
		connDuration := time.Since(connStart)

		if ctx.Err() != nil {
			return ctx.Err()
		}

		slog.Warn("connection lost", "error", err, "duration", connDuration.Round(time.Second))

		// Reset backoff if we were connected for a while
		if connDuration > 60*time.Second {
			backoff = time.Second
		}

		slog.Info("reconnecting", "backoff", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}

		// Exponential backoff
		backoff = min(backoff*2, maxBackoff)
	}
}

func (c *Client) connect(ctx context.Context) error {
	slog.Info("connecting", "server", c.cfg.ServerAddr)

	hostKeyCallback := gossh.InsecureIgnoreHostKey()
	if c.cfg.HostKey != "" {
		cb, err := makeHostKeyCallback(c.cfg.HostKey)
		if err != nil {
			return fmt.Errorf("host key: %w", err)
		}
		hostKeyCallback = cb
	} else {
		slog.Warn("no host key fingerprint configured, accepting any server key")
	}

	sshConfig := &gossh.ClientConfig{
		User: "tunnel",
		Auth: []gossh.AuthMethod{
			gossh.Password(c.cfg.Token),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	conn, err := gossh.Dial("tcp", c.cfg.ServerAddr, sshConfig)
	if err != nil {
		return fmt.Errorf("SSH dial: %w", err)
	}
	defer conn.Close()

	slog.Info("connected", "server", c.cfg.ServerAddr)

	// Open control channel
	controlCh, controlReqs, err := conn.OpenChannel(protocol.ChannelControl, nil)
	if err != nil {
		return fmt.Errorf("control channel: %w", err)
	}
	defer controlCh.Close()
	go gossh.DiscardRequests(controlReqs)

	// Send client info
	hostname, _ := os.Hostname()
	info := protocol.ClientInfo{
		Version:  c.version,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
	}
	infoMsg := protocol.ControlMessage{Type: protocol.ControlClientInfo}
	infoMsg.Data, _ = json.Marshal(info)
	infoBytes, _ := json.Marshal(infoMsg)
	controlCh.Write(infoBytes)

	// Start heartbeat
	go c.heartbeatLoop(ctx, controlCh)

	// Register channel handlers for each type the server may open
	httpChs := conn.HandleChannelOpen(protocol.ChannelHTTP)
	tcpChs := conn.HandleChannelOpen(protocol.ChannelDirectTCPIP)

	// Wait for connection to close
	connDone := make(chan struct{})
	go func() {
		conn.Wait()
		close(connDone)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-connDone:
			return fmt.Errorf("connection closed")
		case newCh, ok := <-httpChs:
			if !ok {
				return fmt.Errorf("HTTP channel closed")
			}
			go c.handleHTTPChannel(newCh)
		case newCh, ok := <-tcpChs:
			if !ok {
				return fmt.Errorf("TCP channel closed")
			}
			go c.handleDirectTCPIP(newCh)
		}
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, ch gossh.Channel) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := protocol.ControlMessage{Type: protocol.ControlHeartbeat}
			data, _ := json.Marshal(msg)
			if _, err := ch.Write(data); err != nil {
				return
			}
		}
	}
}

func (c *Client) targetAddr() string {
	return net.JoinHostPort(c.cfg.TargetHost, fmt.Sprintf("%d", c.cfg.TargetPort))
}

func (c *Client) targetScheme() string {
	if c.cfg.TargetTLS != "" {
		return "https"
	}
	return "http"
}

// makeHostKeyCallback creates a host key callback that verifies the server key
// fingerprint matches the expected SHA256 fingerprint.
func makeHostKeyCallback(fingerprint string) (gossh.HostKeyCallback, error) {
	// Expect format: SHA256:base64digest
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return nil, fmt.Errorf("expected SHA256:... format, got %q", fingerprint)
	}
	expectedDigest := strings.TrimPrefix(fingerprint, "SHA256:")
	// Validate it's valid base64
	if _, err := base64.RawStdEncoding.DecodeString(expectedDigest); err != nil {
		return nil, fmt.Errorf("invalid fingerprint base64: %w", err)
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		actual := gossh.FingerprintSHA256(key)
		if actual != fingerprint {
			return fmt.Errorf("host key mismatch: got %s, want %s", actual, fingerprint)
		}
		return nil
	}, nil
}
