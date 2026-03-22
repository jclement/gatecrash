package server

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// serveTCPForward listens on a port and forwards connections through the SSH tunnel.
// The listener is tracked in s.tcpListeners so it can be stopped on config reload.
func (s *Server) serveTCPForward(tunnel *TunnelState) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.BindAddr, tunnel.ListenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	s.tcpMu.Lock()
	if s.tcpListeners == nil {
		s.tcpListeners = make(map[int]net.Listener)
	}
	s.tcpListeners[tunnel.ListenPort] = listener
	s.tcpMu.Unlock()

	slog.Info("TCP forward listening", "tunnel", tunnel.ID, "addr", addr)

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				slog.Debug("TCP accept stopped", "tunnel", tunnel.ID, "error", err)
				return
			}
			go s.handleTCPConn(conn, tunnel)
		}
	}()

	return nil
}

// reconcileTCPListeners starts listeners for new TCP tunnels and stops listeners
// for removed ones after a config reload.
func (s *Server) reconcileTCPListeners() {
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()

	if s.tcpListeners == nil {
		s.tcpListeners = make(map[int]net.Listener)
	}

	// Build set of ports that should have listeners
	wantPorts := make(map[int]*TunnelState)
	for _, t := range s.registry.AllTunnels() {
		if t.Type == "tcp" && t.ListenPort > 0 {
			wantPorts[t.ListenPort] = t
		}
	}

	// Stop listeners for ports no longer needed
	for port, ln := range s.tcpListeners {
		if _, ok := wantPorts[port]; !ok {
			slog.Info("stopping TCP forward", "port", port)
			ln.Close()
			delete(s.tcpListeners, port)
		}
	}

	// Start listeners for new ports
	for port, tunnel := range wantPorts {
		if _, ok := s.tcpListeners[port]; !ok {
			addr := fmt.Sprintf("%s:%d", s.cfg.Server.BindAddr, port)
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				slog.Error("TCP forward listen failed", "tunnel", tunnel.ID, "port", port, "error", err)
				continue
			}
			s.tcpListeners[port] = ln
			slog.Info("TCP forward listening", "tunnel", tunnel.ID, "addr", addr)

			go func(l net.Listener, t *TunnelState) {
				defer l.Close()
				for {
					conn, err := l.Accept()
					if err != nil {
						slog.Debug("TCP accept stopped", "tunnel", t.ID, "error", err)
						return
					}
					go s.handleTCPConn(conn, t)
				}
			}(ln, tunnel)
		}
	}
}

func (s *Server) handleTCPConn(conn net.Conn, tunnel *TunnelState) {
	defer conn.Close()

	sshConn := tunnel.PickConn()
	if sshConn == nil {
		slog.Debug("TCP forward: tunnel offline", "tunnel", tunnel.ID, "remote", conn.RemoteAddr())
		return
	}

	tunnel.Metrics.ActiveConns.Add(1)
	defer tunnel.Metrics.ActiveConns.Add(-1)
	tunnel.Metrics.RequestCount.Add(1)

	originAddr, originPort := parseAddr(conn.RemoteAddr().String())

	data := gossh.Marshal(struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   "127.0.0.1",
		DestPort:   0, // Client knows its target
		OriginAddr: originAddr,
		OriginPort: originPort,
	})

	ch, reqs, err := sshConn.OpenChannel(protocol.ChannelDirectTCPIP, data)
	if err != nil {
		slog.Error("TCP forward: failed to open channel", "tunnel", tunnel.ID, "error", err)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	// Bidirectional copy with byte counting
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(ch, conn)
		tunnel.Metrics.BytesIn.Add(n)
		if cw, ok := ch.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(conn, ch)
		tunnel.Metrics.BytesOut.Add(n)
		done <- struct{}{}
	}()
	<-done
}

func parseAddr(addr string) (string, uint32) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		parts := strings.Split(addr, ":")
		if len(parts) == 2 {
			host = parts[0]
			portStr = parts[1]
		} else {
			return addr, 0
		}
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint32(port)
}
