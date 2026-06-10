package server

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// serveTCPForward listens on a port and forwards connections through the SSH tunnel.
// The listener is tracked in s.tcpListeners so it can be stopped on config reload.
func (s *Server) serveTCPForward(tunnel *TunnelState) error {
	port := tunnel.Port()
	addr := fmt.Sprintf("%s:%d", s.cfgSnapshot().Server.BindAddr, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	s.tcpMu.Lock()
	if s.tcpListeners == nil {
		s.tcpListeners = make(map[int]net.Listener)
	}
	s.tcpListeners[port] = listener
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
	// Snapshot bind address and tunnels BEFORE taking tcpMu: read s.cfg under its
	// own lock (it races the reload pointer swap otherwise), and avoid establishing
	// a tcpMu→registry.mu lock order by querying the registry up front.
	bindAddr := s.cfgSnapshot().Server.BindAddr

	// Build set of ports that should have listeners
	wantPorts := make(map[int]*TunnelState)
	for _, t := range s.registry.AllTunnels() {
		if t.TunnelType() == "tcp" {
			if p := t.Port(); p > 0 {
				wantPorts[p] = t
			}
		}
	}

	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()

	if s.tcpListeners == nil {
		s.tcpListeners = make(map[int]net.Listener)
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
			addr := fmt.Sprintf("%s:%d", bindAddr, port)
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

	// Detect a public peer that vanishes without FIN/RST so the io.Copy pumps
	// below don't block forever reading from a dead socket.
	setTCPKeepAlive(conn, 30*time.Second)

	// IP policy gate. TCP tunnels can't present an authorization page, so a
	// blocked client is simply dropped; IPs are enrolled out-of-band via the
	// admin panel or enrollment link (the browser's egress IP matches the
	// TCP client's).
	if pol := s.registry.FindIPPolicy(tunnel.IPPolicy()); pol != nil {
		ip := tcpRemoteIP(conn)
		if !pol.Allows(ip) && !s.ipAllow.IsGranted(pol.ID, ip) {
			slog.Debug("ip policy blocked TCP conn", "tunnel", tunnel.ID, "policy", pol.ID, "remote", conn.RemoteAddr())
			return
		}
	}

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

	ch, reqs, err := openChannelTimeout(sshConn, protocol.ChannelDirectTCPIP, data, channelOpenTimeout)
	if err != nil {
		// A channel-open timeout means the SSH transport is dead. Evict it from
		// the pool FIRST so no concurrent connection picks it, then close it to
		// unblock the parked OpenChannel goroutine and force a clean reconnect.
		tunnel.RemoveClient(sshConn)
		sshConn.Close()
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
		// Write deadline guards against a public TCP client that stops reading,
		// which would otherwise pin this goroutine and the SSH channel forever.
		n, _ := copyWithWriteTimeout(conn, ch, streamWriteIdleTimeout)
		tunnel.Metrics.BytesOut.Add(n)
		conn.Close() // unblock the other goroutine
		done <- struct{}{}
	}()
	<-done
	<-done
}

// tcpRemoteIP returns the source IP of a forwarded TCP connection.
func tcpRemoteIP(conn net.Conn) net.IP {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	return net.ParseIP(host)
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
