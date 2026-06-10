package server

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const (
	// keepaliveInterval is how often the server probes each connected tunnel
	// client with an SSH global request to confirm the link is two-way alive.
	keepaliveInterval = 20 * time.Second
	// keepaliveTimeout bounds how long we wait for the probe reply before
	// declaring the connection dead. SendRequest blocks forever on a half-open
	// (silently dropped) TCP connection, so this timeout is mandatory.
	keepaliveTimeout = 10 * time.Second
	// channelOpenTimeout bounds OpenChannel on the forward path. On a half-open
	// client conn the channel-open packet is buffered locally but the reply
	// never arrives, so OpenChannel would otherwise block indefinitely.
	channelOpenTimeout = 15 * time.Second
)

// sshAuthGate applies per-IP rate limiting and bounds concurrent bcrypt work
// for SSH authentication. It returns proceed=false to reject the attempt cheaply
// (rate-limited, or overloaded). On proceed=true the caller MUST call release()
// when the bcrypt check is done, to free the concurrency slot.
func (s *Server) sshAuthGate(remoteIP string) (proceed bool, release func()) {
	if !s.sshAuthLimiter.allow(remoteIP) {
		return false, nil
	}
	select {
	case s.bcryptSem <- struct{}{}:
		return true, func() { <-s.bcryptSem }
	case <-time.After(s.sshAuthAcquireTimeout):
		// All bcrypt slots busy long enough that this is likely a flood; shed it.
		return false, nil
	}
}

// pingConn sends an SSH keepalive global request and reports whether the peer
// answered within timeout. Any reply (even a rejection) proves the link is
// alive in both directions — this matches OpenSSH keepalive semantics. The
// timeout is essential: gossh.Conn.SendRequest blocks on an internal channel
// with no deadline and never returns on a half-open connection.
func pingConn(conn gossh.Conn, timeout time.Duration) bool {
	res := make(chan bool, 1)
	go func() {
		// A reply (accepted or not) means err == nil → the round-trip completed.
		_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
		res <- err == nil
	}()
	select {
	case alive := <-res:
		return alive
	case <-time.After(timeout):
		return false
	}
}

// keepaliveLoop probes a connected tunnel client until stop is signalled or a
// probe fails. On failure it evicts the connection from the pool AND closes it.
// Closing is what unblocks any goroutines parked in OpenChannel against this
// (now dead) connection — RemoveClient alone would not.
func (s *Server) keepaliveLoop(conn gossh.Conn, tunnel *TunnelState, tunnelID string, stop <-chan struct{}) {
	s.keepaliveLoopParams(conn, tunnel, tunnelID, stop, keepaliveInterval, keepaliveTimeout)
}

// keepaliveLoopParams is keepaliveLoop with explicit timings, for testing.
func (s *Server) keepaliveLoopParams(conn gossh.Conn, tunnel *TunnelState, tunnelID string, stop <-chan struct{}, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if pingConn(conn, timeout) {
				continue
			}
			slog.Warn("tunnel client keepalive failed, evicting dead connection",
				"tunnel", tunnelID, "remote", conn.RemoteAddr())
			tunnel.RemoveClient(conn)
			conn.Close() // unblocks goroutines parked in OpenChannel on this conn
			return
		}
	}
}

// openChannelTimeout opens an SSH channel but gives up after timeout. It does
// NOT close the underlying connection: that conn is shared by other concurrent
// requests, and closing it here would break them. Instead the caller evicts the
// conn from the pool (so no new request picks it) and the keepalive loop is the
// single authority that actually closes a dead conn — which is what unblocks the
// parked OpenChannel goroutine below. The result channel is buffered, so that
// goroutine never leaks even if it stays parked until the keepalive reap.
func openChannelTimeout(conn gossh.Conn, chType string, data []byte, timeout time.Duration) (gossh.Channel, <-chan *gossh.Request, error) {
	type result struct {
		ch   gossh.Channel
		reqs <-chan *gossh.Request
		err  error
	}
	resCh := make(chan result, 1) // buffered so the goroutine never leaks
	go func() {
		ch, reqs, err := conn.OpenChannel(chType, data)
		resCh <- result{ch, reqs, err}
	}()

	select {
	case r := <-resCh:
		return r.ch, r.reqs, r.err
	case <-time.After(timeout):
		return nil, nil, fmt.Errorf("open %s channel: timed out after %s (client unresponsive)", chType, timeout)
	}
}

// setTCPKeepAlive enables OS-level TCP keepalives on a connection so a peer that
// vanishes without a FIN/RST (half-open) is detected by the kernel and pending
// reads/writes eventually error out instead of blocking forever.
func setTCPKeepAlive(conn net.Conn, period time.Duration) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		// Unwrap TLS and similar wrappers.
		if nc, has := conn.(interface{ NetConn() net.Conn }); has {
			tc, ok = nc.NetConn().(*net.TCPConn)
		}
	}
	if !ok {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(period)
}

// keepAliveListener wraps a TCP listener to enable keepalives on every accepted
// connection. Used for the SSH listener, whose connections gliderlabs would
// otherwise leave without OS-level liveness detection.
type keepAliveListener struct {
	*net.TCPListener
	period time.Duration
}

func (l keepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.TCPListener.Accept()
	if err != nil {
		return nil, err
	}
	setTCPKeepAlive(conn, l.period)
	return conn, nil
}
