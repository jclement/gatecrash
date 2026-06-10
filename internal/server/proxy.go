package server

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// proxyHTTP forwards an HTTP request through the SSH tunnel to the client.
func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request, tunnel *TunnelState) {
	conn := tunnel.PickConn()
	if conn == nil {
		http.Error(w, "tunnel offline", http.StatusBadGateway)
		return
	}

	tunnel.Metrics.ActiveConns.Add(1)
	defer tunnel.Metrics.ActiveConns.Add(-1)
	tunnel.Metrics.RequestCount.Add(1)
	tunnel.Metrics.LastRequestAt.Store(time.Now())

	// Extract client IP (strip port)
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	data := protocol.HTTPChannelData{
		RequestID:    uuid.NewString(),
		Method:       r.Method,
		URI:          r.RequestURI,
		Host:         r.Host,
		RemoteAddr:   clientIP,
		TLS:          r.TLS != nil,
		PreserveHost: tunnel.PreservesHost(),
	}

	payload := marshalHTTPChannelData(&data)

	ch, reqs, err := openChannelTimeout(conn, protocol.ChannelHTTP, payload, channelOpenTimeout)
	if err != nil {
		// A 15s channel-open timeout means the SSH transport is dead (half-open).
		// Evict it from the pool FIRST so no concurrent request picks it, then
		// close it: that unblocks the parked OpenChannel goroutine and forces the
		// client to reconnect cleanly instead of lingering as an unusable zombie.
		tunnel.RemoveClient(conn)
		conn.Close()
		slog.Error("failed to open HTTP channel", "tunnel", tunnel.ID, "error", err)
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	// Write the HTTP request in wire format to the channel
	cw := &countingWriter{w: ch}
	if err := r.Write(cw); err != nil {
		slog.Error("failed to write request to tunnel", "tunnel", tunnel.ID, "error", err)
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}
	tunnel.Metrics.BytesIn.Add(cw.n)

	// Only signal end-of-request for non-upgrade requests. Upgrade requests
	// (WebSocket) need the channel to remain bidirectional.
	upgrade := isUpgradeRequest(r)
	if !upgrade {
		if cw, ok := ch.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}

	// Read response from channel. Keep the bufio.Reader so any data buffered
	// beyond the HTTP headers (e.g. WebSocket frames) isn't lost.
	chReader := bufio.NewReader(ch)
	resp, err := http.ReadResponse(chReader, r)
	if err != nil {
		slog.Error("failed to read response from tunnel", "tunnel", tunnel.ID, "error", err)
		http.Error(w, "tunnel read failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Check for WebSocket upgrade
	if isWebSocketUpgrade(resp) {
		s.handleWebSocketUpgrade(w, ch, chReader, resp)
		return
	}

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body with byte counting
	n, _ := io.Copy(w, resp.Body)
	tunnel.Metrics.BytesOut.Add(n)

	slog.Debug("http request proxied",
		"tunnel", tunnel.ID,
		"method", data.Method,
		"uri", data.URI,
		"host", data.Host,
		"status", resp.StatusCode,
		"bytes_out", n,
		"from", clientIP,
	)
}

// handleWebSocketUpgrade hijacks the connection for bidirectional streaming.
func (s *Server) handleWebSocketUpgrade(w http.ResponseWriter, ch gossh.Channel, chReader *bufio.Reader, resp *http.Response) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hj.Hijack()
	if err != nil {
		slog.Error("websocket hijack failed", "error", err)
		return
	}
	defer clientConn.Close()
	setTCPKeepAlive(clientConn, 30*time.Second)

	resp.Write(buf)
	buf.Flush()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(ch, clientConn) // public client → tunnel
		if cw, ok := ch.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		// tunnel → public client. Use a write deadline so a public peer that stops
		// reading (slow-reader / slowloris on the response) can't pin this goroutine
		// and the underlying SSH channel forever.
		copyWithWriteTimeout(clientConn, chReader, streamWriteIdleTimeout)
		clientConn.Close() // unblock the other goroutine
		done <- struct{}{}
	}()
	<-done
	<-done
}

// streamWriteIdleTimeout bounds how long a single write to a hijacked/streamed
// public connection may block before we give up on a stalled reader. It is a
// per-write idle bound, not a session cap: a quiet-but-healthy stream (e.g. an
// idle WebSocket with no data to send) is unaffected because the deadline is
// only armed immediately before each write.
const streamWriteIdleTimeout = 60 * time.Second

// copyWithWriteTimeout is io.Copy with an idle write deadline applied to dst when
// it supports SetWriteDeadline. If the peer stops draining its socket, the blocked
// write fails after `idle` instead of leaking the goroutine and its SSH channel.
func copyWithWriteTimeout(dst io.Writer, src io.Reader, idle time.Duration) (int64, error) {
	wc, _ := dst.(interface{ SetWriteDeadline(time.Time) error })
	buf := make([]byte, 32*1024)
	var total int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if wc != nil {
				wc.SetWriteDeadline(time.Now().Add(idle))
			}
			nw, ew := dst.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw < nr {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

// isUpgradeRequest checks whether the request asks for a protocol upgrade
// (e.g. WebSocket). Used to decide whether to keep the channel bidirectional.
func isUpgradeRequest(r *http.Request) bool {
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

func isWebSocketUpgrade(resp *http.Response) bool {
	return resp.StatusCode == http.StatusSwitchingProtocols &&
		strings.EqualFold(resp.Header.Get("Upgrade"), "websocket")
}

// countingWriter wraps an io.Writer and counts bytes written.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// marshalHTTPChannelData encodes HTTP channel extra data.
func marshalHTTPChannelData(d *protocol.HTTPChannelData) []byte {
	return gossh.Marshal(struct {
		RequestID    string
		Method       string
		URI          string
		Host         string
		RemoteAddr   string
		TLS          bool
		PreserveHost bool
	}{
		RequestID:    d.RequestID,
		Method:       d.Method,
		URI:          d.URI,
		Host:         d.Host,
		RemoteAddr:   d.RemoteAddr,
		TLS:          d.TLS,
		PreserveHost: d.PreserveHost,
	})
}
