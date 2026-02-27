package server

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// proxyHTTP forwards an HTTP request through the SSH tunnel to the client.
func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request, tunnel *TunnelState) {
	conn := tunnel.SSHConn()
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
		PreserveHost: tunnel.PreserveHost,
	}

	payload := marshalHTTPChannelData(&data)

	ch, reqs, err := conn.OpenChannel(protocol.ChannelHTTP, payload)
	if err != nil {
		slog.Error("failed to open HTTP channel", "tunnel", tunnel.ID, "error", err)
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	// Write the HTTP request in wire format to the channel
	if err := r.Write(ch); err != nil {
		slog.Error("failed to write request to tunnel", "tunnel", tunnel.ID, "error", err)
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	// Signal we're done writing the request
	if cw, ok := ch.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}

	// Read response from channel
	resp, err := http.ReadResponse(bufio.NewReader(ch), r)
	if err != nil {
		slog.Error("failed to read response from tunnel", "tunnel", tunnel.ID, "error", err)
		http.Error(w, "tunnel read failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Check for WebSocket upgrade
	if isWebSocketUpgrade(resp) {
		s.handleWebSocketUpgrade(w, ch, resp)
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
func (s *Server) handleWebSocketUpgrade(w http.ResponseWriter, ch gossh.Channel, resp *http.Response) {
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

	resp.Write(buf)
	buf.Flush()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(ch, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, ch)
		done <- struct{}{}
	}()
	<-done
}

func isWebSocketUpgrade(resp *http.Response) bool {
	return resp.StatusCode == http.StatusSwitchingProtocols &&
		resp.Header.Get("Upgrade") == "websocket"
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
