package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// handleHTTPChannel processes an incoming HTTP request from the server.
func (c *Client) handleHTTPChannel(newCh gossh.NewChannel) {
	// Parse channel extra data
	var data protocol.HTTPChannelData
	if err := gossh.Unmarshal(newCh.ExtraData(), &data); err != nil {
		slog.Error("failed to parse HTTP channel data", "error", err)
		newCh.Reject(gossh.ConnectionFailed, "invalid channel data")
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		slog.Error("failed to accept HTTP channel", "error", err)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	c.serveTunneledRequest(ch, bufio.NewReader(ch), data)
}

// serveTunneledRequest forwards one HTTP request that arrived on an SSH channel
// to the local backend and writes the response back onto it.
//
// Both channel types converge here. They differ only in how the request metadata
// reached us: in the channel-open ExtraData for a channel the server opened on
// demand, or as a prelude already consumed from br for a pre-opened warm one. br
// must be the reader the prelude was read from, since it may hold buffered
// request bytes.
func (c *Client) serveTunneledRequest(ch gossh.Channel, br *bufio.Reader, data protocol.HTTPChannelData) {
	start := time.Now()

	// Read the HTTP request from the channel
	req, err := http.ReadRequest(br)
	if err != nil {
		slog.Error("failed to read request from channel", "error", err)
		writeErrorResponse(ch, http.StatusBadGateway, "failed to read request")
		return
	}
	defer req.Body.Close()

	// The request only arrives once the edge has pushed it down the tunnel, so
	// this first span is essentially the edge→here network leg. Splitting it out
	// is what makes the total interpretable: a request that is slow here is slow
	// on the wire, not in the backend.
	requestRead := time.Now()

	// Inject standard forwarding headers
	// X-Forwarded-For: append client IP
	if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+data.RemoteAddr)
	} else {
		req.Header.Set("X-Forwarded-For", data.RemoteAddr)
	}

	if data.TLS {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	req.Header.Set("X-Forwarded-Host", data.Host)
	req.Header.Set("X-Real-IP", data.RemoteAddr)
	req.Header.Set("X-Request-Id", data.RequestID)

	// Resolve target based on incoming hostname (route map or default)
	targetAddr, targetScheme, _ := c.resolveTarget(data.Host)

	// Rewrite the request URL to target the local service
	targetURL := fmt.Sprintf("%s://%s%s", targetScheme, targetAddr, data.URI)
	req.URL, _ = url.Parse(targetURL)
	req.RequestURI = "" // Must be empty for http.Client

	// Host header handling
	if data.PreserveHost {
		// Keep original Host header from the public request
		req.Host = data.Host
	} else {
		// Rewrite Host to target address (default)
		req.Host = targetAddr
	}

	// WebSocket / upgrade requests must bypass http.Client because Go's
	// transport strips hop-by-hop headers (Connection, Upgrade). Dial the
	// backend directly and do raw bidirectional piping.
	if isUpgradeRequest(req) {
		c.handleUpgrade(ch, br, req, data)
		return
	}

	// Forward to local target
	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Error("target request failed",
			"target", targetAddr,
			"method", data.Method,
			"uri", data.URI,
			"error", err,
		)
		writeErrorResponse(ch, http.StatusBadGateway, "target unreachable")
		return
	}
	defer resp.Body.Close()

	backendDone := time.Now()

	// Write response back through the channel, joining the header block into a
	// single SSH packet instead of the dozen-plus that Response.Write would emit.
	// Body writes still pass straight through, so streaming is unaffected.
	hw := &headerCoalescingWriter{dst: ch}
	if err := resp.Write(hw); err != nil {
		slog.Error("failed to write response to channel", "error", err)
		return
	}
	if err := hw.Close(); err != nil {
		slog.Error("failed to flush response headers to channel", "error", err)
		return
	}

	// Note this span measures handing the response to the SSH transport, not its
	// arrival at the edge: the per-channel window is 2MB, so anything smaller
	// returns as soon as the bytes are queued. It goes up when the response is
	// large enough to wait on flow control, or when another channel on this
	// connection is saturating the uplink.
	writeDone := time.Now()

	readMS := requestRead.Sub(start).Milliseconds()
	backendMS := backendDone.Sub(requestRead).Milliseconds()
	writeMS := writeDone.Sub(backendDone).Milliseconds()
	elapsed := writeDone.Sub(start)

	// Compute response size from Content-Length or estimate
	respSize := resp.ContentLength
	if respSize < 0 {
		respSize = 0
	}

	slog.Debug("request",
		"method", data.Method,
		"uri", data.URI,
		"host", data.Host,
		"status", resp.StatusCode,
		"size", respSize,
		"duration", elapsed.Round(time.Millisecond),
		"read_ms", readMS,
		"backend_ms", backendMS,
		"write_ms", writeMS,
		"from", data.RemoteAddr,
	)

	// Log at info level with less detail for non-debug
	if slog.Default().Enabled(context.Background(), slog.LevelInfo) && !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		statusStr := fmt.Sprintf("%d", resp.StatusCode)
		if resp.StatusCode >= 400 {
			statusStr = fmt.Sprintf("%d!", resp.StatusCode)
		}
		slog.Info(fmt.Sprintf("%s %s → %s", data.Method, truncateURI(data.URI), statusStr),
			"host", data.Host,
			"ms", elapsed.Milliseconds(),
			"read_ms", readMS,
			"backend_ms", backendMS,
			"write_ms", writeMS,
		)
	}
}

// handleUpgrade dials the backend directly and pipes the raw connection
// through the SSH channel. This preserves hop-by-hop headers (Connection,
// Upgrade) that http.Client would strip.
// br must be the reader the request was parsed from. It can already hold bytes
// that arrived behind the request headers, and those bytes belong to the
// upgraded stream — piping from the raw channel instead would silently drop
// them. The edge side has always done this correctly (it hands its own buffered
// reader to the copy); this is the client side catching up.
func (c *Client) handleUpgrade(ch gossh.Channel, br *bufio.Reader, req *http.Request, data protocol.HTTPChannelData) {
	target, _, tlsMode := c.resolveTarget(data.Host)

	var conn net.Conn
	var err error

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		slog.Error("upgrade: failed to connect to target",
			"target", target,
			"error", err,
		)
		writeErrorResponse(ch, http.StatusBadGateway, "target unreachable")
		return
	}
	defer conn.Close()

	// Wrap with TLS if the target requires it
	if tlsMode != "" {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: tlsMode == "tls-insecure",
		})
		if err := tlsConn.Handshake(); err != nil {
			slog.Error("upgrade: TLS handshake failed",
				"target", target,
				"error", err,
			)
			writeErrorResponse(ch, http.StatusBadGateway, "TLS handshake failed")
			return
		}
		conn = tlsConn
	}

	// Write raw HTTP request to backend (preserves Connection: Upgrade, etc.)
	if err := req.Write(conn); err != nil {
		slog.Error("upgrade: failed to write request to target",
			"target", target,
			"error", err,
		)
		writeErrorResponse(ch, http.StatusBadGateway, "target write failed")
		return
	}

	slog.Info("upgrade",
		"uri", data.URI,
		"host", data.Host,
		"target", target,
		"from", data.RemoteAddr,
	)

	// Bidirectional pipe: backend response + frames flow through the SSH channel
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(conn, br) // SSH channel (incl. anything already buffered) → backend
		conn.Close()      // unblock the other goroutine
		done <- struct{}{}
	}()
	go func() {
		io.Copy(ch, conn) // backend → SSH channel
		if cw, ok := ch.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// isUpgradeRequest checks if the request contains a Connection: Upgrade header.
func isUpgradeRequest(r *http.Request) bool {
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

func writeErrorResponse(w io.Writer, status int, msg string) {
	resp := &http.Response{
		StatusCode: status,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(msg)),
	}
	resp.Write(w)
}

func truncateURI(uri string) string {
	if len(uri) > 60 {
		return uri[:57] + "..."
	}
	return uri
}

// headerTerminator ends the HTTP header block.
var headerTerminator = []byte("\r\n\r\n")

// maxBufferedHeader bounds how much we will hold while looking for the end of
// the header block, so a backend that never sends one cannot grow this buffer
// without limit. Past it we give up coalescing and stream straight through.
const maxBufferedHeader = 64 * 1024

// headerCoalescingWriter joins an HTTP response's header block into a single
// Write, then gets out of the way.
//
// http.Response.Write emits the status line, each transfer header, and each
// header line as separate Writes — a dozen or more for a typical response. Every
// Write on an ssh.Channel becomes its own SSH packet: encrypted, pushed through
// the transport's single write mutex, and flushed as its own syscall and TCP
// segment. Coalescing the header block turns that into one packet.
//
// It deliberately buffers ONLY up to the end of the headers. Wrapping the whole
// response in a bufio.Writer would be simpler and would re-break Server-Sent
// Events by holding body chunks, which is the bug this codebase just fixed.
type headerCoalescingWriter struct {
	dst  io.Writer
	buf  []byte
	done bool // header block emitted; everything after streams through
}

func (w *headerCoalescingWriter) Write(p []byte) (int, error) {
	if w.done {
		return w.dst.Write(p)
	}
	w.buf = append(w.buf, p...)

	end := bytes.Index(w.buf, headerTerminator)
	if end < 0 {
		if len(w.buf) > maxBufferedHeader {
			// No header terminator in sight; stop buffering rather than grow.
			if err := w.flushBuffered(); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	}

	// Emit the header block as one write, then whatever body bytes arrived with
	// it as a second — never merged, so a first SSE event is not held back.
	end += len(headerTerminator)
	if _, err := w.dst.Write(w.buf[:end]); err != nil {
		return 0, err
	}
	rest := w.buf[end:]
	w.done, w.buf = true, nil
	if len(rest) > 0 {
		if _, err := w.dst.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// flushBuffered emits anything still held and switches to pass-through.
func (w *headerCoalescingWriter) flushBuffered() error {
	w.done = true
	if len(w.buf) == 0 {
		return nil
	}
	buf := w.buf
	w.buf = nil
	_, err := w.dst.Write(buf)
	return err
}

// Close flushes a header block that was never terminated, so a malformed
// response is still relayed rather than silently swallowed.
func (w *headerCoalescingWriter) Close() error {
	if w.done {
		return nil
	}
	return w.flushBuffered()
}
