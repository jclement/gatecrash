package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jclement/gatecrash/internal/protocol"
)

func TestIsUpgradeRequest(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"no header", "", false},
		{"keep-alive", "keep-alive", false},
		{"upgrade", "Upgrade", true},
		{"case insensitive", "upgrade", true},
		{"mixed case", "Upgrade", true},
		{"multiple values", "keep-alive, Upgrade", true},
		{"multiple values lowercase", "keep-alive, upgrade", true},
		{"upgrade first", "Upgrade, keep-alive", true},
		{"no upgrade in list", "keep-alive, close", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tt.header != "" {
				r.Header.Set("Connection", tt.header)
			}
			got := isUpgradeRequest(r)
			if got != tt.want {
				t.Fatalf("isUpgradeRequest(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name   string
		status int
		header string
		want   bool
	}{
		{"switching + websocket", http.StatusSwitchingProtocols, "websocket", true},
		{"switching + WebSocket", http.StatusSwitchingProtocols, "WebSocket", true},
		{"switching + no upgrade", http.StatusSwitchingProtocols, "", false},
		{"200 + websocket", http.StatusOK, "websocket", false},
		{"switching + h2c", http.StatusSwitchingProtocols, "h2c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.status,
				Header:     http.Header{},
			}
			if tt.header != "" {
				resp.Header.Set("Upgrade", tt.header)
			}
			got := isWebSocketUpgrade(resp)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCountingWriter(t *testing.T) {
	var buf []byte
	cw := &countingWriter{w: &byteBuffer{buf: &buf}}
	data := []byte("hello world")
	n, err := cw.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("wrote %d bytes, want %d", n, len(data))
	}
	if cw.n != int64(len(data)) {
		t.Fatalf("counted %d bytes, want %d", cw.n, len(data))
	}

	// Write more
	cw.Write([]byte("!"))
	if cw.n != int64(len(data)+1) {
		t.Fatalf("counted %d bytes, want %d", cw.n, len(data)+1)
	}
}

// byteBuffer is a simple io.Writer for testing.
type byteBuffer struct {
	buf *[]byte
}

func (b *byteBuffer) Write(p []byte) (int, error) {
	*b.buf = append(*b.buf, p...)
	return len(p), nil
}

func TestMarshalHTTPChannelData(t *testing.T) {
	d := &protocol.HTTPChannelData{
		RequestID:    "test-123",
		Method:       "GET",
		URI:          "/api",
		Host:         "example.com",
		RemoteAddr:   "1.2.3.4",
		TLS:          true,
		PreserveHost: false,
	}
	data := marshalHTTPChannelData(d)
	if len(data) == 0 {
		t.Fatal("marshal returned empty data")
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, X-Custom-Hop")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("X-Custom-Hop", "1")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "h2c")
	h.Set("Content-Type", "text/html")
	h.Set("Set-Cookie", "a=b")
	h.Set("X-Powered-By", "Express")

	removeHopByHopHeaders(h)

	for _, gone := range []string{"Connection", "Keep-Alive", "X-Custom-Hop", "Proxy-Connection", "Transfer-Encoding", "Upgrade"} {
		if _, ok := h[gone]; ok {
			t.Errorf("%s should have been stripped", gone)
		}
	}
	for _, kept := range []string{"Content-Type", "Set-Cookie", "X-Powered-By"} {
		if _, ok := h[kept]; !ok {
			t.Errorf("%s should have been kept", kept)
		}
	}
}

// TestFlushingCopy_DeliversBeforeSourceEnds is the Server-Sent Events case: the
// visitor must receive an event while the backend's stream is still open. With a
// plain io.Copy the first read below blocks until the test times out, because the
// bytes sit in the ResponseWriter buffer waiting for it to fill.
func TestFlushingCopy_DeliversBeforeSourceEnds(t *testing.T) {
	release := make(chan struct{})
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("data: first\n\n"))
		<-release // hold the stream open, exactly as a live SSE endpoint would
		pw.Write([]byte("data: second\n\n"))
		pw.Close()
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flushingCopy(w, pr)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf)
	if err != nil {
		t.Fatalf("read first event: %v", err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "first") {
		t.Fatalf("expected the first event before the stream closed, got %q", got)
	}
	if strings.Contains(string(buf[:n]), "second") {
		t.Fatal("second event arrived early; the stream was not held open")
	}

	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if !strings.Contains(string(rest), "second") {
		t.Fatalf("expected the second event after release, got %q", rest)
	}
}

// TestFlushingCopy_CopiesEverything guards the ordinary bulk path: flushing must
// not drop or reorder bytes on a body larger than the copy buffer.
func TestFlushingCopy_CopiesEverything(t *testing.T) {
	src := bytes.Repeat([]byte("abcdefgh"), 20000) // 160KB — several 32KB chunks
	var dst bytes.Buffer
	n, err := flushingCopy(&dst, bytes.NewReader(src))
	if err != nil {
		t.Fatalf("flushingCopy: %v", err)
	}
	if n != int64(len(src)) {
		t.Fatalf("reported %d bytes, want %d", n, len(src))
	}
	if !bytes.Equal(dst.Bytes(), src) {
		t.Fatal("copied bytes differ from source")
	}
}

// TestFlushingCopy_ReportsSourceError proves a truncated backend body surfaces as
// an error rather than passing for a clean end-of-stream.
func TestFlushingCopy_ReportsSourceError(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("partial"))
		pw.CloseWithError(io.ErrUnexpectedEOF)
	}()

	var dst bytes.Buffer
	n, err := flushingCopy(&dst, pr)
	if err == nil {
		t.Fatal("expected an error from the truncated source, got nil")
	}
	if n != int64(len("partial")) {
		t.Fatalf("expected the partial bytes to be reported, got %d", n)
	}
}
