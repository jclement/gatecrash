package server

import (
	"net/http"
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
