package client

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// recordingWriter records each Write separately so tests can assert on how the
// response was packetised, not merely on the bytes that came out. Each Write to
// a real ssh.Channel becomes one SSH packet, so write count is the thing that
// matters here.
type recordingWriter struct{ writes [][]byte }

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (r *recordingWriter) all() []byte { return bytes.Join(r.writes, nil) }

// TestHeaderCoalescing_OneWriteForHeaders is the point of the change: a response
// whose headers Response.Write would dribble out in a dozen pieces must reach
// the channel as a single packet.
func TestHeaderCoalescing_OneWriteForHeaders(t *testing.T) {
	resp := &http.Response{
		StatusCode:    200,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader("hello")),
		ContentLength: 5,
	}
	for _, k := range []string{"Content-Type", "Cache-Control", "Etag", "Vary", "X-One", "X-Two", "X-Three"} {
		resp.Header.Set(k, "value-for-"+k)
	}

	// Baseline: how many writes does Response.Write make unaided?
	bare := &recordingWriter{}
	resp2 := *resp
	resp2.Body = io.NopCloser(strings.NewReader("hello"))
	if err := resp2.Write(bare); err != nil {
		t.Fatalf("baseline write: %v", err)
	}
	if len(bare.writes) < 5 {
		t.Fatalf("expected Response.Write to fragment headers, got %d writes", len(bare.writes))
	}

	// Coalesced: the header block must be exactly one write.
	rec := &recordingWriter{}
	hw := &headerCoalescingWriter{dst: rec}
	if err := resp.Write(hw); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := hw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if !bytes.HasSuffix(rec.writes[0], headerTerminator) {
		t.Fatalf("first write is not the complete header block: %q", rec.writes[0])
	}
	if len(rec.writes) > 2 {
		t.Fatalf("expected header block + body in ~2 writes, got %d: %q", len(rec.writes), rec.writes)
	}
	if len(rec.writes) >= len(bare.writes) {
		t.Fatalf("coalescing did not reduce writes: %d vs baseline %d", len(rec.writes), len(bare.writes))
	}

	// Byte stream must be identical to the uncoalesced version.
	if !bytes.Equal(rec.all(), bare.all()) {
		t.Fatalf("byte stream changed.\n got: %q\nwant: %q", rec.all(), bare.all())
	}
}

// TestHeaderCoalescing_DoesNotHoldBodyChunks is the regression guard for the SSE
// fix: only headers may be buffered. Each body chunk must reach the channel as
// its own write, the moment it is produced.
func TestHeaderCoalescing_DoesNotHoldBodyChunks(t *testing.T) {
	rec := &recordingWriter{}
	hw := &headerCoalescingWriter{dst: rec}

	hw.Write([]byte("HTTP/1.1 200 OK\r\n"))
	hw.Write([]byte("Content-Type: text/event-stream\r\n"))
	hw.Write([]byte("\r\n"))
	headerWrites := len(rec.writes)
	if headerWrites != 1 {
		t.Fatalf("expected headers in 1 write, got %d", headerWrites)
	}

	hw.Write([]byte("data: first\n\n"))
	if len(rec.writes) != 2 {
		t.Fatalf("first event was held back: %d writes so far", len(rec.writes))
	}
	hw.Write([]byte("data: second\n\n"))
	if len(rec.writes) != 3 {
		t.Fatalf("second event was held back: %d writes so far", len(rec.writes))
	}
}

// TestHeaderCoalescing_SplitsBodyArrivingWithHeaders covers the case where the
// terminator and the first body bytes land in one Write: the body must go out as
// a separate write so a first SSE event is not merged into the header packet in
// a way that could be held.
func TestHeaderCoalescing_SplitsBodyArrivingWithHeaders(t *testing.T) {
	rec := &recordingWriter{}
	hw := &headerCoalescingWriter{dst: rec}
	hw.Write([]byte("HTTP/1.1 200 OK\r\n\r\ndata: first\n\n"))

	if len(rec.writes) != 2 {
		t.Fatalf("expected header and body split into 2 writes, got %d: %q", len(rec.writes), rec.writes)
	}
	if !bytes.HasSuffix(rec.writes[0], headerTerminator) {
		t.Fatalf("first write should end at the header terminator, got %q", rec.writes[0])
	}
	if string(rec.writes[1]) != "data: first\n\n" {
		t.Fatalf("body write = %q", rec.writes[1])
	}
}

// TestHeaderCoalescing_UnterminatedHeadersStillRelayed guards the safety valve:
// a malformed response with no header terminator must still be forwarded on
// Close rather than silently swallowed.
func TestHeaderCoalescing_UnterminatedHeadersStillRelayed(t *testing.T) {
	rec := &recordingWriter{}
	hw := &headerCoalescingWriter{dst: rec}
	hw.Write([]byte("HTTP/1.1 200 OK\r\nX-Truncated: yes\r\n"))
	if len(rec.writes) != 0 {
		t.Fatal("expected the writer to still be buffering an unterminated header block")
	}
	if err := hw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := string(rec.all()); got != "HTTP/1.1 200 OK\r\nX-Truncated: yes\r\n" {
		t.Fatalf("unterminated headers were not relayed, got %q", got)
	}
}

// TestHeaderCoalescing_GivesUpOnOversizedHeaders ensures a backend that never
// sends a terminator cannot grow the buffer without bound.
func TestHeaderCoalescing_GivesUpOnOversizedHeaders(t *testing.T) {
	rec := &recordingWriter{}
	hw := &headerCoalescingWriter{dst: rec}
	hw.Write(bytes.Repeat([]byte("x"), maxBufferedHeader+1))
	if len(rec.writes) == 0 {
		t.Fatal("expected the writer to stop buffering past maxBufferedHeader")
	}
	if hw.buf != nil {
		t.Fatal("buffer should have been released after giving up")
	}
}
