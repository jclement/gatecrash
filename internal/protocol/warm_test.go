package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// legacyHTTPChannelData is a verbatim copy of the anonymous struct that released
// clients unmarshal a gatecrash-http channel's ExtraData into. It exists so the
// test below can decode as an old client would, rather than trusting that the
// current struct still matches.
type legacyHTTPChannelData struct {
	RequestID    string
	Method       string
	URI          string
	Host         string
	RemoteAddr   string
	TLS          bool
	PreserveHost bool
}

// TestHTTPChannelData_LegacyWireFormatUnchanged is the single most important
// compatibility guard in this package. Released clients decode the channel-open
// ExtraData into the struct above, and gossh.Unmarshal REJECTS trailing bytes —
// so adding, reordering, or retyping a field here would not degrade gracefully,
// it would make every request from every older client fail.
//
// If this test fails, do not "fix" it by updating the expectation: put the new
// data in the warm-channel prelude, or behind a new versioned channel type.
func TestHTTPChannelData_LegacyWireFormatUnchanged(t *testing.T) {
	d := HTTPChannelData{
		RequestID:    "req-abc",
		Method:       "POST",
		URI:          "/a/b?c=d",
		Host:         "example.test",
		RemoteAddr:   "203.0.113.9",
		TLS:          true,
		PreserveHost: true,
	}

	encoded := gossh.Marshal(d)

	var old legacyHTTPChannelData
	if err := gossh.Unmarshal(encoded, &old); err != nil {
		t.Fatalf("an older client could not decode this ExtraData: %v", err)
	}

	if old.RequestID != d.RequestID || old.Method != d.Method || old.URI != d.URI ||
		old.Host != d.Host || old.RemoteAddr != d.RemoteAddr ||
		old.TLS != d.TLS || old.PreserveHost != d.PreserveHost {
		t.Fatalf("field mismatch decoding as an older client:\n got %+v\nwant %+v", old, d)
	}
}

// TestHTTPChannelData_TrailingBytesAreRejected documents the library behaviour
// the guard above depends on, so the reasoning survives even if someone doubts
// it later.
func TestHTTPChannelData_TrailingBytesAreRejected(t *testing.T) {
	encoded := append(gossh.Marshal(HTTPChannelData{Method: "GET"}), 0x00)
	var old legacyHTTPChannelData
	if err := gossh.Unmarshal(encoded, &old); err == nil {
		t.Fatal("expected gossh.Unmarshal to reject trailing bytes; if this ever " +
			"changes, the ExtraData compatibility argument needs revisiting")
	}
}

func TestHTTPPrelude_RoundTrip(t *testing.T) {
	want := &HTTPChannelData{
		RequestID:    "req-1",
		Method:       "GET",
		URI:          "/x",
		Host:         "h.test",
		RemoteAddr:   "198.51.100.4",
		TLS:          true,
		PreserveHost: false,
	}

	var buf bytes.Buffer
	if err := WriteHTTPPrelude(&buf, want); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := ReadHTTPPrelude(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if *got != *want {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", *got, *want)
	}
}

// TestHTTPPrelude_LeavesFollowingBytes is what lets the client parse the HTTP
// request straight after the prelude from the same reader: the prelude reader
// must consume its own bytes and not a byte more.
func TestHTTPPrelude_LeavesFollowingBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTTPPrelude(&buf, &HTTPChannelData{Method: "GET"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	const follows = "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
	buf.WriteString(follows)

	if _, err := ReadHTTPPrelude(&buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	rest, err := io.ReadAll(&buf)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != follows {
		t.Fatalf("prelude consumed request bytes; remaining = %q", rest)
	}
}

// TestHTTPPrelude_IsASingleWrite matters because every Write on an SSH channel
// becomes its own packet — the prelude must not cost an extra one.
func TestHTTPPrelude_IsASingleWrite(t *testing.T) {
	cw := &countingWriter{}
	if err := WriteHTTPPrelude(cw, &HTTPChannelData{Method: "GET", URI: "/x"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cw.writes != 1 {
		t.Fatalf("prelude took %d writes, want 1", cw.writes)
	}
}

type countingWriter struct{ writes int }

func (c *countingWriter) Write(p []byte) (int, error) { c.writes++; return len(p), nil }

func TestHTTPPrelude_RejectsBadLength(t *testing.T) {
	// Absurd length prefix must not cause a huge allocation.
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(1<<30))
	buf.WriteString("nonsense")
	if _, err := ReadHTTPPrelude(&buf); err == nil {
		t.Fatal("expected an oversized prelude length to be rejected")
	} else if !strings.Contains(err.Error(), "invalid prelude length") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Zero length is meaningless and must be rejected too.
	var zero bytes.Buffer
	binary.Write(&zero, binary.BigEndian, uint32(0))
	if _, err := ReadHTTPPrelude(&zero); err == nil {
		t.Fatal("expected a zero-length prelude to be rejected")
	}
}

func TestHTTPPrelude_TruncatedIsAnError(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTTPPrelude(&buf, &HTTPChannelData{Method: "GET"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	truncated := buf.Bytes()[:buf.Len()-3]
	if _, err := ReadHTTPPrelude(bytes.NewReader(truncated)); err == nil {
		t.Fatal("expected a truncated prelude to be an error")
	}
}
