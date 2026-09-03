package client

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNew_BoundsBackendResponseHeaders pins the two halves of the hung-backend
// bound: the transport must cap the wait for response headers, and the client
// must NOT carry an overall Timeout. Setting http.Client.Timeout instead would
// look equivalent but would sever every streamed response at the deadline.
func TestNew_BoundsBackendResponseHeaders(t *testing.T) {
	c := New(Config{}, "test")

	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected an *http.Transport, got %T", c.httpClient.Transport)
	}
	if tr.ResponseHeaderTimeout != responseHeaderTimeout {
		t.Fatalf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, responseHeaderTimeout)
	}
	if c.httpClient.Timeout != 0 {
		t.Fatalf("http.Client.Timeout must stay unset (got %v): it would cut off "+
			"Server-Sent Events and other long-lived response bodies", c.httpClient.Timeout)
	}
}

// TestResponseHeaderTimeout_HungBackendFails is the case the bound exists for: a
// backend that accepts the connection and then never answers must fail rather
// than park the forwarding goroutine and its SSH channel forever.
func TestResponseHeaderTimeout_HungBackendFails(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked // never writes a header
	}))
	defer func() { close(blocked); srv.Close() }()

	client := &http.Client{Transport: shortHeaderTimeoutTransport()}

	start := time.Now()
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected the hung backend to fail, got a response")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %v to give up; the timeout is not being applied", elapsed)
	}
}

// TestResponseHeaderTimeout_SlowBodySurvives is the property that rules out
// http.Client.Timeout: once headers are in, a body may take arbitrarily long —
// an SSE stream never ends at all — and must not be cut off.
func TestResponseHeaderTimeout_SlowBodySurvives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// Dribble events well past the header deadline.
		for i := range 3 {
			time.Sleep(60 * time.Millisecond)
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()

	client := &http.Client{Transport: shortHeaderTimeoutTransport()}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("the slow body was cut off: %v", err)
	}
	for i := range 3 {
		if want := fmt.Sprintf("data: event-%d", i); !strings.Contains(string(body), want) {
			t.Fatalf("missing %q in streamed body %q", want, body)
		}
	}
}

// shortHeaderTimeoutTransport mirrors the production transport but with a
// deadline short enough to assert against in a test.
func shortHeaderTimeoutTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 50 * time.Millisecond
	return tr
}

// TestNew_BackendTransportTuning pins the two backend-pool settings. Both are
// easy to lose in a future Clone() refactor and neither fails loudly if dropped
// — they just quietly cost a dial or a compress/decompress cycle per request.
func TestNew_BackendTransportTuning(t *testing.T) {
	tr, ok := New(Config{}, "test").httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected an *http.Transport, got %T", tr)
	}
	if tr.MaxIdleConnsPerHost != maxIdleConnsPerBackend {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d (Go's default of 2 forces a "+
			"fresh backend dial on any burst past two concurrent requests)",
			tr.MaxIdleConnsPerHost, maxIdleConnsPerBackend)
	}
	if !tr.DisableCompression {
		t.Fatal("DisableCompression must stay set: otherwise the transport requests " +
			"gzip the visitor never asked for and decompresses it again locally")
	}
}

// TestDisableCompression_RelaysVisitorEncodingUntouched checks the property that
// makes the setting safe: a visitor that asks for gzip still gets gzip, relayed
// as the backend encoded it rather than decoded in transit.
func TestDisableCompression_RelaysVisitorEncodingUntouched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo what the transport actually asked the backend for.
		w.Header().Set("X-Saw-Accept-Encoding", r.Header.Get("Accept-Encoding"))
		w.Write([]byte("body"))
	}))
	defer srv.Close()

	c := New(Config{}, "test")

	// No Accept-Encoding from the visitor: the transport must not invent one.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Saw-Accept-Encoding"); got != "" {
		t.Fatalf("backend saw Accept-Encoding %q; the transport added one the visitor never sent", got)
	}

	// Visitor asked for gzip: it must be forwarded verbatim.
	req2, _ := http.NewRequest("GET", srv.URL, nil)
	req2.Header.Set("Accept-Encoding", "gzip")
	resp2, err := c.httpClient.Do(req2)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp2.Body.Close()
	if got := resp2.Header.Get("X-Saw-Accept-Encoding"); got != "gzip" {
		t.Fatalf("backend saw Accept-Encoding %q, want \"gzip\"", got)
	}
}
