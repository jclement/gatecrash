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
