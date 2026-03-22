package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSEBroadcaster_NewEmpty(t *testing.T) {
	b := NewSSEBroadcaster()
	if b == nil {
		t.Fatal("NewSSEBroadcaster returned nil")
	}
	// Broadcasting to no clients should not panic
	b.Broadcast("test", "data")
}

func TestSSEBroadcaster_ServeAndBroadcast(t *testing.T) {
	b := NewSSEBroadcaster()

	// Start an SSE client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/events", nil).WithContext(ctx)
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	done := make(chan struct{})
	go func() {
		b.ServeHTTP(w, req)
		close(done)
	}()

	// Wait for client to register
	time.Sleep(50 * time.Millisecond)

	// Broadcast
	b.Broadcast("tunnel-connect", "web-app")

	// Give time for message delivery
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop the handler
	cancel()
	<-done

	body := w.Body.String()

	// Should have initial ping
	if !strings.Contains(body, "event: ping\ndata: connected") {
		t.Fatalf("missing initial ping in: %q", body)
	}

	// Should have broadcast message
	if !strings.Contains(body, "event: tunnel-connect\ndata: web-app") {
		t.Fatalf("missing broadcast in: %q", body)
	}
}

func TestSSEBroadcaster_MultipleClients(t *testing.T) {
	b := NewSSEBroadcaster()

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()

	w1 := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	w2 := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		b.ServeHTTP(w1, httptest.NewRequest("GET", "/events", nil).WithContext(ctx1))
		close(done1)
	}()
	go func() {
		b.ServeHTTP(w2, httptest.NewRequest("GET", "/events", nil).WithContext(ctx2))
		close(done2)
	}()

	time.Sleep(50 * time.Millisecond)

	b.Broadcast("test-event", "hello")
	time.Sleep(50 * time.Millisecond)

	cancel1()
	cancel2()
	<-done1
	<-done2

	for i, w := range []*flushRecorder{w1, w2} {
		if !strings.Contains(w.Body.String(), "event: test-event\ndata: hello") {
			t.Fatalf("client %d missing broadcast", i+1)
		}
	}
}

func TestSSEBroadcaster_ClientDisconnect(t *testing.T) {
	b := NewSSEBroadcaster()

	ctx, cancel := context.WithCancel(context.Background())
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	done := make(chan struct{})
	go func() {
		b.ServeHTTP(w, httptest.NewRequest("GET", "/events", nil).WithContext(ctx))
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	// After disconnect, broadcast should not panic
	b.Broadcast("after-disconnect", "data")
}

func TestSSEBroadcaster_Headers(t *testing.T) {
	b := NewSSEBroadcaster()

	ctx, cancel := context.WithCancel(context.Background())
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	done := make(chan struct{})
	go func() {
		b.ServeHTTP(w, httptest.NewRequest("GET", "/events", nil).WithContext(ctx))
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("wrong content type: %s", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("wrong cache control: %s", w.Header().Get("Cache-Control"))
	}
}

func TestSSEBroadcaster_NoFlusher(t *testing.T) {
	b := NewSSEBroadcaster()

	// httptest.ResponseRecorder without Flush — use a non-flusher wrapper
	rec := httptest.NewRecorder()
	w := &noFlushWriter{rec: rec}
	req := httptest.NewRequest("GET", "/events", nil)
	b.ServeHTTP(w, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// flushRecorder wraps httptest.ResponseRecorder and implements http.Flusher.
type flushRecorder struct {
	*httptest.ResponseRecorder
}

func (f *flushRecorder) Flush() {
	f.ResponseRecorder.Flush()
}

// noFlushWriter implements http.ResponseWriter but NOT http.Flusher.
// Uses a named field (not embedding) to prevent Flush() promotion.
type noFlushWriter struct {
	rec *httptest.ResponseRecorder
}

func (n *noFlushWriter) Header() http.Header         { return n.rec.Header() }
func (n *noFlushWriter) Write(b []byte) (int, error)  { return n.rec.Write(b) }
func (n *noFlushWriter) WriteHeader(code int)         { n.rec.WriteHeader(code) }
