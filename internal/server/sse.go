package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// sseWriteTimeout bounds a single SSE write so a stalled reader can't wedge the
// handler goroutine indefinitely.
const sseWriteTimeout = 10 * time.Second

// sseKeepaliveInterval drives a periodic comment ping so a dead-but-not-closed
// connection surfaces as a write error (via the write deadline) rather than
// silently lingering.
const sseKeepaliveInterval = 25 * time.Second

// SSEBroadcaster manages Server-Sent Events connections.
type SSEBroadcaster struct {
	mu      sync.RWMutex
	clients map[chan string]struct{}
}

// NewSSEBroadcaster creates a new SSE broadcaster.
func NewSSEBroadcaster() *SSEBroadcaster {
	return &SSEBroadcaster{
		clients: make(map[chan string]struct{}),
	}
}

// Broadcast sends an event to all connected clients.
func (b *SSEBroadcaster) Broadcast(event, data string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", event, data)
	for ch := range b.clients {
		select {
		case ch <- msg:
		default:
			// Client too slow, skip
		}
	}
}

// ServeHTTP handles SSE connections.
func (b *SSEBroadcaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	rc := http.NewResponseController(w)

	ch := make(chan string, 16)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.clients, ch)
		b.mu.Unlock()
	}()

	// write applies a per-write deadline so a stalled reader can't pin this
	// goroutine. A write error (deadline or broken pipe) ends the connection.
	// SetWriteDeadline/Flush may be unsupported by the underlying writer (e.g. a
	// test recorder); treat "not supported" as a no-op rather than a failure.
	write := func(s string) error {
		if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		if _, err := fmt.Fprint(w, s); err != nil {
			return err
		}
		if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		return nil
	}

	// Send initial ping
	if err := write("event: ping\ndata: connected\n\n"); err != nil {
		return
	}

	slog.Debug("SSE client connected", "remote", r.RemoteAddr)

	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			slog.Debug("SSE client disconnected", "remote", r.RemoteAddr)
			return
		case <-keepalive.C:
			if err := write(": keepalive\n\n"); err != nil {
				slog.Debug("SSE keepalive write failed", "remote", r.RemoteAddr, "error", err)
				return
			}
		case msg := <-ch:
			if err := write(msg); err != nil {
				slog.Debug("SSE write failed", "remote", r.RemoteAddr, "error", err)
				return
			}
		}
	}
}
