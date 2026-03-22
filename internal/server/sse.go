package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
)

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
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan string, 16)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.clients, ch)
		b.mu.Unlock()
	}()

	// Send initial ping
	fmt.Fprint(w, "event: ping\ndata: connected\n\n")
	flusher.Flush()

	slog.Debug("SSE client connected", "remote", r.RemoteAddr)

	for {
		select {
		case <-r.Context().Done():
			slog.Debug("SSE client disconnected", "remote", r.RemoteAddr)
			return
		case msg := <-ch:
			fmt.Fprint(w, msg)
			flusher.Flush()
		}
	}
}
