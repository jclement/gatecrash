package server

import (
	"math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// TunnelMetrics tracks in-memory stats for a tunnel (not persisted).
type TunnelMetrics struct {
	BytesIn       atomic.Int64
	BytesOut      atomic.Int64
	RequestCount  atomic.Int64
	ActiveConns   atomic.Int32
	LastRequestAt atomic.Value // time.Time
}

// clientConn represents one client connection in the pool.
type clientConn struct {
	addr        string
	connectedAt time.Time
}

// TunnelState holds the runtime state for a configured tunnel.
type TunnelState struct {
	ID             string
	Type           string // "http" or "tcp"
	Hostnames      []string
	ListenPort     int
	PreserveHost   bool
	TLSPassthrough bool

	mu      sync.RWMutex
	clients map[ssh.Conn]clientConn
	Metrics TunnelMetrics
}

func (t *TunnelState) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.clients) > 0
}

// PickConn returns a randomly selected SSH connection, or nil if none.
func (t *TunnelState) PickConn() ssh.Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := len(t.clients)
	if n == 0 {
		return nil
	}
	idx := rand.IntN(n)
	i := 0
	for conn := range t.clients {
		if i == idx {
			return conn
		}
		i++
	}
	return nil
}

// AddClient registers a new client connection.
func (t *TunnelState) AddClient(conn ssh.Conn, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.clients == nil {
		t.clients = make(map[ssh.Conn]clientConn)
	}
	t.clients[conn] = clientConn{
		addr:        addr,
		connectedAt: time.Now(),
	}
}

// RemoveClient removes a specific client connection.
func (t *TunnelState) RemoveClient(conn ssh.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.clients, conn)
}

// ClientCount returns the number of connected clients.
func (t *TunnelState) ClientCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.clients)
}

// ClientAddrs returns all connected client addresses.
func (t *TunnelState) ClientAddrs() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	addrs := make([]string, 0, len(t.clients))
	for _, c := range t.clients {
		addrs = append(addrs, c.addr)
	}
	return addrs
}

// Registry holds all configured tunnels and provides lookups.
type Registry struct {
	mu     sync.RWMutex
	byID   map[string]*TunnelState
	byHost map[string]*TunnelState
	byPort map[int]*TunnelState
}

func NewRegistry() *Registry {
	return &Registry{
		byID:   make(map[string]*TunnelState),
		byHost: make(map[string]*TunnelState),
		byPort: make(map[int]*TunnelState),
	}
}

func (r *Registry) Register(t *TunnelState) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.byID[t.ID] = t
	for _, h := range t.Hostnames {
		r.byHost[h] = t
	}
	if t.ListenPort > 0 {
		r.byPort[t.ListenPort] = t
	}
}

func (r *Registry) FindByID(id string) *TunnelState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

func (r *Registry) FindByHostname(host string) *TunnelState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byHost[host]
}

func (r *Registry) FindByPort(port int) *TunnelState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byPort[port]
}

func (r *Registry) AllTunnels() []*TunnelState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tunnels := make([]*TunnelState, 0, len(r.byID))
	for _, t := range r.byID {
		tunnels = append(tunnels, t)
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].ID < tunnels[j].ID
	})
	return tunnels
}

// Reload updates the registry with new tunnel configs.
// Existing tunnels keep their connection state and metrics.
// New tunnels are added, removed tunnels are dropped (connections will be closed by SSH).
func (r *Registry) Reload(tunnels []struct {
	ID             string
	Type           string
	Hostnames      []string
	ListenPort     int
	PreserveHost   bool
	TLSPassthrough bool
}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Build new maps, preserving existing tunnel state where IDs match
	newByID := make(map[string]*TunnelState, len(tunnels))
	newByHost := make(map[string]*TunnelState)
	newByPort := make(map[int]*TunnelState)

	for _, tc := range tunnels {
		var t *TunnelState
		if existing, ok := r.byID[tc.ID]; ok {
			// Preserve existing tunnel state (connection, metrics)
			t = existing
			t.Type = tc.Type
			t.Hostnames = tc.Hostnames
			t.ListenPort = tc.ListenPort
			t.PreserveHost = tc.PreserveHost
			t.TLSPassthrough = tc.TLSPassthrough
		} else {
			// New tunnel
			t = &TunnelState{
				ID:             tc.ID,
				Type:           tc.Type,
				Hostnames:      tc.Hostnames,
				ListenPort:     tc.ListenPort,
				PreserveHost:   tc.PreserveHost,
				TLSPassthrough: tc.TLSPassthrough,
			}
		}
		newByID[tc.ID] = t
		for _, h := range tc.Hostnames {
			newByHost[h] = t
		}
		if tc.ListenPort > 0 {
			newByPort[tc.ListenPort] = t
		}
	}

	r.byID = newByID
	r.byHost = newByHost
	r.byPort = newByPort
}
