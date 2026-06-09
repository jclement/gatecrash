package server

import (
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
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
	version     string
}

// TunnelState holds the runtime state for a configured tunnel.
type TunnelState struct {
	ID              string
	Type            string // "http" or "tcp"
	Hostnames       []string
	ListenPort      int
	PreserveHost    bool
	TLSPassthrough  bool
	RequireAuth     bool
	AuthClaimName   string
	AuthClaimValue  string
	AuthHeader      string
	AuthHeaderClaim string
	IPAllowlist     bool
	AllowIPs        []string     // raw permanent entries (IPs/CIDRs), for display
	allowNets       []*net.IPNet // parsed permanent entries, for matching

	mu      sync.RWMutex
	clients map[ssh.Conn]clientConn
	Metrics TunnelMetrics
}

// TunnelSpec is the config-derived subset of a tunnel that the registry needs.
// Using a named type (rather than a repeated anonymous struct) keeps the Reload
// call sites readable and makes adding fields a one-line change.
type TunnelSpec struct {
	ID              string
	Type            string
	Hostnames       []string
	ListenPort      int
	PreserveHost    bool
	TLSPassthrough  bool
	RequireAuth     bool
	AuthClaimName   string
	AuthClaimValue  string
	AuthHeader      string
	AuthHeaderClaim string
	IPAllowlist     bool
	AllowIPs        []string
}

// applySpec copies config-derived fields onto the tunnel, parsing the permanent
// IP allowlist entries into matchable networks. Connection state and metrics are
// left untouched so a live tunnel survives a reload.
func (t *TunnelState) applySpec(spec TunnelSpec) {
	t.Type = spec.Type
	t.Hostnames = spec.Hostnames
	t.ListenPort = spec.ListenPort
	t.PreserveHost = spec.PreserveHost
	t.TLSPassthrough = spec.TLSPassthrough
	t.RequireAuth = spec.RequireAuth
	t.AuthClaimName = spec.AuthClaimName
	t.AuthClaimValue = spec.AuthClaimValue
	t.AuthHeader = spec.AuthHeader
	t.AuthHeaderClaim = spec.AuthHeaderClaim
	t.IPAllowlist = spec.IPAllowlist
	t.AllowIPs = spec.AllowIPs
	t.allowNets = parseAllowIPs(spec.ID, spec.AllowIPs)
}

// newTunnelState builds a tunnel from a spec.
func newTunnelState(spec TunnelSpec) *TunnelState {
	t := &TunnelState{ID: spec.ID}
	t.applySpec(spec)
	return t
}

// StaticIPAllowed reports whether ip matches a permanent allowlist entry.
// Self-service (TTL'd) grants are checked separately via the IPAllowStore.
func (t *TunnelState) StaticIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range t.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseAllowIPs converts allowlist entries (bare IPs or CIDRs) into networks,
// skipping (and logging) any that don't parse so one bad entry can't break the
// whole tunnel.
func parseAllowIPs(tunnelID string, entries []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, e := range entries {
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		slog.Warn("ignoring invalid allow_ips entry", "tunnel", tunnelID, "entry", e)
	}
	return nets
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

// ClientInfo holds exported details about a connected client.
type ClientInfo struct {
	Addr        string
	ConnectedAt time.Time
	Version     string
}

// ClientInfos returns details for all connected clients.
func (t *TunnelState) ClientInfos() []ClientInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	infos := make([]ClientInfo, 0, len(t.clients))
	for _, c := range t.clients {
		infos = append(infos, ClientInfo{Addr: c.addr, ConnectedAt: c.connectedAt, Version: c.version})
	}
	return infos
}

// SetClientVersion updates the version for a connected client.
func (t *TunnelState) SetClientVersion(conn ssh.Conn, version string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.clients[conn]; ok {
		c.version = version
		t.clients[conn] = c
	}
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
		r.byHost[strings.ToLower(h)] = t
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
	return r.byHost[strings.ToLower(host)] // hostnames are case-insensitive (DNS)
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

// Reload updates the registry with new tunnel specs.
// Existing tunnels keep their connection state and metrics.
// New tunnels are added, removed tunnels are dropped (connections will be closed by SSH).
func (r *Registry) Reload(specs []TunnelSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Build new maps, preserving existing tunnel state where IDs match
	newByID := make(map[string]*TunnelState, len(specs))
	newByHost := make(map[string]*TunnelState)
	newByPort := make(map[int]*TunnelState)

	for _, spec := range specs {
		t, ok := r.byID[spec.ID]
		if ok {
			// Preserve existing tunnel state (connection, metrics)
			t.applySpec(spec)
		} else {
			t = newTunnelState(spec)
		}
		newByID[spec.ID] = t
		for _, h := range spec.Hostnames {
			newByHost[strings.ToLower(h)] = t
		}
		if spec.ListenPort > 0 {
			newByPort[spec.ListenPort] = t
		}
	}

	r.byID = newByID
	r.byHost = newByHost
	r.byPort = newByPort
}
