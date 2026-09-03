package server

import (
	"math/rand/v2"
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

// clientConn represents one client connection in the pool. It is held by
// pointer so inFlight can be updated without taking the registry write lock.
type clientConn struct {
	addr        string
	connectedAt time.Time
	version     string

	// inFlight counts requests currently occupying this SSH connection. Every
	// channel on a connection serialises its packet writes through one transport
	// mutex, so spreading requests across connections is what keeps a trivial
	// request from queueing behind a bulk transfer.
	inFlight atomic.Int64

	// warm holds channels the client pre-opened and parked. Leasing one lets a
	// request skip the CHANNEL_OPEN round trip. It stays empty for clients too
	// old to offer them, which is exactly the legacy path.
	warm chan ssh.Channel
}

// TunnelState holds the runtime state for a configured tunnel.
type TunnelState struct {
	ID             string
	Type           string // "http" or "tcp"
	Hostnames      []string
	ListenPort     int
	PreserveHost   bool
	TLSPassthrough bool
	IPPolicyID     string // referenced ip_policy, or ""
	AuthPolicyID   string // referenced auth_policy, or ""

	mu      sync.RWMutex
	clients map[ssh.Conn]*clientConn
	Metrics TunnelMetrics
}

// TunnelSpec is the config-derived subset of a tunnel that the registry needs.
type TunnelSpec struct {
	ID             string
	Type           string
	Hostnames      []string
	ListenPort     int
	PreserveHost   bool
	TLSPassthrough bool
	IPPolicyID     string
	AuthPolicyID   string
}

// applySpec copies config-derived fields onto the tunnel. Connection state and
// metrics are left untouched so a live tunnel survives a reload. The write is
// guarded by t.mu because a reload mutates these fields while live request
// handlers read them concurrently (see the accessors below); without the lock a
// torn read of, say, IPPolicyID could momentarily skip an access-policy gate.
func (t *TunnelState) applySpec(spec TunnelSpec) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Type = spec.Type
	t.Hostnames = spec.Hostnames
	t.ListenPort = spec.ListenPort
	t.PreserveHost = spec.PreserveHost
	t.TLSPassthrough = spec.TLSPassthrough
	t.IPPolicyID = spec.IPPolicyID
	t.AuthPolicyID = spec.AuthPolicyID
}

// Config accessors read the reload-mutable fields under t.mu so request handlers
// never race with applySpec. Direct field reads are only safe at construction
// time (before the tunnel is published) or in single-threaded tests.
func (t *TunnelState) TunnelType() string  { t.mu.RLock(); defer t.mu.RUnlock(); return t.Type }
func (t *TunnelState) Port() int           { t.mu.RLock(); defer t.mu.RUnlock(); return t.ListenPort }
func (t *TunnelState) PreservesHost() bool { t.mu.RLock(); defer t.mu.RUnlock(); return t.PreserveHost }
func (t *TunnelState) IsTLSPassthrough() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.TLSPassthrough
}
func (t *TunnelState) IPPolicy() string   { t.mu.RLock(); defer t.mu.RUnlock(); return t.IPPolicyID }
func (t *TunnelState) AuthPolicy() string { t.mu.RLock(); defer t.mu.RUnlock(); return t.AuthPolicyID }

// HostnameList returns a copy of the tunnel's hostnames so callers can range
// over them without holding the lock or aliasing the live slice.
func (t *TunnelState) HostnameList() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, len(t.Hostnames))
	copy(out, t.Hostnames)
	return out
}

// newTunnelState builds a tunnel from a spec.
func newTunnelState(spec TunnelSpec) *TunnelState {
	t := &TunnelState{ID: spec.ID}
	t.applySpec(spec)
	return t
}

func (t *TunnelState) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.clients) > 0
}

// PickConn returns a randomly selected SSH connection, or nil if none.
// PickConn returns the connection with the fewest in-flight requests, so a
// trivial request is not queued behind a bulk transfer when another connection
// is idle. Ties are broken randomly to avoid always loading the same connection
// when all are equal. Callers MUST pair this with ReleaseConn.
//
// It returns the chosen connection and its state; the state is nil only when
// there are no connections, in which case the connection is nil too.
func (t *TunnelState) PickConn() ssh.Conn {
	conn, release := t.AcquireConn()
	release() // caller is not tracking occupancy; don't leave the count raised
	return conn
}

// AcquireConn picks the least-loaded connection and marks it busy. The returned
// release func MUST be called when the request finishes; it is safe to call on a
// nil connection, so callers can defer it unconditionally.
func (t *TunnelState) AcquireConn() (ssh.Conn, func()) {
	conn, _, release := t.AcquireConnState()
	return conn, release
}

// AcquireConnState is AcquireConn plus the per-connection state, for callers
// that need the warm-channel pool. The state is nil when no connection exists.
func (t *TunnelState) AcquireConnState() (ssh.Conn, *clientConn, func()) {
	conn, state := t.acquireConn()
	return conn, state, func() { ReleaseConn(state) }
}

// acquireConn picks the least-loaded connection and increments its in-flight
// count. The returned *clientConn is what ReleaseConn decrements; returning it
// directly avoids a second map lookup on the release path, and keeps the
// accounting correct even if the connection is evicted from the pool meanwhile.
func (t *TunnelState) acquireConn() (ssh.Conn, *clientConn) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var best ssh.Conn
	var bestState *clientConn
	bestLoad := int64(-1)
	seen := 0
	for conn, state := range t.clients {
		load := state.inFlight.Load()
		switch {
		case bestLoad < 0 || load < bestLoad:
			best, bestState, bestLoad, seen = conn, state, load, 1
		case load == bestLoad:
			// Reservoir-sample among equally loaded connections so ties are
			// spread rather than decided by Go's map iteration order.
			seen++
			if rand.IntN(seen) == 0 {
				best, bestState = conn, state
			}
		}
	}
	if bestState == nil {
		return nil, nil
	}
	bestState.inFlight.Add(1)
	return best, bestState
}

// warmPoolCapacity bounds how many pre-opened channels the server will park per
// connection. The client decides how many to offer; this only caps what the
// server will hold, so a client offering more simply has the excess rejected.
const warmPoolCapacity = 32

// OfferWarmChannel parks a client-supplied pre-opened channel for later use.
// It reports false if the pool is full or the connection is unknown, in which
// case the caller must close the channel.
func (t *TunnelState) OfferWarmChannel(conn ssh.Conn, ch ssh.Channel) bool {
	t.mu.RLock()
	state := t.clients[conn]
	t.mu.RUnlock()
	if state == nil {
		return false
	}
	select {
	case state.warm <- ch:
		return true
	default:
		return false
	}
}

// takeWarmChannel leases a parked channel, or returns nil if none is available.
// A nil return is the normal case for an older client and means the caller
// should fall back to opening a channel on demand.
func takeWarmChannel(state *clientConn) ssh.Channel {
	if state == nil {
		return nil
	}
	select {
	case ch := <-state.warm:
		return ch
	default:
		return nil
	}
}

// closeWarmChannels drains and closes any parked channels for a departing
// connection, so the client's paired goroutines unblock instead of leaking.
func closeWarmChannels(state *clientConn) {
	if state == nil {
		return
	}
	for {
		select {
		case ch := <-state.warm:
			ch.Close()
		default:
			return
		}
	}
}

// ReleaseConn records that a request occupying the connection has finished.
func ReleaseConn(state *clientConn) {
	if state != nil {
		state.inFlight.Add(-1)
	}
}

// AddClient registers a new client connection.
func (t *TunnelState) AddClient(conn ssh.Conn, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.clients == nil {
		t.clients = make(map[ssh.Conn]*clientConn)
	}
	t.clients[conn] = &clientConn{
		addr:        addr,
		connectedAt: time.Now(),
		warm:        make(chan ssh.Channel, warmPoolCapacity),
	}
}

// RemoveClient removes a specific client connection and closes any warm
// channels it had parked.
func (t *TunnelState) RemoveClient(conn ssh.Conn) {
	t.mu.Lock()
	state := t.clients[conn]
	delete(t.clients, conn)
	t.mu.Unlock()
	closeWarmChannels(state)
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
	}
}

// Registry holds all configured tunnels and provides lookups.
type Registry struct {
	mu           sync.RWMutex
	byID         map[string]*TunnelState
	byHost       map[string]*TunnelState
	byPort       map[int]*TunnelState
	ipPolicies   map[string]*IPPolicyState
	authPolicies map[string]*AuthPolicyState
}

func NewRegistry() *Registry {
	return &Registry{
		byID:         make(map[string]*TunnelState),
		byHost:       make(map[string]*TunnelState),
		byPort:       make(map[int]*TunnelState),
		ipPolicies:   make(map[string]*IPPolicyState),
		authPolicies: make(map[string]*AuthPolicyState),
	}
}

// SetPolicies replaces the registry's access policies (called at startup and on
// config reload).
func (r *Registry) SetPolicies(ip []*IPPolicyState, auth []*AuthPolicyState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ipPolicies = make(map[string]*IPPolicyState, len(ip))
	for _, p := range ip {
		r.ipPolicies[p.ID] = p
	}
	r.authPolicies = make(map[string]*AuthPolicyState, len(auth))
	for _, p := range auth {
		r.authPolicies[p.ID] = p
	}
}

func (r *Registry) FindIPPolicy(id string) *IPPolicyState {
	if id == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ipPolicies[id]
}

func (r *Registry) FindAuthPolicy(id string) *AuthPolicyState {
	if id == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.authPolicies[id]
}

// AllIPPolicies returns all IP policies, sorted by ID.
func (r *Registry) AllIPPolicies() []*IPPolicyState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*IPPolicyState, 0, len(r.ipPolicies))
	for _, p := range r.ipPolicies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// AllAuthPolicies returns all auth policies, sorted by ID.
func (r *Registry) AllAuthPolicies() []*AuthPolicyState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*AuthPolicyState, 0, len(r.authPolicies))
	for _, p := range r.authPolicies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
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
