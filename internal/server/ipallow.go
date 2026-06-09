package server

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

// IPGrant is a single self-service IP authorization for a tunnel. Grants are
// created when an authenticated admin authorizes their current source IP, and
// expire after a TTL (dynamic IPs change, so grants are intentionally temporary).
type IPGrant struct {
	IP        string    `json:"ip"`
	GrantedBy string    `json:"granted_by"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (g IPGrant) expired(now time.Time) bool { return now.After(g.ExpiresAt) }

// maxGrantsPerTunnel bounds the live self-service grants kept for one tunnel, so
// a flapping/rotating source IP can't grow the store without limit. When
// exceeded, the oldest grants are evicted.
const maxGrantsPerTunnel = 256

// IPAllowStore persists per-tunnel self-service IP grants to a JSON file. It is
// safe for concurrent use. Permanent allowlist entries live in the tunnel config
// (AllowIPs); this store holds only the dynamic, TTL'd grants.
type IPAllowStore struct {
	mu     sync.Mutex
	path   string
	grants map[string][]IPGrant // tunnelID -> grants
}

// NewIPAllowStore loads grants from path (creating an empty store if absent).
func NewIPAllowStore(path string) (*IPAllowStore, error) {
	s := &IPAllowStore{path: path, grants: make(map[string][]IPGrant)}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading ip allowlist: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.grants); err != nil {
			return nil, fmt.Errorf("parsing ip allowlist: %w", err)
		}
	}
	if s.grants == nil {
		s.grants = make(map[string][]IPGrant)
	}
	return s, nil
}

// save writes the store atomically. Callers must hold s.mu.
func (s *IPAllowStore) save() error {
	data, err := json.MarshalIndent(s.grants, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Grant authorizes ip for the tunnel for ttl, refreshing any existing grant for
// the same IP. by identifies who created the grant (for the audit trail / UI).
func (s *IPAllowStore) Grant(tunnelID, ip, by string, ttl time.Duration) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	grants := s.grants[tunnelID]
	// Drop expired entries and any existing grant for this IP (we refresh it).
	kept := grants[:0]
	for _, g := range grants {
		if g.expired(now) || g.IP == ip {
			continue
		}
		kept = append(kept, g)
	}
	kept = append(kept, IPGrant{
		IP:        ip,
		GrantedBy: by,
		GrantedAt: now,
		ExpiresAt: now.Add(ttl),
	})
	// Bound the per-tunnel grant count, evicting the oldest.
	if len(kept) > maxGrantsPerTunnel {
		sort.Slice(kept, func(i, j int) bool { return kept[i].GrantedAt.Before(kept[j].GrantedAt) })
		kept = kept[len(kept)-maxGrantsPerTunnel:]
	}
	s.grants[tunnelID] = kept
	return s.save()
}

// IsGranted reports whether ip currently has a live grant for the tunnel.
func (s *IPAllowStore) IsGranted(tunnelID string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	target := ip.String()
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.grants[tunnelID] {
		if g.IP == target && !g.expired(now) {
			return true
		}
	}
	return false
}

// List returns the live (non-expired) grants for a tunnel, newest first.
func (s *IPAllowStore) List(tunnelID string) []IPGrant {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var live []IPGrant
	for _, g := range s.grants[tunnelID] {
		if !g.expired(now) {
			live = append(live, g)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].GrantedAt.After(live[j].GrantedAt) })
	return live
}

// Revoke removes a grant for the given tunnel/IP. It is not an error if absent.
func (s *IPAllowStore) Revoke(tunnelID, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	grants := s.grants[tunnelID]
	kept := grants[:0]
	for _, g := range grants {
		if g.IP != ip {
			kept = append(kept, g)
		}
	}
	s.grants[tunnelID] = kept
	return s.save()
}

// pruneExpired drops expired grants and persists if anything changed.
func (s *IPAllowStore) pruneExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for id, grants := range s.grants {
		kept := grants[:0]
		for _, g := range grants {
			if g.expired(now) {
				changed = true
				continue
			}
			kept = append(kept, g)
		}
		if len(kept) == 0 {
			delete(s.grants, id)
		} else {
			s.grants[id] = kept
		}
	}
	if changed {
		_ = s.save()
	}
}
