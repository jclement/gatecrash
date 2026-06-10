package server

import (
	"log/slog"
	"net"

	"github.com/jclement/gatecrash/internal/config"
)

// IPPolicyState is the runtime form of a config IPPolicy: a reusable source-IP
// allowlist that tunnels reference by ID.
type IPPolicyState struct {
	ID          string
	Ranges      []config.IPRange // raw entries (cidr + comment), for display
	EnrollToken string
	nets        []*net.IPNet // parsed Ranges, for matching
}

func newIPPolicyState(p config.IPPolicy) *IPPolicyState {
	s := &IPPolicyState{ID: p.ID, Ranges: p.Ranges, EnrollToken: p.EnrollToken}
	for _, r := range p.Ranges {
		s.nets = append(s.nets, parseCIDROrIP(p.ID, r.CIDR)...)
	}
	return s
}

// Allows reports whether ip matches one of the policy's permanent ranges.
// Self-service (TTL'd) grants are checked separately via the IPAllowStore.
func (p *IPPolicyState) Allows(ip net.IP) bool {
	if p == nil || ip == nil {
		return false
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// CIDRs returns the raw range strings (for display/serialization).
func (p *IPPolicyState) CIDRs() []string {
	out := make([]string, 0, len(p.Ranges))
	for _, r := range p.Ranges {
		out = append(out, r.CIDR)
	}
	return out
}

// parseCIDROrIP turns a CIDR or bare IP into a network, skipping (and logging)
// anything that doesn't parse so one bad entry can't break the policy.
func parseCIDROrIP(policyID, entry string) []*net.IPNet {
	if _, n, err := net.ParseCIDR(entry); err == nil {
		return []*net.IPNet{n}
	}
	if ip := net.ParseIP(entry); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return []*net.IPNet{{IP: ip, Mask: net.CIDRMask(bits, bits)}}
	}
	slog.Warn("ignoring invalid ip_policy range", "policy", policyID, "entry", entry)
	return nil
}
