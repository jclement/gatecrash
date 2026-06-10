package server

import (
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jclement/gatecrash/internal/config"
)

// ServiceAuthUsername is the conventional HTTP Basic username for the
// machine-generated service secret. The username is not actually checked (all
// the entropy is in the secret); it exists so client configs and docs have a
// stable principal to show, and so the injected identity header has a value.
const ServiceAuthUsername = "service"

// AuthPolicyState is the runtime form of a config AuthPolicy. A request passes
// if it is a logged-in user in Users, or (optionally) presents the service
// secret via HTTP Basic.
type AuthPolicyState struct {
	ID         string
	Users      map[string]bool // allowed user IDs
	Header     string
	SecretHash string
}

func newAuthPolicyState(p config.AuthPolicy) *AuthPolicyState {
	users := make(map[string]bool, len(p.Users))
	for _, u := range p.Users {
		users[u] = true
	}
	return &AuthPolicyState{
		ID:         p.ID,
		Users:      users,
		Header:     p.Header,
		SecretHash: p.SecretHash,
	}
}

func (p *AuthPolicyState) allowsUser(id string) bool { return id != "" && p.Users[id] }
func (p *AuthPolicyState) requiresLogin() bool       { return len(p.Users) > 0 }
func (p *AuthPolicyState) usesSecret() bool          { return p.SecretHash != "" }

// headerName returns the identity header to inject, defaulting to x-Gatecrash-User.
func (p *AuthPolicyState) headerName() string {
	if p.Header != "" {
		return p.Header
	}
	return "x-Gatecrash-User"
}

// checkServiceSecret validates the HTTP Basic password against the policy's
// service-secret hash. The username is ignored (all entropy is in the secret).
// Credential-bearing requests are per-IP rate limited (a flood of bad secrets is
// shed cheaply before any bcrypt), and the bcrypt comparison is bounded by the
// shared concurrency semaphore so it can't exhaust CPU. Returns true on success.
func (s *Server) checkServiceSecret(r *http.Request, pol *AuthPolicyState) bool {
	_, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// Per-IP rate limit on actual credential attempts. Shed floods before bcrypt.
	if s.tunnelAuthLimiter != nil && !s.tunnelAuthLimiter.allow(basicAuthIP(r)) {
		return false
	}
	if pol.SecretHash == "" {
		return false
	}
	// Bound concurrent bcrypt (shared with SSH auth). Wait briefly rather than
	// failing instantly so a legitimate login survives a transient burst, but cap
	// the wait so a flood can't pile up goroutines (mirrors the SSH auth gate).
	select {
	case s.bcryptSem <- struct{}{}:
		defer func() { <-s.bcryptSem }()
	case <-time.After(s.sshAuthAcquireTimeout):
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(pol.SecretHash), []byte(pass)) == nil
}

// basicAuthIP returns the source IP of a request for rate-limiting keys.
func basicAuthIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
