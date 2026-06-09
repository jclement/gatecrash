package server

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/jclement/gatecrash/internal/config"
)

// AuthPolicyState is the runtime form of a config AuthPolicy. Methods are OR'd:
// a request authenticates if it satisfies any enabled method.
type AuthPolicyState struct {
	ID          string
	Methods     []string
	ClaimName   string
	ClaimValue  string
	Header      string
	HeaderClaim string
	Username    string
	PasswordHash string
}

func newAuthPolicyState(p config.AuthPolicy) *AuthPolicyState {
	return &AuthPolicyState{
		ID:           p.ID,
		Methods:      p.Methods,
		ClaimName:    p.ClaimName,
		ClaimValue:   p.ClaimValue,
		Header:       p.Header,
		HeaderClaim:  p.HeaderClaim,
		Username:     p.Username,
		PasswordHash: p.PasswordHash,
	}
}

func (p *AuthPolicyState) hasMethod(m string) bool {
	for _, x := range p.Methods {
		if x == m {
			return true
		}
	}
	return false
}

func (p *AuthPolicyState) usesSystem() bool   { return p.hasMethod(config.AuthMethodSystem) }
func (p *AuthPolicyState) usesPassword() bool { return p.hasMethod(config.AuthMethodPassword) }

// headerName returns the identity header to inject, defaulting to x-Gatecrash-User.
func (p *AuthPolicyState) headerName() string {
	if p.Header != "" {
		return p.Header
	}
	return "x-Gatecrash-User"
}

// checkBasic validates HTTP Basic credentials against the policy's password.
// The bcrypt comparison is bounded by the shared concurrency semaphore so a
// flood of bad credentials can't exhaust CPU. Returns the username on success.
func (s *Server) checkBasic(r *http.Request, pol *AuthPolicyState) (string, bool) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return "", false
	}
	if pol.Username != "" && user != pol.Username {
		return "", false
	}
	if pol.PasswordHash == "" {
		return "", false
	}
	// Bound concurrent bcrypt (shared with SSH auth) to blunt CPU-flood attempts.
	select {
	case s.bcryptSem <- struct{}{}:
		defer func() { <-s.bcryptSem }()
	default:
		return "", false
	}
	if bcrypt.CompareHashAndPassword([]byte(pol.PasswordHash), []byte(pass)) != nil {
		return "", false
	}
	return user, true
}
