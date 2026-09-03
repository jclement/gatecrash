//go:build dev

package server

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/jclement/gatecrash/internal/admin"
)

// This file only compiles under the "dev" build tag. It implements the local
// development conveniences (admin auth bypass and self-signed TLS) that must
// never exist in a released binary. Release builds use devauth_off.go, where
// these are compile-time no-ops.

// devSessionSID is a fixed session id for the dev admin so the derived CSRF
// token is stable across requests (a fresh SID per request would break CSRF on
// mutating API calls).
const devSessionSID = "dev-session"

// devNoAuth reports whether the admin panel auth bypass is active. Gated on an
// env var so the same dev binary can serve both `mise run server` (bypass on)
// and `mise run server:auth` (bypass off).
func (s *Server) devNoAuth() bool { return os.Getenv("GATECRASH_DEV_NOAUTH") == "1" }

// devSelfSigned reports whether the server should serve a self-signed
// certificate for the configured hostnames instead of obtaining real ACME
// certificates. Used for local HTTPS testing on lvh.me hostnames.
func (s *Server) devSelfSigned() bool { return os.Getenv("GATECRASH_DEV_SELFSIGNED") == "1" }

// devSeedAdmin provisions the passkey-less dev admin when the no-auth bypass is
// active, so sessionUser() resolves to a real admin record.
func (s *Server) devSeedAdmin() {
	if !s.devNoAuth() || s.users == nil {
		return
	}
	if err := s.users.EnsureDevAdmin(); err != nil {
		slog.Error("dev: failed to seed dev admin", "error", err)
		return
	}
	slog.Warn("DEV NO-AUTH MODE — admin panel is open, auto-logged-in as dev admin")
}

// devEnsureSession mints a dev-admin session cookie for requests that don't
// already carry a valid one, when the no-auth bypass is active. Returning true
// means a session was just issued (the caller should let the request proceed).
func (s *Server) devEnsureSession(w http.ResponseWriter, r *http.Request) bool {
	if !s.devNoAuth() || s.sessionMgr == nil {
		return false
	}
	if s.sessionMgr.ValidateSession(r) {
		return false
	}
	if err := s.sessionMgr.IssueDevSession(w, r, admin.DevAdminID, admin.RoleAdmin, devSessionSID); err != nil {
		slog.Error("dev: failed to issue dev session", "error", err)
		return false
	}
	return true
}
