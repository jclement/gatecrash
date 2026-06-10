package server

import (
	"net/http"
	"net/url"

	"github.com/jclement/gatecrash/internal/admin"
)

// This file holds the admin HTTP auth middleware: the require* wrappers that gate
// page and API handlers on session, role, and CSRF, plus the sessionUser lookup
// they share.

// sessionUser returns the live directory record for the request's session, or
// nil if there's no valid session or the user no longer exists. Looking the user
// up (rather than trusting the JWT) makes deletes and role changes take effect
// immediately, not at session expiry.
func (s *Server) sessionUser(r *http.Request) *admin.User {
	if !s.sessionMgr.ValidateSession(r) {
		return nil
	}
	return s.users.Get(s.sessionMgr.UserID(r))
}

// requireAuth wraps a page handler: any logged-in user. On first boot (no admin
// yet) it shows the not-initialized notice; otherwise it redirects to login,
// preserving the destination.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.webauthn.NeedsSetup() {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if s.sessionUser(r) == nil {
			s.sessionMgr.ClearSession(w)
			loginURL := "/login"
			if ret := r.URL.RequestURI(); ret != "/" && isSafeReturnURL(ret) {
				loginURL = "/login?return=" + url.QueryEscape(ret)
			}
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireAdmin wraps a page handler: must be a logged-in admin (verified live).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if u := s.sessionUser(r); u == nil || !u.IsAdmin() {
			s.serveErrorPage(w, r, http.StatusForbidden, "Admin Only",
				"You don't have access to this page.")
			return
		}
		next(w, r)
	})
}

// requireAuthAPI wraps an API handler: any logged-in user, 401 JSON otherwise.
func (s *Server) requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessionUser(r) == nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requireAdminAPI wraps an API handler: must be a logged-in admin (verified live).
func (s *Server) requireAdminAPI(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuthAPI(func(w http.ResponseWriter, r *http.Request) {
		if u := s.sessionUser(r); u == nil || !u.IsAdmin() {
			http.Error(w, `{"error":"admin only"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// requireCSRF wraps a mutating API handler: logged-in user + valid CSRF token.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuthAPI(func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionMgr.ValidCSRFToken(r, r.Header.Get("X-CSRF-Token")) {
			http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// requireAdminCSRF wraps a mutating admin API handler: admin (verified live) + CSRF.
func (s *Server) requireAdminCSRF(next http.HandlerFunc) http.HandlerFunc {
	return s.requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if u := s.sessionUser(r); u == nil || !u.IsAdmin() {
			http.Error(w, `{"error":"admin only"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
