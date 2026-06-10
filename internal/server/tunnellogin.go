package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file holds the cross-host tunnel-login handoff, previously smeared across
// server.go and vhost.go. The flow: a visitor to a protected tunnel with no
// tunnel session is bounced to the admin host (initiateTunnelLogin); once signed
// in there, the admin host parks a one-time token carrying their identity and
// redirects back to the tunnel host (handleTunnelLogin); the tunnel host consumes
// the token and sets its own session cookie (handleTunnelLoginComplete). Pending
// tokens are expired by cleanupPendingTunnelAuth. The backing map lives on Server
// (pendingTunnelAuth) so it can be shared across hostnames.

// pendingTunnelAuthResult holds an authenticated user's identity for a one-time
// cross-host login handoff.
type pendingTunnelAuthResult struct {
	userID    string
	role      string
	hostname  string
	returnURL string
	expires   time.Time
}

// cleanupPendingTunnelAuth periodically removes expired pending tunnel auth tokens.
func (s *Server) cleanupPendingTunnelAuth(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.pendingTunnelAuthMu.Lock()
			for k, v := range s.pendingTunnelAuth {
				if now.After(v.expires) {
					delete(s.pendingTunnelAuth, k)
				}
			}
			s.pendingTunnelAuthMu.Unlock()
		}
	}
}

// initiateTunnelLogin (runs on the tunnel host) redirects an unauthenticated
// visitor to the admin host to sign in, carrying the hostname and return URL.
func (s *Server) initiateTunnelLogin(w http.ResponseWriter, r *http.Request, hostname string) {
	s.cfgMu.RLock()
	adminHost := s.cfg.Server.AdminHost
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()

	if adminHost == "" {
		s.serveErrorPage(w, r, http.StatusForbidden, "Access Denied",
			"This service requires authentication, but no admin host is configured.")
		return
	}
	returnURL := fmt.Sprintf("https://%s%s", hostname, r.URL.RequestURI())
	base := "https://" + adminHost
	if httpsPort != 443 {
		base = fmt.Sprintf("https://%s:%d", adminHost, httpsPort)
	}
	http.Redirect(w, r, fmt.Sprintf("%s/tunnel-login?hostname=%s&return=%s",
		base, url.QueryEscape(hostname), url.QueryEscape(returnURL)), http.StatusFound)
}

// handleTunnelLogin runs on the admin host for a logged-in user. It parks a
// one-time token carrying the user's identity and redirects to the tunnel
// hostname to establish its session. requireAuth ensures the user is signed in
// (redirecting through /login first if not).
func (s *Server) handleTunnelLogin(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" || s.registry.FindByHostname(hostname) == nil {
		http.Error(w, "unknown tunnel hostname", http.StatusBadRequest)
		return
	}

	// Not signed in → show the bespoke "this service is protected" page. Its
	// passkey ceremony establishes a session and reloads this URL; the reload then
	// falls through to mint the handoff token. (This handler is intentionally not
	// behind requireAuth so unauthenticated visitors land here, not on the generic
	// admin login.)
	if s.sessionUser(r) == nil {
		if s.webauthn.NeedsSetup() {
			s.serveErrorPage(w, r, http.StatusServiceUnavailable, "Not Set Up",
				"This Gatecrash server has no users yet. Ask the administrator to finish setup.")
			return
		}
		s.renderStandalonePage(w, http.StatusOK, "service-login", serviceLoginPageData{
			Title:       "Sign in",
			ServiceHost: hostname,
		})
		return
	}

	returnURL := r.URL.Query().Get("return")
	if returnURL != "" {
		if u, err := url.Parse(returnURL); err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), hostname) {
			returnURL = ""
		}
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	oneTimeToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	s.pendingTunnelAuthMu.Lock()
	s.pendingTunnelAuth[oneTimeToken] = &pendingTunnelAuthResult{
		userID:    s.sessionMgr.UserID(r),
		role:      s.sessionMgr.Role(r),
		hostname:  hostname,
		returnURL: returnURL,
		expires:   time.Now().Add(60 * time.Second),
	}
	s.pendingTunnelAuthMu.Unlock()

	s.cfgMu.RLock()
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()
	completeURL := fmt.Sprintf("https://%s/.gatecrash/auth/complete?token=%s", hostname, oneTimeToken)
	if httpsPort != 443 {
		completeURL = fmt.Sprintf("https://%s:%d/.gatecrash/auth/complete?token=%s", hostname, httpsPort, oneTimeToken)
	}
	http.Redirect(w, r, completeURL, http.StatusFound)
}

// handleTunnelLoginComplete consumes the one-time handoff token and sets the
// tunnel session cookie for the authenticated user on this hostname.
func (s *Server) handleTunnelLoginComplete(w http.ResponseWriter, r *http.Request, hostname string) {
	oneTimeToken := r.URL.Query().Get("token")
	if oneTimeToken == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	s.pendingTunnelAuthMu.Lock()
	result, ok := s.pendingTunnelAuth[oneTimeToken]
	if ok {
		delete(s.pendingTunnelAuth, oneTimeToken)
	}
	s.pendingTunnelAuthMu.Unlock()

	if !ok || time.Now().After(result.expires) {
		s.serveErrorPage(w, r, http.StatusForbidden, "Authentication Failed",
			"Login token is invalid or expired. Please try again.")
		return
	}
	if result.hostname != hostname {
		http.Error(w, "hostname mismatch", http.StatusBadRequest)
		return
	}
	if err := s.tunnelSession.CreateSession(w, hostname, result.userID, result.role); err != nil {
		slog.Error("failed to create tunnel session", "error", err)
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	dest := "/"
	if result.returnURL != "" {
		if u, err := url.Parse(result.returnURL); err == nil && u.Scheme == "https" && strings.EqualFold(u.Hostname(), hostname) {
			dest = result.returnURL
		}
	}
	http.Redirect(w, r, dest, http.StatusFound)
}
