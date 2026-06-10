package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jclement/gatecrash/internal/config"
)

// ipGrantTTL is how long a self-service IP authorization lasts.
const ipGrantTTL = 7 * 24 * time.Hour

// handleAuthorizeIPPage (GET) shows a confirmation page for authorizing the
// caller's source IP. Mounted on the admin host behind requireAuth, so reaching
// it proves the visitor is an authenticated admin. The actual grant happens on a
// CSRF-protected POST (handleAuthorizeIPSubmit) — a state change must not be
// drivable by a cross-site GET navigation.
func (s *Server) handleAuthorizeIPPage(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("return")
	tunnel := s.tunnelFromReturnURL(returnURL)
	if tunnel == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Authorization Failed",
			"This authorization link is invalid.")
		return
	}
	ip := clientIP(r)
	if ip == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Authorization Failed",
			"Could not determine your IP address.")
		return
	}

	name := ""
	if hosts := tunnel.HostnameList(); len(hosts) > 0 {
		name = hosts[0]
	}

	s.renderStandalonePage(w, http.StatusOK, "ip-authorize", ipAuthorizePageData{
		Title:     "Authorize IP",
		IP:        ip.String(),
		Name:      name,
		ReturnURL: returnURL,
		CSRF:      s.sessionMgr.CSRFToken(r),
	})
}

// tunnelFromReturnURL resolves the tunnel for an authorize-ip flow from the
// service return URL's hostname. Keying off the hostname (instead of an explicit
// tunnel ID in the link) keeps internal IDs out of anything a visitor can see.
func (s *Server) tunnelFromReturnURL(raw string) *TunnelState {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	return s.registry.FindByHostname(u.Hostname())
}

// handleAuthorizeIPSubmit (POST) performs the grant after validating CSRF.
func (s *Server) handleAuthorizeIPSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.sessionMgr.ValidCSRFToken(r, r.FormValue("csrf_token")) {
		s.serveErrorPage(w, r, http.StatusForbidden, "Authorization Failed",
			"Invalid or expired form token. Please try again.")
		return
	}

	returnURL := r.FormValue("return")
	tunnel := s.tunnelFromReturnURL(returnURL)
	if tunnel == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Authorization Failed",
			"This authorization link is invalid.")
		return
	}
	ip := clientIP(r)
	if ip == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Authorization Failed",
			"Could not determine your IP address.")
		return
	}
	pol := s.registry.FindIPPolicy(tunnel.IPPolicy())
	if pol == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Authorization Failed",
			"This tunnel has no IP policy.")
		return
	}

	actor := s.actorName(r)
	if err := s.ipAllow.Grant(pol.ID, ip.String(), actor, ipGrantTTL); err != nil {
		slog.Error("failed to grant ip", "policy", pol.ID, "ip", ip, "error", err)
		s.serveErrorPage(w, r, http.StatusInternalServerError, "Authorization Failed",
			"Failed to record the authorization. Please try again.")
		return
	}
	s.auditLog.Log(actor, "ip_policy.authorize",
		fmt.Sprintf("Authorized IP %s for ip_policy %q (7 days)", ip, pol.ID))
	slog.Info("ip authorized", "policy", pol.ID, "ip", ip, "by", actor)

	// Send the user back to the originating app if the return URL is a safe https
	// URL on one of this tunnel's hostnames; otherwise show a confirmation page.
	if u := safeTunnelReturnURL(returnURL, tunnel); u != "" {
		http.Redirect(w, r, u, http.StatusSeeOther)
		return
	}
	// Show the hostname (which the admin already sees in the URL), not the
	// internal tunnel ID. TCP tunnels have no hostname → generic confirmation.
	name := ""
	if hosts := tunnel.HostnameList(); len(hosts) > 0 {
		name = hosts[0]
	}
	s.serveIPAuthorizedPage(w, r, name, ip.String())
}

// safeTunnelReturnURL returns the URL if it is an https URL whose host is one of
// the tunnel's hostnames, else "" (guards against open redirects).
func safeTunnelReturnURL(raw string, tunnel *TunnelState) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ""
	}
	for _, h := range tunnel.HostnameList() {
		if h == u.Hostname() {
			return u.String()
		}
	}
	return ""
}

// serveIPAuthorizedPage confirms a grant. name is a display label (a hostname)
// or "" for a generic message — never an internal tunnel/policy ID.
func (s *Server) serveIPAuthorizedPage(w http.ResponseWriter, _ *http.Request, name, ip string) {
	s.renderStandalonePage(w, http.StatusOK, "ip-authorized", ipAuthorizedPageData{
		Title:   "IP Authorized",
		Heading: "IP Authorized",
		IP:      ip,
		Name:    name,
	})
}

// handleListPolicyIPs returns an IP policy's permanent ranges and live grants.
func (s *Server) handleListPolicyIPs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pol := s.registry.FindIPPolicy(id)
	if pol == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	resp := struct {
		Ranges    []config.IPRange `json:"ranges"`
		Grants    []IPGrant        `json:"grants"`
		EnrollURL string           `json:"enroll_url"`
	}{
		Ranges:    pol.Ranges,
		Grants:    s.ipAllow.List(id),
		EnrollURL: s.enrollURL(pol.EnrollToken),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleRevokePolicyIP removes a self-service grant from an IP policy.
func (s *Server) handleRevokePolicyIP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ip := r.PathValue("ip")
	if err := s.ipAllow.Revoke(id, ip); err != nil {
		slog.Error("failed to revoke ip grant", "policy", id, "ip", ip, "error", err)
		http.Error(w, "failed to revoke", http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(s.actorName(r), "ip_policy.revoke",
		fmt.Sprintf("Revoked IP %s from ip_policy %q", ip, id))
	w.WriteHeader(http.StatusNoContent)
}
