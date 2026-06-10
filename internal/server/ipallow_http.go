package server

import (
	"encoding/json"
	"fmt"
	"html"
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
	tunnelID := r.URL.Query().Get("tunnel")
	returnURL := r.URL.Query().Get("return")

	tunnel := s.registry.FindByID(tunnelID)
	if tunnel == nil {
		s.serveErrorPage(w, r, http.StatusNotFound, "Unknown Tunnel",
			"There is no tunnel with that ID.")
		return
	}
	ip := clientIP(r)
	if ip == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Authorization Failed",
			"Could not determine your IP address.")
		return
	}

	name := tunnelID
	if hosts := tunnel.HostnameList(); len(hosts) > 0 {
		name = hosts[0]
	}
	csrf := s.sessionMgr.CSRFToken(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize IP — Gatecrash</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f5f5; color: #333; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; }
  .card { background: white; border-radius: 8px; padding: 48px; max-width: 480px;
          text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  h1 { font-size: 20px; margin-bottom: 12px; }
  p { color: #666; line-height: 1.6; font-size: 14px; margin-bottom: 8px; }
  .ip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #333; }
  .btn { margin-top: 16px; padding: 12px 24px; background: #2563eb; color: white;
         border: none; cursor: pointer; border-radius: 6px; font-size: 14px; font-weight: 600; }
  .btn:hover { background: #1d4ed8; }
  .footer { margin-top: 24px; font-size: 12px; color: #bbb; }
</style>
</head>
<body>
<div class="card">
  <h1>Authorize this IP</h1>
  <p>Grant <span class="ip">%s</span> access to <strong>%s</strong> for 7 days?</p>
  <form method="POST" action="/authorize-ip">
    <input type="hidden" name="tunnel" value="%s">
    <input type="hidden" name="return" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <button class="btn" type="submit">Authorize this IP</button>
  </form>
  <div class="footer">Gatecrash</div>
</div>
</body>
</html>`,
		html.EscapeString(ip.String()), html.EscapeString(name),
		html.EscapeString(tunnelID), html.EscapeString(returnURL), html.EscapeString(csrf))
}

// handleAuthorizeIPSubmit (POST) performs the grant after validating CSRF.
func (s *Server) handleAuthorizeIPSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.sessionMgr.ValidCSRFToken(r, r.FormValue("csrf_token")) {
		s.serveErrorPage(w, r, http.StatusForbidden, "Authorization Failed",
			"Invalid or expired form token. Please try again.")
		return
	}

	tunnelID := r.FormValue("tunnel")
	returnURL := r.FormValue("return")

	tunnel := s.registry.FindByID(tunnelID)
	if tunnel == nil {
		s.serveErrorPage(w, r, http.StatusNotFound, "Unknown Tunnel",
			"There is no tunnel with that ID.")
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

	actor := s.sessionMgr.GetActor(r)
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
	s.serveIPAuthorizedPage(w, r, tunnelID, ip.String())
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

func (s *Server) serveIPAuthorizedPage(w http.ResponseWriter, _ *http.Request, tunnelID, ip string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Authorized — Gatecrash</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f5f5; color: #333; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; }
  .card { background: white; border-radius: 8px; padding: 48px; max-width: 480px;
          text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  h1 { font-size: 20px; margin-bottom: 12px; color: #16a34a; }
  p { color: #666; line-height: 1.6; font-size: 14px; margin-bottom: 8px; }
  .ip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #333; }
  .footer { margin-top: 24px; font-size: 12px; color: #bbb; }
</style>
</head>
<body>
<div class="card">
  <h1>&#10003; IP Authorized</h1>
  <p>Your address <span class="ip">%s</span> may now access <strong>%s</strong> for the next 7 days.</p>
  <p>You can close this page.</p>
  <div class="footer">Gatecrash</div>
</div>
</body>
</html>`, html.EscapeString(ip), html.EscapeString(tunnelID))
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
	s.auditLog.Log(s.sessionMgr.GetActor(r), "ip_policy.revoke",
		fmt.Sprintf("Revoked IP %s from ip_policy %q", ip, id))
	w.WriteHeader(http.StatusNoContent)
}
