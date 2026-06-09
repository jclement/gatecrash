package server

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// ipGrantTTL is how long a self-service IP authorization lasts.
const ipGrantTTL = 7 * 24 * time.Hour

// handleAuthorizeIP authorizes the caller's source IP for a tunnel. It is mounted
// on the admin host behind requireAuth, so reaching it proves the visitor is an
// authenticated admin. The browser's egress IP is granted (which is also the
// egress IP of any tool — e.g. an MCP client — sharing that network).
func (s *Server) handleAuthorizeIP(w http.ResponseWriter, r *http.Request) {
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

	actor := s.sessionMgr.GetActor(r)
	if err := s.ipAllow.Grant(tunnelID, ip.String(), actor, ipGrantTTL); err != nil {
		slog.Error("failed to grant ip", "tunnel", tunnelID, "ip", ip, "error", err)
		s.serveErrorPage(w, r, http.StatusInternalServerError, "Authorization Failed",
			"Failed to record the authorization. Please try again.")
		return
	}
	s.auditLog.Log(actor, "tunnel.ip_authorize",
		fmt.Sprintf("Authorized IP %s for tunnel %q (7 days)", ip, tunnelID))
	slog.Info("ip authorized", "tunnel", tunnelID, "ip", ip, "by", actor)

	// Send the user back to where they came from if the return URL is a safe
	// https URL on one of this tunnel's hostnames; otherwise show confirmation.
	if u := safeTunnelReturnURL(returnURL, tunnel); u != "" {
		http.Redirect(w, r, u, http.StatusFound)
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
	for _, h := range tunnel.Hostnames {
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

// handleListTunnelIPs returns a tunnel's permanent allowlist and live grants.
func (s *Server) handleListTunnelIPs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tunnel := s.registry.FindByID(id)
	if tunnel == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	resp := struct {
		IPAllowlist bool      `json:"ip_allowlist"`
		Static      []string  `json:"static"`
		Grants      []IPGrant `json:"grants"`
	}{
		IPAllowlist: tunnel.IPAllowlist,
		Static:      tunnel.AllowIPs,
		Grants:      s.ipAllow.List(id),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleRevokeTunnelIP removes a self-service grant.
func (s *Server) handleRevokeTunnelIP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ip := r.PathValue("ip")
	if err := s.ipAllow.Revoke(id, ip); err != nil {
		slog.Error("failed to revoke ip grant", "tunnel", id, "ip", ip, "error", err)
		http.Error(w, "failed to revoke", http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "tunnel.ip_revoke",
		fmt.Sprintf("Revoked IP %s from tunnel %q", ip, id))
	w.WriteHeader(http.StatusNoContent)
}
