package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"

	"github.com/jclement/gatecrash/internal/config"
)

// generateEnrollToken returns a URL-safe random bearer token for an enrollment
// link (256 bits of entropy).
func generateEnrollToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// findTunnelByEnrollToken returns the config tunnel whose enrollment token
// matches (constant-time), or ok=false.
func (s *Server) findTunnelByEnrollToken(token string) (config.Tunnel, bool) {
	if token == "" {
		return config.Tunnel{}, false
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	for _, t := range s.cfg.Tunnel {
		if t.EnrollToken == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(t.EnrollToken), []byte(token)) == 1 {
			return t, true
		}
	}
	return config.Tunnel{}, false
}

// enrollTokenFor returns the enrollment token configured for a tunnel ID.
func (s *Server) enrollTokenFor(id string) string {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	for _, t := range s.cfg.Tunnel {
		if t.ID == id {
			return t.EnrollToken
		}
	}
	return ""
}

// enrollURL builds the public enrollment link for a token on the admin host.
func (s *Server) enrollURL(token string) string {
	if token == "" {
		return ""
	}
	s.cfgMu.RLock()
	adminHost := s.cfg.Server.AdminHost
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()
	if adminHost == "" {
		return ""
	}
	base := "https://" + adminHost
	if httpsPort != 443 {
		base = fmt.Sprintf("https://%s:%d", adminHost, httpsPort)
	}
	return base + "/enroll/" + token
}

// publicURLFor builds the public https URL for a tunnel's first hostname.
func (s *Server) publicURLFor(t config.Tunnel) string {
	if t.Type != "http" || len(t.Hostnames) == 0 {
		return ""
	}
	s.cfgMu.RLock()
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()
	if httpsPort != 443 {
		return fmt.Sprintf("https://%s:%d", t.Hostnames[0], httpsPort)
	}
	return "https://" + t.Hostnames[0]
}

func tunnelLabel(t config.Tunnel) string {
	if len(t.Hostnames) > 0 {
		return t.Hostnames[0]
	}
	return t.ID
}

// handleEnrollPage (GET /enroll/{token}) shows an unauthenticated confirmation
// page for self-authorizing the visitor's source IP. The grant happens on POST
// (so link-preview bots / scanners can't enroll by merely fetching the URL).
func (s *Server) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	tunnel, ok := s.findTunnelByEnrollToken(token)
	if !ok {
		s.serveErrorPage(w, r, http.StatusNotFound, "Invalid Link",
			"This enrollment link is not valid. It may have been rotated or removed.")
		return
	}
	ip := clientIP(r)
	if ip == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Enrollment Failed",
			"Could not determine your IP address.")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize Access — Gatecrash</title>
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
  <h1>Authorize Access</h1>
  <p>You've been invited to access <strong>%s</strong>.</p>
  <p>Authorize your current IP <span class="ip">%s</span> for 7 days?</p>
  <form method="POST" action="/enroll/%s">
    <button class="btn" type="submit">Authorize my IP</button>
  </form>
  <div class="footer">Gatecrash</div>
</div>
</body>
</html>`,
		html.EscapeString(tunnelLabel(tunnel)), html.EscapeString(ip.String()), html.EscapeString(token))
}

// handleEnrollSubmit (POST /enroll/{token}) records the grant and confirms.
func (s *Server) handleEnrollSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	tunnel, ok := s.findTunnelByEnrollToken(token)
	if !ok {
		s.serveErrorPage(w, r, http.StatusNotFound, "Invalid Link",
			"This enrollment link is not valid. It may have been rotated or removed.")
		return
	}
	ip := clientIP(r)
	if ip == nil {
		s.serveErrorPage(w, r, http.StatusBadRequest, "Enrollment Failed",
			"Could not determine your IP address.")
		return
	}

	if err := s.ipAllow.Grant(tunnel.ID, ip.String(), "enrollment-link", ipGrantTTL); err != nil {
		slog.Error("failed to grant ip via enroll link", "tunnel", tunnel.ID, "ip", ip, "error", err)
		s.serveErrorPage(w, r, http.StatusInternalServerError, "Enrollment Failed",
			"Failed to record the authorization. Please try again.")
		return
	}
	s.auditLog.Log("enrollment-link", "tunnel.ip_authorize",
		fmt.Sprintf("Self-enrolled IP %s for tunnel %q via link (7 days)", ip, tunnel.ID))
	slog.Info("ip self-enrolled via link", "tunnel", tunnel.ID, "ip", ip)

	appURL := s.publicURLFor(tunnel)
	continueBtn := ""
	if appURL != "" {
		continueBtn = fmt.Sprintf(`<a class="btn" href="%s">Continue to %s</a>`,
			html.EscapeString(appURL), html.EscapeString(tunnelLabel(tunnel)))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Authorized — Gatecrash</title>
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
  .btn { display: inline-block; margin-top: 16px; padding: 12px 24px; background: #2563eb;
         color: white; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 600; }
  .btn:hover { background: #1d4ed8; }
  .footer { margin-top: 24px; font-size: 12px; color: #bbb; }
</style>
</head>
<body>
<div class="card">
  <h1>&#10003; Access Authorized</h1>
  <p>Your IP <span class="ip">%s</span> may now access <strong>%s</strong> for 7 days.</p>
  %s
  <div class="footer">Gatecrash</div>
</div>
</body>
</html>`,
		html.EscapeString(ip.String()), html.EscapeString(tunnelLabel(tunnel)), continueBtn)
}

// handleRotateEnrollToken (POST) generates a new enrollment token for a tunnel,
// invalidating any previous link, and returns the new URL.
func (s *Server) handleRotateEnrollToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token, err := generateEnrollToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	s.cfgMu.Lock()
	found := false
	for i := range s.cfg.Tunnel {
		if s.cfg.Tunnel[i].ID == id {
			s.cfg.Tunnel[i].EnrollToken = token
			found = true
			break
		}
	}
	var saveErr error
	if found {
		saveErr = s.cfg.Save(s.configPath)
	}
	s.cfgMu.Unlock()

	if !found {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	if saveErr != nil {
		slog.Error("failed to save config", "error", saveErr)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	s.auditLog.Log(s.sessionMgr.GetActor(r), "tunnel.enroll_token.rotate",
		fmt.Sprintf("Rotated enrollment link for tunnel %q", id))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": s.enrollURL(token)})
}

// handleDeleteEnrollToken (DELETE) removes a tunnel's enrollment link.
func (s *Server) handleDeleteEnrollToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.cfgMu.Lock()
	found := false
	for i := range s.cfg.Tunnel {
		if s.cfg.Tunnel[i].ID == id {
			s.cfg.Tunnel[i].EnrollToken = ""
			found = true
			break
		}
	}
	var saveErr error
	if found {
		saveErr = s.cfg.Save(s.configPath)
	}
	s.cfgMu.Unlock()

	if !found {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	if saveErr != nil {
		slog.Error("failed to save config", "error", saveErr)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	s.auditLog.Log(s.sessionMgr.GetActor(r), "tunnel.enroll_token.remove",
		fmt.Sprintf("Removed enrollment link for tunnel %q", id))
	w.WriteHeader(http.StatusNoContent)
}
