package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

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

// findIPPolicyByEnrollToken returns the config IP policy whose enrollment token
// matches (constant-time), or ok=false.
func (s *Server) findIPPolicyByEnrollToken(token string) (config.IPPolicy, bool) {
	if token == "" {
		return config.IPPolicy{}, false
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	for _, p := range s.cfg.IPPolicy {
		if p.EnrollToken == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(p.EnrollToken), []byte(token)) == 1 {
			return p, true
		}
	}
	return config.IPPolicy{}, false
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

// handleEnrollPage (GET /enroll/{token}) shows an unauthenticated confirmation
// page for self-authorizing the visitor's source IP. The grant happens on POST
// (so link-preview bots / scanners can't enroll by merely fetching the URL).
func (s *Server) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	pol, ok := s.findIPPolicyByEnrollToken(token)
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

	data := enrollPageData{
		Title: "Authorize Access",
		IP:    ip.String(),
		Label: policyLabel(pol),
		Token: token,
	}
	switch {
	case s.staticAllows(pol.ID, ip):
		// Permanently allowlisted in config — no self-service grant needed.
		data.Heading = "You already have access"
		data.Mode = "static"
	case s.grantRemaining(pol.ID, ip) != "":
		// Already enrolled — offer to extend (re-grant bumps the 7-day clock).
		data.Heading = "You're already authorized"
		data.Mode = "extend"
		data.Remaining = s.grantRemaining(pol.ID, ip)
	default:
		data.Heading = "Authorize Access"
		data.Mode = ""
	}
	s.renderStandalonePage(w, http.StatusOK, "enroll", data)
}

func policyLabel(p config.IPPolicy) string { return p.ID }

// staticAllows reports whether ip is permanently allowed by the IP policy.
func (s *Server) staticAllows(policyID string, ip net.IP) bool {
	pol := s.registry.FindIPPolicy(policyID)
	return pol != nil && pol.Allows(ip)
}

// grantRemaining returns a human-readable remaining time for a live self-service
// grant, or "" if the IP has no live grant for the policy.
func (s *Server) grantRemaining(policyID string, ip net.IP) string {
	g, ok := s.ipAllow.GrantFor(policyID, ip)
	if !ok {
		return ""
	}
	return humanizeDuration(time.Until(g.ExpiresAt))
}

func humanizeDuration(d time.Duration) string {
	if d <= 0 {
		return "less than a minute"
	}
	if days := int(d.Hours()) / 24; days >= 1 {
		return plural(days, "day")
	}
	if hours := int(d.Hours()); hours >= 1 {
		return plural(hours, "hour")
	}
	return plural(max(1, int(d.Minutes())), "minute")
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// handleEnrollSubmit (POST /enroll/{token}) records the grant and confirms.
func (s *Server) handleEnrollSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	pol, ok := s.findIPPolicyByEnrollToken(token)
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

	if err := s.ipAllow.Grant(pol.ID, ip.String(), "enrollment-link", ipGrantTTL); err != nil {
		slog.Error("failed to grant ip via enroll link", "policy", pol.ID, "ip", ip, "error", err)
		s.serveErrorPage(w, r, http.StatusInternalServerError, "Enrollment Failed",
			"Failed to record the authorization. Please try again.")
		return
	}
	s.auditLog.Log("enrollment-link", "ip_policy.authorize",
		fmt.Sprintf("Self-enrolled IP %s for ip_policy %q via link (7 days)", ip, pol.ID))
	slog.Info("ip self-enrolled via link", "policy", pol.ID, "ip", ip)

	s.renderStandalonePage(w, http.StatusOK, "ip-authorized", ipAuthorizedPageData{
		Title:   "Access Authorized",
		Heading: "Access Authorized",
		IP:      ip.String(),
		Name:    policyLabel(pol),
	})
}

// setEnrollToken sets (or clears, if token == "") the enrollment token on an IP
// policy and persists the config. Returns ok=false if the policy is unknown.
func (s *Server) setEnrollToken(policyID, token string) (ok bool, err error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	for i := range s.cfg.IPPolicy {
		if s.cfg.IPPolicy[i].ID == policyID {
			s.cfg.IPPolicy[i].EnrollToken = token
			return true, s.cfg.Save(s.configPath)
		}
	}
	return false, nil
}

// handleRotateEnrollToken (POST) generates a new enrollment token for an IP
// policy, invalidating any previous link, and returns the new URL.
func (s *Server) handleRotateEnrollToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token, err := generateEnrollToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	found, saveErr := s.setEnrollToken(id, token)
	if !found {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if saveErr != nil {
		slog.Error("failed to save config", "error", saveErr)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(s.actorName(r), "ip_policy.enroll_token.rotate",
		fmt.Sprintf("Rotated enrollment link for ip_policy %q", id))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": s.enrollURL(token)})
}

// handleDeleteEnrollToken (DELETE) removes an IP policy's enrollment link.
func (s *Server) handleDeleteEnrollToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found, saveErr := s.setEnrollToken(id, "")
	if !found {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if saveErr != nil {
		slog.Error("failed to save config", "error", saveErr)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(s.actorName(r), "ip_policy.enroll_token.remove",
		fmt.Sprintf("Removed enrollment link for ip_policy %q", id))
	w.WriteHeader(http.StatusNoContent)
}
