package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/internal/config"
	"github.com/jclement/gatecrash/internal/token"
)

// handleAccessPoliciesPage renders the Access Policies admin page.
func (s *Server) handleAccessPoliciesPage(w http.ResponseWriter, r *http.Request) {
	s.adminH.Render(w, "pages/access-policies.html", &admin.PageData{
		Title:     "Access Policies",
		Active:    "access-policies",
		UserID:    s.sessionMgr.UserID(r),
		IsAdmin:   true,
		CSRFToken: s.sessionMgr.CSRFToken(r),
	})
}

// ── IP policies ──────────────────────────────────────────────────────────────

type ipPolicyView struct {
	ID        string           `json:"id"`
	Ranges    []config.IPRange `json:"ranges"`
	EnrollURL string           `json:"enroll_url"`
}

func (s *Server) handleListIPPolicies(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	out := make([]ipPolicyView, 0, len(s.cfg.IPPolicy))
	for _, p := range s.cfg.IPPolicy {
		out = append(out, ipPolicyView{ID: p.ID, Ranges: p.Ranges, EnrollURL: s.enrollURLLocked(p.EnrollToken)})
	}
	s.cfgMu.RUnlock()
	writeJSON(w, out)
}

func (s *Server) handleSaveIPPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string           `json:"id"`
		Ranges []config.IPRange `json:"ranges"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if !tunnelIDPattern.MatchString(req.ID) {
		http.Error(w, "invalid id: lowercase alphanumeric with hyphens", http.StatusBadRequest)
		return
	}
	for _, rg := range req.Ranges {
		if _, _, err := net.ParseCIDR(rg.CIDR); err != nil && net.ParseIP(rg.CIDR) == nil {
			http.Error(w, fmt.Sprintf("invalid range %q: must be an IP or CIDR", rg.CIDR), http.StatusBadRequest)
			return
		}
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	updated := false
	for i := range s.cfg.IPPolicy {
		if s.cfg.IPPolicy[i].ID == req.ID {
			s.cfg.IPPolicy[i].Ranges = req.Ranges // preserve EnrollToken
			updated = true
			break
		}
	}
	if !updated {
		s.cfg.IPPolicy = append(s.cfg.IPPolicy, config.IPPolicy{ID: req.ID, Ranges: req.Ranges})
	}
	if err := s.saveAndReloadPoliciesLocked(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "ip_policy.save", fmt.Sprintf("Saved ip_policy %q", req.ID))
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteIPPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	for _, t := range s.cfg.Tunnel {
		if t.IPPolicy == id {
			http.Error(w, fmt.Sprintf("ip_policy %q is in use by tunnel %q", id, t.ID), http.StatusConflict)
			return
		}
	}
	kept := s.cfg.IPPolicy[:0]
	found := false
	for _, p := range s.cfg.IPPolicy {
		if p.ID == id {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.cfg.IPPolicy = kept
	if err := s.saveAndReloadPoliciesLocked(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "ip_policy.delete", fmt.Sprintf("Deleted ip_policy %q", id))
	w.WriteHeader(http.StatusNoContent)
}

// ── Auth policies ────────────────────────────────────────────────────────────

type authPolicyView struct {
	ID          string   `json:"id"`
	Users       []string `json:"users"`
	Header      string   `json:"header"`
	Username    string   `json:"username"`
	HasPassword bool     `json:"has_password"`
}

func (s *Server) handleListAuthPolicies(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	out := make([]authPolicyView, 0, len(s.cfg.AuthPolicy))
	for _, p := range s.cfg.AuthPolicy {
		out = append(out, authPolicyView{
			ID: p.ID, Users: p.Users, Header: p.Header, Username: p.Username,
			HasPassword: p.PasswordHash != "",
		})
	}
	s.cfgMu.RUnlock()
	writeJSON(w, out)
}

func (s *Server) handleSaveAuthPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string   `json:"id"`
		Users    []string `json:"users"`
		Header   string   `json:"header"`
		Username string   `json:"username"`
		Password string   `json:"password"` // plaintext; empty on edit keeps existing
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if !tunnelIDPattern.MatchString(req.ID) {
		http.Error(w, "invalid id: lowercase alphanumeric with hyphens", http.StatusBadRequest)
		return
	}

	var newHash string
	if req.Password != "" {
		h, err := token.HashSecret(req.Password)
		if err != nil {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		newHash = h
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	pol := config.AuthPolicy{ID: req.ID, Users: req.Users, Header: req.Header, Username: req.Username}
	updated := false
	for i := range s.cfg.AuthPolicy {
		if s.cfg.AuthPolicy[i].ID == req.ID {
			if newHash == "" {
				pol.PasswordHash = s.cfg.AuthPolicy[i].PasswordHash // keep existing
			} else {
				pol.PasswordHash = newHash
			}
			s.cfg.AuthPolicy[i] = pol
			updated = true
			break
		}
	}
	if !updated {
		pol.PasswordHash = newHash
		s.cfg.AuthPolicy = append(s.cfg.AuthPolicy, pol)
	}
	if err := s.saveAndReloadPoliciesLocked(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "auth_policy.save", fmt.Sprintf("Saved auth_policy %q", req.ID))
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteAuthPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	for _, t := range s.cfg.Tunnel {
		if t.AuthPolicy == id {
			http.Error(w, fmt.Sprintf("auth_policy %q is in use by tunnel %q", id, t.ID), http.StatusConflict)
			return
		}
	}
	kept := s.cfg.AuthPolicy[:0]
	found := false
	for _, p := range s.cfg.AuthPolicy {
		if p.ID == id {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.cfg.AuthPolicy = kept
	if err := s.saveAndReloadPoliciesLocked(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "auth_policy.delete", fmt.Sprintf("Deleted auth_policy %q", id))
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// saveAndReloadPoliciesLocked validates, persists, and applies the current
// config's access policies. Caller must hold s.cfgMu.
func (s *Server) saveAndReloadPoliciesLocked() error {
	if err := s.cfg.Validate(); err != nil {
		return err
	}
	if err := s.cfg.Save(s.configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	s.registry.SetPolicies(policiesFromConfig(s.cfg))
	return nil
}

// enrollURLLocked builds the enroll link without taking s.cfgMu (caller holds it).
func (s *Server) enrollURLLocked(tokenStr string) string {
	if tokenStr == "" || s.cfg.Server.AdminHost == "" {
		return ""
	}
	base := "https://" + s.cfg.Server.AdminHost
	if s.cfg.Server.HTTPSPort != 443 {
		base = fmt.Sprintf("https://%s:%d", s.cfg.Server.AdminHost, s.cfg.Server.HTTPSPort)
	}
	return base + "/enroll/" + tokenStr
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
