package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jclement/gatecrash/internal/admin"
)

// inviteURL builds the public invite link for a token on the admin host.
func (s *Server) inviteURL(token string) string {
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
	return base + "/invite/" + token
}

func (s *Server) handleUsersPage(w http.ResponseWriter, r *http.Request) {
	s.adminH.Render(w, "pages/users.html", &admin.PageData{
		Title:     "Users",
		Active:    "users",
		UserID:    s.sessionMgr.UserID(r),
		IsAdmin:   true,
		CSRFToken: s.sessionMgr.CSRFToken(r),
	})
}

type userView struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	HasPasskeys bool   `json:"has_passkeys"`
	Passkeys    int    `json:"passkeys"`
	InviteURL   string `json:"invite_url"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	users := s.users.All()
	out := make([]userView, 0, len(users))
	for _, u := range users {
		v := userView{ID: u.ID, Role: u.Role, HasPasskeys: u.HasPasskeys(), Passkeys: len(u.Credentials)}
		if u.InviteActive(now) {
			v.InviteURL = s.inviteURL(u.InviteToken)
		}
		out = append(out, v)
	}
	writeJSON(w, out)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	token, err := s.users.Create(req.ID, req.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "user.create", fmt.Sprintf("Created %s user %q", req.Role, req.ID))
	writeJSON(w, map[string]string{"invite_url": s.inviteURL(token)})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.users.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "user.delete", fmt.Sprintf("Deleted user %q", id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token, err := s.users.Reset(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "user.reset", fmt.Sprintf("Reset user %q (cleared passkeys)", id))
	writeJSON(w, map[string]string{"invite_url": s.inviteURL(token)})
}

func (s *Server) handleSetUserRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := s.users.SetRole(id, req.Role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.sessionMgr.GetActor(r), "user.role", fmt.Sprintf("Set user %q role to %q", id, req.Role))
	w.WriteHeader(http.StatusNoContent)
}
