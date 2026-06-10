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
	Name        string `json:"name"`
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
		v := userView{ID: u.ID, Name: u.Name, Role: u.Role, HasPasskeys: u.HasPasskeys(), Passkeys: len(u.Credentials)}
		if u.InviteActive(now) {
			v.InviteURL = s.inviteURL(u.InviteToken)
		}
		out = append(out, v)
	}
	writeJSON(w, out)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	_, token, err := s.users.Create(req.Name, req.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.actorName(r), "user.create", fmt.Sprintf("Created %s user %q", req.Role, req.Name))
	writeJSON(w, map[string]string{"invite_url": s.inviteURL(token)})
}

func (s *Server) handleRenameUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := s.users.Rename(id, req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.actorName(r), "user.rename", fmt.Sprintf("Renamed user to %q", req.Name))
	w.WriteHeader(http.StatusNoContent)
}

// userName resolves a user id to its display label for readable audit messages.
func (s *Server) userName(id string) string {
	if u := s.users.Get(id); u != nil {
		return u.Name
	}
	return id
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == s.sessionMgr.UserID(r) {
		http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
		return
	}
	name := s.userName(id)
	if err := s.users.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.actorName(r), "user.delete", fmt.Sprintf("Deleted user %q", name))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := s.userName(id)
	token, err := s.users.Reset(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.actorName(r), "user.reset", fmt.Sprintf("Reset user %q (cleared passkeys)", name))
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
	// An admin can't demote themselves — that would strip their own access and is
	// almost always a mistake. Another admin must do it.
	if id == s.sessionMgr.UserID(r) && req.Role != admin.RoleAdmin {
		http.Error(w, "you cannot change your own role", http.StatusBadRequest)
		return
	}
	if err := s.users.SetRole(id, req.Role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLog.Log(s.actorName(r), "user.role", fmt.Sprintf("Set user %q role to %q", s.userName(id), req.Role))
	w.WriteHeader(http.StatusNoContent)
}
