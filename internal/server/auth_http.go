package server

import (
	"encoding/json"
	"html"
	"log/slog"
	"net/http"

	"github.com/jclement/gatecrash/internal/admin"
)

const setupUserID = "admin" // first-boot admin's default ID

func writeChallenge(w http.ResponseWriter, options interface{}, challengeID string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"publicKey": options, "challenge_id": challengeID})
}

func landingForRole(role string) string {
	if role == admin.RoleAdmin {
		return "/"
	}
	return "/passkeys"
}

// ── Login (usernameless / discoverable) ──────────────────────────────────────

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, cid, err := s.webauthn.BeginLogin()
	if err != nil {
		slog.Error("login begin failed", "error", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	writeChallenge(w, options, cid)
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	userID, credID, signCount, err := s.webauthn.FinishLogin(r, r.URL.Query().Get("challenge_id"))
	if err != nil {
		slog.Error("login finish failed", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}
	u := s.users.Get(userID)
	if u == nil {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	s.users.UpdateSignCount(userID, credID, signCount)
	if err := s.sessionMgr.CreateSession(w, u.ID, u.Role); err != nil {
		slog.Error("session create failed", "error", err)
	}
	s.auditLog.Log(u.ID, "auth.login", "Signed in with a passkey")
	writeJSON(w, map[string]string{"status": "ok", "redirect": landingForRole(u.Role)})
}

// ── First-boot admin setup ───────────────────────────────────────────────────

func (s *Server) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	if !s.webauthn.NeedsSetup() {
		http.Error(w, "setup already complete", http.StatusForbidden)
		return
	}
	u := s.users.Get(setupUserID)
	if u == nil {
		if _, err := s.users.Create(setupUserID, admin.RoleAdmin); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		u = s.users.Get(setupUserID)
	}
	options, cid, err := s.webauthn.BeginRegistration(u)
	if err != nil {
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	writeChallenge(w, options, cid)
}

func (s *Server) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	if !s.webauthn.NeedsSetup() {
		http.Error(w, "setup already complete", http.StatusForbidden)
		return
	}
	userID, sc, err := s.webauthn.FinishRegistration(r, r.URL.Query().Get("challenge_id"))
	if err != nil {
		slog.Error("setup finish failed", "error", err)
		http.Error(w, "registration verification failed", http.StatusBadRequest)
		return
	}
	if err := s.users.AddCredential(userID, sc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.sessionMgr.CreateSession(w, userID, admin.RoleAdmin); err != nil {
		slog.Error("session create failed", "error", err)
	}
	s.auditLog.Log(userID, "auth.setup", "Provisioned the first admin")
	writeJSON(w, map[string]string{"status": "ok", "redirect": "/"})
}

// ── Invite-based registration (new users) ────────────────────────────────────

func (s *Server) handleInvitePage(w http.ResponseWriter, r *http.Request) {
	u := s.users.FindByInvite(r.PathValue("token"))
	if u == nil {
		s.serveErrorPage(w, r, http.StatusNotFound, "Invalid Invite",
			"This invite link is not valid. It may have expired or already been used.")
		return
	}
	s.adminH.Render(w, "pages/invite.html", &admin.PageData{
		Title: "Set up your passkey",
		Data:  struct{ UserID, Token string }{UserID: html.EscapeString(u.ID), Token: r.PathValue("token")},
	})
}

func (s *Server) handleInviteBegin(w http.ResponseWriter, r *http.Request) {
	u := s.users.FindByInvite(r.PathValue("token"))
	if u == nil {
		http.Error(w, "invalid invite", http.StatusForbidden)
		return
	}
	options, cid, err := s.webauthn.BeginRegistration(u)
	if err != nil {
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	writeChallenge(w, options, cid)
}

func (s *Server) handleInviteFinish(w http.ResponseWriter, r *http.Request) {
	u := s.users.FindByInvite(r.PathValue("token"))
	if u == nil {
		http.Error(w, "invalid invite", http.StatusForbidden)
		return
	}
	userID, sc, err := s.webauthn.FinishRegistration(r, r.URL.Query().Get("challenge_id"))
	if err != nil || userID != u.ID {
		http.Error(w, "registration verification failed", http.StatusBadRequest)
		return
	}
	if err := s.users.AddCredential(userID, sc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.sessionMgr.CreateSession(w, u.ID, u.Role); err != nil {
		slog.Error("session create failed", "error", err)
	}
	s.auditLog.Log(u.ID, "auth.register", "Registered a passkey via invite")
	writeJSON(w, map[string]string{"status": "ok", "redirect": landingForRole(u.Role)})
}

// ── Add a passkey to your own account ────────────────────────────────────────

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := s.users.Get(s.sessionMgr.UserID(r))
	if u == nil {
		http.Error(w, "unknown user", http.StatusUnauthorized)
		return
	}
	options, cid, err := s.webauthn.BeginRegistration(u)
	if err != nil {
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	writeChallenge(w, options, cid)
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	userID, sc, err := s.webauthn.FinishRegistration(r, r.URL.Query().Get("challenge_id"))
	if err != nil || userID != s.sessionMgr.UserID(r) {
		http.Error(w, "registration verification failed", http.StatusBadRequest)
		return
	}
	if err := s.users.AddCredential(userID, sc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(userID, "auth.passkey.add", "Added a passkey")
	writeJSON(w, map[string]string{"status": "ok"})
}
