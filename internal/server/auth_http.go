package server

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jclement/gatecrash/internal/admin"
)

func writeChallenge(w http.ResponseWriter, options interface{}, challengeID string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"publicKey": options, "challenge_id": challengeID})
}

// passkeyName returns the cleaned, length-bounded display name supplied with a
// registration (via the ?name= query), defaulting to "Passkey" when blank. It is
// shown in the UI, so control characters are stripped and the length is capped.
func passkeyName(r *http.Request) string {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	name = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f { // drop control characters
			return -1
		}
		return c
	}, name)
	if runes := []rune(name); len(runes) > 48 {
		name = strings.TrimSpace(string(runes[:48]))
	}
	if name == "" {
		return "Passkey"
	}
	return name
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
	s.auditLog.Log(u.Name, "auth.login", "Signed in with a passkey")
	writeJSON(w, map[string]string{"status": "ok", "redirect": landingForRole(u.Role)})
}

// ── Invite-based registration (new users + first-admin bootstrap) ────────────

func (s *Server) handleInvitePage(w http.ResponseWriter, r *http.Request) {
	u := s.users.FindByInvite(r.PathValue("token"))
	if u == nil {
		s.serveErrorPage(w, r, http.StatusNotFound, "Invalid Invite",
			"This invite link is not valid. It may have expired or already been used.")
		return
	}
	s.adminH.Render(w, "pages/invite.html", &admin.PageData{
		Title: "Set up your passkey",
		Data:  struct{ Name, Token string }{Name: html.EscapeString(u.Name), Token: r.PathValue("token")},
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
	sc.Name = passkeyName(r)
	if err := s.users.AddCredential(userID, sc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// If this completed first-boot bootstrap, retire the on-disk invite file.
	s.clearBootstrapInviteFile()
	if err := s.sessionMgr.CreateSession(w, u.ID, u.Role); err != nil {
		slog.Error("session create failed", "error", err)
	}
	s.auditLog.Log(u.Name, "auth.register", "Registered a passkey via invite")
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
	sc.Name = passkeyName(r)
	if err := s.users.AddCredential(userID, sc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditLog.Log(s.actorName(r), "auth.passkey.add", fmt.Sprintf("Added passkey %q", sc.Name))
	writeJSON(w, map[string]string{"status": "ok"})
}
