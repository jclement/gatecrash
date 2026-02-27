package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnHandler handles passkey registration and authentication.
type WebAuthnHandler struct {
	wan     *webauthn.WebAuthn
	store   *PasskeyStore
	session *SessionManager

	// In-memory challenge store with TTL
	mu         sync.Mutex
	challenges map[string]*sessionData
}

type sessionData struct {
	session *webauthn.SessionData
	expires time.Time
}

// webauthnUser implements webauthn.User interface.
type webauthnUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.name }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// NewWebAuthnHandler creates a new WebAuthn handler.
func NewWebAuthnHandler(rpID, rpOrigin string, store *PasskeyStore, session *SessionManager) (*WebAuthnHandler, error) {
	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Gatecrash",
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}

	h := &WebAuthnHandler{
		wan:        wan,
		store:      store,
		session:    session,
		challenges: make(map[string]*sessionData),
	}

	// Cleanup expired challenges every minute
	go h.cleanupLoop()

	return h, nil
}

func (h *WebAuthnHandler) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		now := time.Now()
		for k, v := range h.challenges {
			if now.After(v.expires) {
				delete(h.challenges, k)
			}
		}
		h.mu.Unlock()
	}
}

func (h *WebAuthnHandler) storeChallenge(key string, sd *webauthn.SessionData) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.challenges[key] = &sessionData{
		session: sd,
		expires: time.Now().Add(5 * time.Minute),
	}
}

func (h *WebAuthnHandler) getChallenge(key string) *webauthn.SessionData {
	h.mu.Lock()
	defer h.mu.Unlock()
	sd, ok := h.challenges[key]
	if !ok || time.Now().After(sd.expires) {
		delete(h.challenges, key)
		return nil
	}
	delete(h.challenges, key)
	return sd.session
}

// user builds a webauthnUser from stored credentials.
func (h *WebAuthnHandler) user() *webauthnUser {
	stored := h.store.Credentials()
	creds := make([]webauthn.Credential, len(stored))
	for i, sc := range stored {
		creds[i] = webauthn.Credential{
			ID:              sc.ID,
			PublicKey:       sc.PublicKey,
			AttestationType: sc.AttType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    sc.AAGUID,
				SignCount: sc.SignCount,
			},
		}
	}
	return &webauthnUser{
		id:          []byte("gatecrash-admin"),
		name:        "admin",
		credentials: creds,
	}
}

// HandleRegisterBegin starts passkey registration.
func (h *WebAuthnHandler) HandleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user := h.user()
	options, session, err := h.wan.BeginRegistration(user)
	if err != nil {
		slog.Error("WebAuthn register begin failed", "error", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}

	h.storeChallenge("register", session)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// HandleRegisterFinish completes passkey registration.
func (h *WebAuthnHandler) HandleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	session := h.getChallenge("register")
	if session == nil {
		http.Error(w, "no pending registration", http.StatusBadRequest)
		return
	}

	user := h.user()
	credential, err := h.wan.FinishRegistration(user, *session, r)
	if err != nil {
		slog.Error("WebAuthn register finish failed", "error", err)
		http.Error(w, "registration verification failed", http.StatusBadRequest)
		return
	}

	// Determine transport strings
	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	// Store credential
	sc := StoredCredential{
		ID:        credential.ID,
		PublicKey: credential.PublicKey,
		Name:      "Passkey",
		AAGUID:   credential.Authenticator.AAGUID,
		SignCount: credential.Authenticator.SignCount,
		Transport: transports,
		AttType:   credential.AttestationType,
	}
	if err := h.store.AddCredential(sc); err != nil {
		slog.Error("failed to store credential", "error", err)
		http.Error(w, "failed to store credential", http.StatusInternalServerError)
		return
	}

	// Create session
	if err := h.session.CreateSession(w); err != nil {
		slog.Error("failed to create session", "error", err)
	}

	slog.Info("passkey registered")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleLoginBegin starts passkey authentication.
func (h *WebAuthnHandler) HandleLoginBegin(w http.ResponseWriter, r *http.Request) {
	user := h.user()
	if len(user.credentials) == 0 {
		http.Error(w, "no passkeys registered", http.StatusBadRequest)
		return
	}

	options, session, err := h.wan.BeginLogin(user)
	if err != nil {
		slog.Error("WebAuthn login begin failed", "error", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	h.storeChallenge("login", session)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// HandleLoginFinish completes passkey authentication.
func (h *WebAuthnHandler) HandleLoginFinish(w http.ResponseWriter, r *http.Request) {
	session := h.getChallenge("login")
	if session == nil {
		http.Error(w, "no pending login", http.StatusBadRequest)
		return
	}

	user := h.user()
	credential, err := h.wan.FinishLogin(user, *session, r)
	if err != nil {
		slog.Error("WebAuthn login finish failed", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}

	// Update sign count
	h.store.UpdateSignCount(credential.ID, credential.Authenticator.SignCount)

	// Create session
	if err := h.session.CreateSession(w); err != nil {
		slog.Error("failed to create session", "error", err)
	}

	slog.Info("passkey authenticated")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// NeedsSetup returns true if no passkeys are registered.
func (h *WebAuthnHandler) NeedsSetup() bool {
	return !h.store.IsSetupComplete()
}

// Ensure protocol is imported (used in credential transport types)
var _ = protocol.AuthenticatorTransport("")
