package admin

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnHandler runs passkey registration and (usernameless) login ceremonies
// against the user directory. It is transport-agnostic: callers handle HTTP and
// persistence.
type WebAuthnHandler struct {
	wan   *webauthn.WebAuthn
	users *UserStore

	mu         sync.Mutex
	challenges map[string]*challenge
}

type challenge struct {
	session *webauthn.SessionData
	userID  string // registration target; empty for login
	expires time.Time
}

// webauthnUser adapts a directory User to the webauthn.User interface.
type webauthnUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.name }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func userToWebAuthn(u *User) *webauthnUser {
	creds := make([]webauthn.Credential, len(u.Credentials))
	for i, sc := range u.Credentials {
		creds[i] = webauthn.Credential{
			ID:              sc.ID,
			PublicKey:       sc.PublicKey,
			AttestationType: sc.AttType,
			Authenticator:   webauthn.Authenticator{AAGUID: sc.AAGUID, SignCount: sc.SignCount},
			Flags:           webauthn.CredentialFlags{BackupEligible: sc.BackupEligible, BackupState: sc.BackupState},
		}
	}
	return &webauthnUser{id: []byte(u.ID), name: u.ID, credentials: creds}
}

// NewWebAuthnHandler creates a WebAuthn handler bound to the user directory.
func NewWebAuthnHandler(rpID, rpOrigin string, users *UserStore) (*WebAuthnHandler, error) {
	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Gatecrash",
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}
	h := &WebAuthnHandler{wan: wan, users: users, challenges: make(map[string]*challenge)}
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

func (h *WebAuthnHandler) store(sd *webauthn.SessionData, userID string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	key := base64.RawURLEncoding.EncodeToString(b)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.challenges[key] = &challenge{session: sd, userID: userID, expires: time.Now().Add(5 * time.Minute)}
	return key
}

func (h *WebAuthnHandler) take(key string) *challenge {
	if key == "" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.challenges[key]
	if !ok || time.Now().After(c.expires) {
		delete(h.challenges, key)
		return nil
	}
	delete(h.challenges, key)
	return c
}

// BeginRegistration starts a passkey registration for the target user, requiring
// a discoverable (resident) credential so usernameless login works.
func (h *WebAuthnHandler) BeginRegistration(u *User) (creation interface{}, challengeID string, err error) {
	options, session, err := h.wan.BeginRegistration(
		userToWebAuthn(u),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, "", err
	}
	key := h.store(session, u.ID)
	if key == "" {
		return nil, "", fmt.Errorf("failed to store challenge")
	}
	return options.Response, key, nil
}

// FinishRegistration verifies the registration response and returns the target
// user ID and the new credential. The caller persists it.
func (h *WebAuthnHandler) FinishRegistration(r *http.Request, challengeID string) (userID string, sc StoredCredential, err error) {
	c := h.take(challengeID)
	if c == nil || c.userID == "" {
		return "", StoredCredential{}, fmt.Errorf("no pending registration")
	}
	u := h.users.Get(c.userID)
	if u == nil {
		return "", StoredCredential{}, fmt.Errorf("unknown user")
	}
	cred, err := h.wan.FinishRegistration(userToWebAuthn(u), *c.session, r)
	if err != nil {
		return "", StoredCredential{}, err
	}
	var transports []string
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	return c.userID, StoredCredential{
		ID:             cred.ID,
		PublicKey:      cred.PublicKey,
		Name:           "Passkey",
		AAGUID:         cred.Authenticator.AAGUID,
		SignCount:      cred.Authenticator.SignCount,
		Transport:      transports,
		AttType:        cred.AttestationType,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		CreatedAt:      time.Now(),
		LastUsedAt:     time.Now(),
	}, nil
}

// BeginLogin starts a usernameless (discoverable) login.
func (h *WebAuthnHandler) BeginLogin() (assertion interface{}, challengeID string, err error) {
	options, session, err := h.wan.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	key := h.store(session, "")
	if key == "" {
		return nil, "", fmt.Errorf("failed to store challenge")
	}
	return options.Response, key, nil
}

// FinishLogin verifies a discoverable login, resolving and returning the
// authenticated user ID, the credential used, and its new sign count.
func (h *WebAuthnHandler) FinishLogin(r *http.Request, challengeID string) (userID string, credID []byte, signCount uint32, err error) {
	c := h.take(challengeID)
	if c == nil {
		return "", nil, 0, fmt.Errorf("no pending login")
	}
	var resolved *User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u := h.users.Get(string(userHandle))
		if u == nil {
			return nil, fmt.Errorf("unknown user")
		}
		resolved = u
		return userToWebAuthn(u), nil
	}
	cred, err := h.wan.FinishDiscoverableLogin(handler, *c.session, r)
	if err != nil {
		return "", nil, 0, err
	}
	if resolved == nil {
		return "", nil, 0, fmt.Errorf("user not resolved")
	}
	return resolved.ID, cred.ID, cred.Authenticator.SignCount, nil
}

// NeedsSetup reports whether first-boot admin provisioning is required.
func (h *WebAuthnHandler) NeedsSetup() bool { return h.users.NeedsSetup() }
