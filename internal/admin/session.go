package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DeriveKey derives a purpose-specific key from a master secret using HMAC-SHA256.
func DeriveKey(master, purpose string) []byte {
	mac := hmac.New(sha256.New, []byte(master))
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

const (
	sessionCookieName = "gatecrash_session"
	sessionDuration   = 24 * time.Hour
)

// SessionManager handles JWT-based sessions.
type SessionManager struct {
	secret []byte
}

// NewSessionManager creates a new session manager with a purpose-derived key.
func NewSessionManager(secret string) *SessionManager {
	return &SessionManager{secret: DeriveKey(secret, "admin-session")}
}

// sessionClaims extends RegisteredClaims with an actor identity for audit logging
// and a stable per-login session id. The CSRF token binds to the SID (not the
// signed JWT) so it survives session-cookie re-issues (the sliding-window
// keepalive), which would otherwise invalidate CSRF tokens in other open tabs.
type sessionClaims struct {
	jwt.RegisteredClaims
	Actor string `json:"actor,omitempty"` // user ID
	Role  string `json:"role,omitempty"`  // "admin" | "user"
	SID   string `json:"sid,omitempty"`
}

func newSID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// issue signs and sets a session cookie carrying the user, role, and stable SID.
func (sm *SessionManager) issue(w http.ResponseWriter, userID, role, sid string) error {
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "gatecrash",
		},
		Actor: userID,
		Role:  role,
		SID:   sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sm.secret)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})

	return nil
}

// CreateSession starts a new session (fresh SID) for a login as the given user.
func (sm *SessionManager) CreateSession(w http.ResponseWriter, userID, role string) error {
	return sm.issue(w, userID, role, newSID())
}

// RefreshSession re-issues the current session with a bumped expiry, PRESERVING
// its user, role, and SID. Used by the sliding-window keepalive so the CSRF
// token (bound to the SID) does not change underneath other open tabs.
func (sm *SessionManager) RefreshSession(w http.ResponseWriter, r *http.Request) error {
	claims, ok := sm.parseSession(r)
	if !ok {
		return fmt.Errorf("no valid session")
	}
	return sm.issue(w, claims.Actor, claims.Role, claims.SID)
}

// ClearSession removes the session cookie.
func (sm *SessionManager) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ValidateSession checks if the request has a valid session.
func (sm *SessionManager) ValidateSession(r *http.Request) bool {
	_, ok := sm.parseSession(r)
	return ok
}

// GetActor returns the user ID from the session JWT (for the audit log).
func (sm *SessionManager) GetActor(r *http.Request) string {
	claims, ok := sm.parseSession(r)
	if !ok {
		return "unknown"
	}
	return actorOf(claims)
}

// UserID returns the logged-in user's ID, or "" if no valid session.
func (sm *SessionManager) UserID(r *http.Request) string {
	claims, ok := sm.parseSession(r)
	if !ok {
		return ""
	}
	return claims.Actor
}

// Role returns the logged-in user's role, or "" if no valid session.
func (sm *SessionManager) Role(r *http.Request) string {
	claims, ok := sm.parseSession(r)
	if !ok {
		return ""
	}
	return claims.Role
}

// IsAdmin reports whether the request has a valid admin session.
func (sm *SessionManager) IsAdmin(r *http.Request) bool {
	return sm.Role(r) == RoleAdmin
}

func actorOf(c *sessionClaims) string {
	if c.Actor == "" {
		return "unknown"
	}
	return c.Actor
}

// parseSession extracts and validates session claims from the request cookie.
func (sm *SessionManager) parseSession(r *http.Request) (*sessionClaims, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return sm.secret, nil
	})
	if err != nil {
		return nil, false
	}

	claims, ok := token.Claims.(*sessionClaims)
	if !ok || !token.Valid {
		return nil, false
	}

	if claims.Issuer != "gatecrash" {
		return nil, false
	}

	return claims, true
}

// CSRFToken generates a CSRF token bound to the session's stable identity, not
// the (frequently re-issued) signed cookie value. New sessions bind to the SID;
// legacy sessions without a SID fall back to the actor. Either way the token is
// stable across keepalive re-issues, so it stays valid across open tabs.
// Returns empty string if there is no valid session.
func (sm *SessionManager) CSRFToken(r *http.Request) string {
	claims, ok := sm.parseSession(r)
	if !ok {
		return ""
	}
	key := claims.SID
	if key == "" {
		key = "actor:" + actorOf(claims)
	}
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte("csrf:" + key))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidCSRFToken checks that a submitted CSRF token matches the session.
func (sm *SessionManager) ValidCSRFToken(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	return hmac.Equal([]byte(sm.CSRFToken(r)), []byte(token))
}
