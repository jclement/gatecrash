package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	sessionCookieName = "gatecrash_session"
	sessionDuration   = 24 * time.Hour
)

// SessionManager handles JWT-based sessions.
type SessionManager struct {
	secret []byte
}

// NewSessionManager creates a new session manager.
func NewSessionManager(secret string) *SessionManager {
	return &SessionManager{secret: []byte(secret)}
}

// sessionClaims extends RegisteredClaims with an actor identity for audit logging.
type sessionClaims struct {
	jwt.RegisteredClaims
	Actor string `json:"actor,omitempty"`
}

// CreateSession sets a session cookie on the response.
// The actor string identifies who is logging in (e.g. "Admin (passkey)" or "Name <email>").
func (sm *SessionManager) CreateSession(w http.ResponseWriter, actor string) error {
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "gatecrash",
		},
		Actor: actor,
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

// GetActor returns the actor identity from the session JWT.
// Returns "Admin (passkey)" as default for sessions without an actor field.
func (sm *SessionManager) GetActor(r *http.Request) string {
	claims, ok := sm.parseSession(r)
	if !ok || claims.Actor == "" {
		return "Admin (passkey)"
	}
	return claims.Actor
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

// CSRFToken generates a CSRF token derived from the session cookie.
// Returns empty string if there is no valid session.
func (sm *SessionManager) CSRFToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte("csrf:" + cookie.Value))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidCSRFToken checks that a submitted CSRF token matches the session.
func (sm *SessionManager) ValidCSRFToken(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	return hmac.Equal([]byte(sm.CSRFToken(r)), []byte(token))
}
