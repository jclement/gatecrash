package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type sessionContextKey string

const (
	sessionCookieName             = "gatecrash_session"
	sessionDuration               = 24 * time.Hour
	ctxKeyAuthenticated sessionContextKey = "authenticated"
)

// SessionManager handles JWT-based sessions.
type SessionManager struct {
	secret []byte
}

// NewSessionManager creates a new session manager.
func NewSessionManager(secret string) *SessionManager {
	return &SessionManager{secret: []byte(secret)}
}

// CreateSession sets a session cookie on the response.
func (sm *SessionManager) CreateSession(w http.ResponseWriter) error {
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionDuration)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "gatecrash",
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
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return sm.secret, nil
	})
	if err != nil {
		return false
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return false
	}

	if claims.Issuer != "gatecrash" {
		return false
	}

	return true
}

// RequireAuth is middleware that enforces authentication.
func (sm *SessionManager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sm.ValidateSession(r) {
			ctx := context.WithValue(r.Context(), ctxKeyAuthenticated, true)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

// IsAuthenticated checks if the request context has been authenticated.
func IsAuthenticated(r *http.Request) bool {
	auth, _ := r.Context().Value(ctxKeyAuthenticated).(bool)
	return auth
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
