package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSessionManager_CreateAndValidate(t *testing.T) {
	sm := NewSessionManager("test-secret-key")

	// Create session
	w := httptest.NewRecorder()
	if err := sm.CreateSession(w); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Extract cookie
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != sessionCookieName {
		t.Fatalf("wrong cookie name: %s", cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Fatal("cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Fatal("cookie should be Secure")
	}

	// Validate session
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)

	if !sm.ValidateSession(req) {
		t.Fatal("session should be valid")
	}
}

func TestSessionManager_InvalidToken(t *testing.T) {
	sm := NewSessionManager("test-secret-key")

	tests := []struct {
		name   string
		cookie *http.Cookie
	}{
		{
			"wrong secret",
			func() *http.Cookie {
				other := NewSessionManager("other-secret")
				w := httptest.NewRecorder()
				other.CreateSession(w)
				return w.Result().Cookies()[0]
			}(),
		},
		{
			"garbage token",
			&http.Cookie{Name: sessionCookieName, Value: "not-a-jwt"},
		},
		{
			"expired token",
			func() *http.Cookie {
				claims := jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					Issuer:    "gatecrash",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte("test-secret-key"))
				return &http.Cookie{Name: sessionCookieName, Value: signed}
			}(),
		},
		{
			"wrong issuer",
			func() *http.Cookie {
				claims := jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "not-gatecrash",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte("test-secret-key"))
				return &http.Cookie{Name: sessionCookieName, Value: signed}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.AddCookie(tt.cookie)
			if sm.ValidateSession(req) {
				t.Fatal("session should be invalid")
			}
		})
	}
}

func TestSessionManager_NoCookie(t *testing.T) {
	sm := NewSessionManager("test-secret-key")
	req := httptest.NewRequest("GET", "/", nil)
	if sm.ValidateSession(req) {
		t.Fatal("session without cookie should be invalid")
	}
}

func TestSessionManager_ClearSession(t *testing.T) {
	sm := NewSessionManager("test-secret-key")

	w := httptest.NewRecorder()
	sm.ClearSession(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge != -1 {
		t.Fatal("cleared cookie should have MaxAge -1")
	}
}

func TestSessionManager_RequireAuth(t *testing.T) {
	sm := NewSessionManager("test-secret-key")

	// Handler that should only be called if authenticated
	handler := sm.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsAuthenticated(r) {
			t.Fatal("should be authenticated in handler")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Without session: should redirect
	t.Run("unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("expected redirect, got %d", w.Code)
		}
	})

	// With session: should pass through
	t.Run("authenticated", func(t *testing.T) {
		// Create session first
		sessionW := httptest.NewRecorder()
		sm.CreateSession(sessionW)
		cookie := sessionW.Result().Cookies()[0]

		req := httptest.NewRequest("GET", "/dashboard", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}
