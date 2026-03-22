package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestSessionManager_CreateAndValidate(t *testing.T) {
	sm := NewSessionManager("test-secret-key-for-jwt")

	w := httptest.NewRecorder()
	if err := sm.CreateSession(w); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not found")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(sessionCookie)
	if !sm.ValidateSession(req) {
		t.Fatal("session should be valid")
	}
}

func TestSessionManager_InvalidSession(t *testing.T) {
	sm := NewSessionManager("test-secret")

	// No cookie
	req := httptest.NewRequest("GET", "/", nil)
	if sm.ValidateSession(req) {
		t.Fatal("should not validate without cookie")
	}

	// Bad cookie value
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "garbage"})
	if sm.ValidateSession(req2) {
		t.Fatal("should not validate with bad cookie")
	}

	// Wrong secret
	sm2 := NewSessionManager("different-secret")
	w := httptest.NewRecorder()
	sm.CreateSession(w)
	cookie := w.Result().Cookies()[0]

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.AddCookie(cookie)
	if sm2.ValidateSession(req3) {
		t.Fatal("should not validate with different secret")
	}
}

func TestSessionManager_ClearSession(t *testing.T) {
	sm := NewSessionManager("test-secret")

	w := httptest.NewRecorder()
	sm.ClearSession(w)

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			if c.MaxAge != -1 {
				t.Fatalf("expected MaxAge -1, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Fatal("clear should set cookie with MaxAge -1")
	}
}

func TestSessionManager_CSRFToken(t *testing.T) {
	sm := NewSessionManager("test-secret")

	w := httptest.NewRecorder()
	sm.CreateSession(w)
	cookie := w.Result().Cookies()[0]

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)

	token := sm.CSRFToken(req)
	if token == "" {
		t.Fatal("CSRF token should not be empty")
	}

	// Deterministic
	if sm.CSRFToken(req) != token {
		t.Fatal("CSRF token should be deterministic")
	}

	// Valid
	if !sm.ValidCSRFToken(req, token) {
		t.Fatal("CSRF token should be valid")
	}

	// Invalid
	if sm.ValidCSRFToken(req, "wrong-token") {
		t.Fatal("wrong CSRF token should not validate")
	}
	if sm.ValidCSRFToken(req, "") {
		t.Fatal("empty CSRF token should not validate")
	}
}

func TestSessionManager_CSRFToken_NoCookie(t *testing.T) {
	sm := NewSessionManager("test-secret")
	req := httptest.NewRequest("GET", "/", nil)

	if sm.CSRFToken(req) != "" {
		t.Fatal("CSRF token should be empty without session")
	}
}

func TestSessionManager_RequireAuth(t *testing.T) {
	sm := NewSessionManager("test-secret")

	var authenticated bool
	handler := sm.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated = IsAuthenticated(r)
		w.WriteHeader(200)
	}))

	// Without session — redirect
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/dashboard", nil)
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", w.Code)
	}

	// With valid session — pass through
	wCreate := httptest.NewRecorder()
	sm.CreateSession(wCreate)
	cookie := wCreate.Result().Cookies()[0]

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/dashboard", nil)
	req2.AddCookie(cookie)
	handler.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
	if !authenticated {
		t.Fatal("handler should see authenticated context")
	}
}

func TestIsAuthenticated_NoContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if IsAuthenticated(req) {
		t.Fatal("should not be authenticated without context")
	}
}

func TestSessionManager_AlgorithmConfusion(t *testing.T) {
	sm := NewSessionManager("test-secret")

	// Create a valid session to get a proper cookie value first.
	w := httptest.NewRecorder()
	if err := sm.CreateSession(w); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Craft a token signed with the "none" algorithm — should be rejected.
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
		Issuer: "gatecrash",
	})
	signed, err := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("signing with none: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signed})
	if sm.ValidateSession(req) {
		t.Fatal("session with 'none' algorithm should be rejected")
	}
}
