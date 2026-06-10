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
	if err := sm.CreateSession(w, "Admin (passkey)", "admin"); err != nil {
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

// sessionReq creates a request carrying the session cookie just written to w.
func sessionReq(t *testing.T, w *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			req.AddCookie(c)
			return req
		}
	}
	t.Fatal("session cookie not found")
	return nil
}

// TestSessionManager_CSRFStableAcrossRefresh is the regression test for the bug
// where the sliding-window keepalive re-issued the cookie and invalidated CSRF
// tokens in other open tabs. After RefreshSession the cookie value changes but
// the CSRF token (bound to the stable SID) must NOT.
func TestSessionManager_CSRFStableAcrossRefresh(t *testing.T) {
	sm := NewSessionManager("test-secret-key-for-jwt")

	w1 := httptest.NewRecorder()
	if err := sm.CreateSession(w1, "Name <user@example.com>", "admin"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	req1 := sessionReq(t, w1)
	csrf1 := sm.CSRFToken(req1)
	if csrf1 == "" {
		t.Fatal("expected a CSRF token")
	}

	// Simulate the keepalive re-issuing the cookie.
	w2 := httptest.NewRecorder()
	if err := sm.RefreshSession(w2, req1); err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	req2 := sessionReq(t, w2)

	// The re-issued cookie may differ (new expiry), but the CSRF token must not.
	csrf2 := sm.CSRFToken(req2)
	if csrf1 != csrf2 {
		t.Fatalf("CSRF token changed across refresh: %q -> %q", csrf1, csrf2)
	}
	// And the token from the original page still validates against the new session.
	if !sm.ValidCSRFToken(req2, csrf1) {
		t.Fatal("original CSRF token should still validate after refresh")
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
	sm.CreateSession(w, "Admin (passkey)", "admin")
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
	sm.CreateSession(w, "Admin (passkey)", "admin")
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

func TestSessionManager_AlgorithmConfusion(t *testing.T) {
	sm := NewSessionManager("test-secret")

	// Create a valid session to get a proper cookie value first.
	w := httptest.NewRecorder()
	if err := sm.CreateSession(w, "Admin (passkey)", "admin"); err != nil {
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
