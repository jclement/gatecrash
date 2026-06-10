package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/internal/config"
	"github.com/jclement/gatecrash/internal/token"
)

// authTestServer builds a Server with the auth components wired together (user
// store, session managers, rate limiters) for exercising the enforcement and
// handoff paths end to end.
func authTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	users, err := admin.NewUserStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("user store: %v", err)
	}
	auditLog, _ := admin.NewAuditLog(filepath.Join(dir, "audit.json"))
	sm := admin.NewSessionManager("test-secret")
	sm.SetEpochSource(users.Epoch)
	ts := admin.NewTunnelSession("test-secret")
	ts.SetEpochSource(users.Epoch)
	wa, err := admin.NewWebAuthnHandler("admin.example.com", "https://admin.example.com", users)
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}

	s := &Server{
		cfg:                   &config.Config{Server: config.ServerConfig{AdminHost: "admin.example.com", HTTPSPort: 443}},
		configPath:            filepath.Join(dir, "gatecrash.toml"),
		registry:              NewRegistry(),
		sse:                   NewSSEBroadcaster(),
		users:                 users,
		sessionMgr:            sm,
		tunnelSession:         ts,
		webauthn:              wa,
		auditLog:              auditLog,
		pendingTunnelAuth:     make(map[string]*pendingTunnelAuthResult),
		tunnelAuthLimiter:     newIPRateLimiter(100, time.Minute),
		bcryptSem:             make(chan struct{}, 2),
		sshAuthAcquireTimeout: 2 * time.Second,
	}
	return s
}

// addUser creates a user directly in the store and returns its id.
func addUser(t *testing.T, s *Server, name, role string) string {
	t.Helper()
	id, _, err := s.users.Create(name, role)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

// ── enforceAuthPolicy ────────────────────────────────────────────────────────

func TestEnforceAuthPolicy_ServiceSecret(t *testing.T) {
	s := authTestServer(t)
	plain, hash, _ := token.GenerateSecret()
	pol := newAuthPolicyState(config.AuthPolicy{ID: "svc", SecretHash: hash})

	// Correct secret (any username) → allowed, identity injected as the service principal.
	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r.SetBasicAuth("anything", plain)
	w := httptest.NewRecorder()
	if !s.enforceAuthPolicy(w, r, "app.example.com", pol) {
		t.Fatal("correct service secret should be allowed")
	}
	if got := r.Header.Get("x-Gatecrash-User"); got != ServiceAuthUsername {
		t.Fatalf("expected identity header %q, got %q", ServiceAuthUsername, got)
	}
	if got := r.Header.Get("X-Gatecrash-Role"); got != "service" {
		t.Fatalf("expected role 'service', got %q", got)
	}

	// Wrong secret on a secret-only policy → 401 challenge.
	r2 := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r2.SetBasicAuth("anything", "wrong")
	w2 := httptest.NewRecorder()
	if s.enforceAuthPolicy(w2, r2, "app.example.com", pol) {
		t.Fatal("wrong secret must not be allowed")
	}
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 challenge, got %d", w2.Code)
	}
}

func TestEnforceAuthPolicy_UserAllowedAndDenied(t *testing.T) {
	s := authTestServer(t)
	alice := addUser(t, s, "Alice", admin.RoleUser)
	bob := addUser(t, s, "Bob", admin.RoleUser)
	pol := newAuthPolicyState(config.AuthPolicy{ID: "staff", Users: []string{alice}})
	host := "app.example.com"

	// Helper: build a request carrying a tunnel session for the given user.
	withTunnelSession := func(uid, role string) *http.Request {
		rec := httptest.NewRecorder()
		if err := s.tunnelSession.CreateSession(rec, host, uid, role); err != nil {
			t.Fatalf("create tunnel session: %v", err)
		}
		r := httptest.NewRequest("GET", "https://"+host+"/", nil)
		for _, c := range rec.Result().Cookies() {
			r.AddCookie(c)
		}
		return r
	}

	// Alice is in the policy → allowed, identity injected.
	r := withTunnelSession(alice, admin.RoleUser)
	w := httptest.NewRecorder()
	if !s.enforceAuthPolicy(w, r, host, pol) {
		t.Fatal("alice should be allowed")
	}
	if got := r.Header.Get("x-Gatecrash-User"); got != "Alice" {
		t.Fatalf("expected injected name 'Alice', got %q", got)
	}
	if got := r.Header.Get("X-Gatecrash-Id"); got != alice {
		t.Fatalf("expected injected id %q, got %q", alice, got)
	}

	// Bob has a valid session but is NOT in the policy → 403.
	r2 := withTunnelSession(bob, admin.RoleUser)
	w2 := httptest.NewRecorder()
	if s.enforceAuthPolicy(w2, r2, host, pol) {
		t.Fatal("bob is not in the policy and must be denied")
	}
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w2.Code)
	}

	// No session → redirected into the cross-host login handoff.
	r3 := httptest.NewRequest("GET", "https://"+host+"/", nil)
	w3 := httptest.NewRecorder()
	if s.enforceAuthPolicy(w3, r3, host, pol) {
		t.Fatal("anonymous request must not be allowed")
	}
	if w3.Code != http.StatusFound {
		t.Fatalf("expected 302 login redirect, got %d", w3.Code)
	}
	if loc := w3.Header().Get("Location"); !strings.Contains(loc, "admin.example.com/tunnel-login") {
		t.Fatalf("expected redirect to admin tunnel-login, got %q", loc)
	}
}

func TestEnforceAuthPolicy_StripsSpoofedHeaders(t *testing.T) {
	s := authTestServer(t)
	plain, hash, _ := token.GenerateSecret()
	pol := newAuthPolicyState(config.AuthPolicy{ID: "svc", SecretHash: hash})

	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r.Header.Set("X-Gatecrash-Id", "u_attacker")
	r.Header.Set("X-Gatecrash-Role", "admin")
	r.SetBasicAuth("svc", plain)
	w := httptest.NewRecorder()
	if !s.enforceAuthPolicy(w, r, "app.example.com", pol) {
		t.Fatal("valid secret should be allowed")
	}
	// The spoofed admin role/id must have been overwritten by the server's values.
	if r.Header.Get("X-Gatecrash-Role") == "admin" || r.Header.Get("X-Gatecrash-Id") == "u_attacker" {
		t.Fatal("spoofed identity headers were not overwritten")
	}
}

// ── CSRF middleware ──────────────────────────────────────────────────────────

func TestRequireCSRF(t *testing.T) {
	s := authTestServer(t)
	uid := addUser(t, s, "Alice", admin.RoleAdmin)

	// Establish a session and capture its cookie + CSRF token.
	rec := httptest.NewRecorder()
	if err := s.sessionMgr.CreateSession(rec, uid, admin.RoleAdmin); err != nil {
		t.Fatalf("create session: %v", err)
	}
	cookies := rec.Result().Cookies()
	authedReq := func() *http.Request {
		r := httptest.NewRequest("POST", "/api/x", nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		return r
	}
	csrf := s.sessionMgr.CSRFToken(authedReq())
	if csrf == "" {
		t.Fatal("expected a CSRF token")
	}

	hit := false
	h := s.requireCSRF(func(w http.ResponseWriter, r *http.Request) { hit = true; w.WriteHeader(200) })

	// Valid token → passes.
	r := authedReq()
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	h(w, r)
	if !hit || w.Code != 200 {
		t.Fatalf("valid CSRF should pass, got %d (hit=%v)", w.Code, hit)
	}

	// Missing token → 403.
	hit = false
	w = httptest.NewRecorder()
	h(w, authedReq())
	if hit || w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF should be 403, got %d (hit=%v)", w.Code, hit)
	}

	// Forged token → 403.
	hit = false
	r = authedReq()
	r.Header.Set("X-CSRF-Token", csrf+"tampered")
	w = httptest.NewRecorder()
	h(w, r)
	if hit || w.Code != http.StatusForbidden {
		t.Fatalf("forged CSRF should be 403, got %d (hit=%v)", w.Code, hit)
	}

	// No session at all → 401 (before CSRF is even considered).
	hit = false
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("POST", "/api/x", nil))
	if hit || w.Code != http.StatusUnauthorized {
		t.Fatalf("no session should be 401, got %d (hit=%v)", w.Code, hit)
	}
}

func TestRequireAdminCSRF_NonAdminForbidden(t *testing.T) {
	s := authTestServer(t)
	uid := addUser(t, s, "Eve", admin.RoleUser) // not an admin

	rec := httptest.NewRecorder()
	s.sessionMgr.CreateSession(rec, uid, admin.RoleUser)
	cookies := rec.Result().Cookies()
	r := httptest.NewRequest("POST", "/api/x", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	r.Header.Set("X-CSRF-Token", s.sessionMgr.CSRFToken(r))

	hit := false
	h := s.requireAdminCSRF(func(w http.ResponseWriter, r *http.Request) { hit = true })
	w := httptest.NewRecorder()
	h(w, r)
	if hit || w.Code != http.StatusForbidden {
		t.Fatalf("non-admin should be 403, got %d (hit=%v)", w.Code, hit)
	}
}

// ── Cross-host tunnel-login handoff ──────────────────────────────────────────

func TestTunnelLoginHandoff(t *testing.T) {
	s := authTestServer(t)
	host := "app.example.com"
	s.registry.Register(newTunnelState(TunnelSpec{ID: "web", Hostnames: []string{host}}))
	uid := addUser(t, s, "Alice", admin.RoleUser)

	// Admin-host session for the user initiating the handoff.
	rec := httptest.NewRecorder()
	s.sessionMgr.CreateSession(rec, uid, admin.RoleUser)
	cookies := rec.Result().Cookies()

	// Mint: GET /tunnel-login?hostname=...&return=... → 302 to the complete URL with a one-time token.
	mintReq := httptest.NewRequest("GET", "/tunnel-login?hostname="+host+"&return="+url.QueryEscape("https://"+host+"/dashboard"), nil)
	for _, c := range cookies {
		mintReq.AddCookie(c)
	}
	mintW := httptest.NewRecorder()
	s.handleTunnelLogin(mintW, mintReq)
	if mintW.Code != http.StatusFound {
		t.Fatalf("mint expected 302, got %d", mintW.Code)
	}
	loc := mintW.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, "https://"+host+"/.gatecrash/auth/complete") {
		t.Fatalf("unexpected complete URL: %q", loc)
	}
	oneTimeToken := u.Query().Get("token")
	if oneTimeToken == "" {
		t.Fatal("expected a one-time token in the complete URL")
	}

	// Consume: the matching hostname sets a tunnel session and redirects to the return URL.
	consumeReq := httptest.NewRequest("GET", "https://"+host+"/.gatecrash/auth/complete?token="+oneTimeToken, nil)
	consumeW := httptest.NewRecorder()
	s.handleTunnelLoginComplete(consumeW, consumeReq, host)
	if consumeW.Code != http.StatusFound {
		t.Fatalf("consume expected 302, got %d (%s)", consumeW.Code, consumeW.Body.String())
	}
	if consumeW.Header().Get("Location") != "https://"+host+"/dashboard" {
		t.Fatalf("expected redirect to return URL, got %q", consumeW.Header().Get("Location"))
	}
	var gotTunnelCookie bool
	for _, c := range consumeW.Result().Cookies() {
		if c.Name == "gatecrash_tunnel" && c.Value != "" {
			gotTunnelCookie = true
		}
	}
	if !gotTunnelCookie {
		t.Fatal("expected a tunnel session cookie to be set")
	}

	// The token is single-use: replaying it fails.
	replayW := httptest.NewRecorder()
	s.handleTunnelLoginComplete(replayW, httptest.NewRequest("GET", "https://"+host+"/.gatecrash/auth/complete?token="+oneTimeToken, nil), host)
	if replayW.Code == http.StatusFound {
		t.Fatal("a consumed token must not be reusable")
	}
}

func TestTunnelLoginComplete_HostnameMismatch(t *testing.T) {
	s := authTestServer(t)
	host := "app.example.com"
	s.registry.Register(newTunnelState(TunnelSpec{ID: "web", Hostnames: []string{host}}))
	uid := addUser(t, s, "Alice", admin.RoleUser)

	rec := httptest.NewRecorder()
	s.sessionMgr.CreateSession(rec, uid, admin.RoleUser)
	mintReq := httptest.NewRequest("GET", "/tunnel-login?hostname="+host, nil)
	for _, c := range rec.Result().Cookies() {
		mintReq.AddCookie(c)
	}
	mintW := httptest.NewRecorder()
	s.handleTunnelLogin(mintW, mintReq)
	tok := mustToken(t, mintW.Header().Get("Location"))

	// Presenting the token on a DIFFERENT hostname must be rejected (token binding).
	w := httptest.NewRecorder()
	s.handleTunnelLoginComplete(w, httptest.NewRequest("GET", "https://evil.example.com/.gatecrash/auth/complete?token="+tok, nil), "evil.example.com")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("hostname mismatch should be 400, got %d", w.Code)
	}
}

func TestTunnelLogin_UnauthenticatedShowsServiceLoginPage(t *testing.T) {
	s := authTestServer(t)
	host := "app.example.com"
	s.registry.Register(newTunnelState(TunnelSpec{ID: "web", Hostnames: []string{host}}))
	// A real (non-bootstrap) user must exist so NeedsSetup() is false.
	addUser(t, s, "Alice", admin.RoleAdmin)
	// Mark setup complete by giving the admin a credential.
	_ = s.users.AddCredential(s.users.All()[0].ID, admin.StoredCredential{ID: []byte("c"), Name: "k"})

	// No session cookie → the bespoke "service protected" page, not a redirect.
	w := httptest.NewRecorder()
	s.handleTunnelLogin(w, httptest.NewRequest("GET", "/tunnel-login?hostname="+host, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 sign-in page, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "protected by Gatecrash") || !strings.Contains(body, host) {
		t.Fatalf("expected bespoke service-login page naming the host, got: %s", body[:min(len(body), 300)])
	}
}

func TestTunnelLogin_UnknownHostname(t *testing.T) {
	s := authTestServer(t)
	uid := addUser(t, s, "Alice", admin.RoleUser)
	rec := httptest.NewRecorder()
	s.sessionMgr.CreateSession(rec, uid, admin.RoleUser)
	r := httptest.NewRequest("GET", "/tunnel-login?hostname=nope.example.com", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.handleTunnelLogin(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown hostname should be 400, got %d", w.Code)
	}
}

func mustToken(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location %q: %v", location, err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("no token in %q", location)
	}
	return tok
}
