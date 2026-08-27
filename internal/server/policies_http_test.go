package server

import (
	"io/fs"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/internal/config"
	"github.com/jclement/gatecrash/web"
)

func TestAccessPoliciesPageRenders(t *testing.T) {
	fsys, _ := fs.Sub(web.EmbeddedFS, "templates")
	h, err := admin.NewHandlers("t", time.Hour, fsys)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	rec := httptest.NewRecorder()
	h.Render(rec, "pages/access-policies.html", &admin.PageData{Title: "Access Policies", Active: "access-policies", CSRFToken: "x"})
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	for _, want := range []string{"IP Policies", "Auth Policies", "accessPolicies()", "Service secret"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func newPolicyTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	auditLog, _ := admin.NewAuditLog(filepath.Join(dir, "audit.json"))
	return &Server{
		cfg:        &config.Config{Server: config.ServerConfig{AdminHost: "admin.example.com", HTTPSPort: 443}},
		configPath: filepath.Join(dir, "gatecrash.toml"),
		registry:   NewRegistry(),
		auditLog:   auditLog,
		sessionMgr: admin.NewSessionManager("test-secret"),
	}
}

func TestIPPolicyCRUD(t *testing.T) {
	s := newPolicyTestServer(t)

	body := `{"id":"internal","ranges":[{"cidr":"10.0.0.0/8","comment":"lan"},{"cidr":"bad"}]}`
	rec := httptest.NewRecorder()
	s.handleSaveIPPolicy(rec, httptest.NewRequest("POST", "/api/ip-policies", strings.NewReader(body)))
	if rec.Code == 200 {
		t.Fatal("expected invalid CIDR to be rejected")
	}

	body = `{"id":"internal","ranges":[{"cidr":"10.0.0.0/8","comment":"lan"}]}`
	rec = httptest.NewRecorder()
	s.handleSaveIPPolicy(rec, httptest.NewRequest("POST", "/api/ip-policies", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body.String())
	}
	// Applied to the registry live.
	pol := s.registry.FindIPPolicy("internal")
	if pol == nil || !pol.Allows(parseIPHelper("10.1.2.3")) {
		t.Fatal("policy not applied to registry")
	}

	// The list endpoint must emit lowercase cidr/comment keys so the editor can
	// reload ranges (Go would otherwise marshal CIDR/Comment from the field names).
	lrec := httptest.NewRecorder()
	s.handleListIPPolicies(lrec, httptest.NewRequest("GET", "/api/ip-policies", nil))
	listBody := lrec.Body.String()
	if !strings.Contains(listBody, `"cidr":"10.0.0.0/8"`) || !strings.Contains(listBody, `"comment":"lan"`) {
		t.Fatalf("list must expose lowercase cidr/comment, got: %s", listBody)
	}
}

func TestAuthPolicyCRUD_ServiceSecret(t *testing.T) {
	s := newPolicyTestServer(t)

	// Generate a service secret: the plaintext is returned exactly once, the hash
	// is stored and applied, and the secret grants access via HTTP Basic.
	body := `{"id":"staff","users":["alice"],"generate_secret":true}`
	rec := httptest.NewRecorder()
	s.handleSaveAuthPolicy(rec, httptest.NewRequest("POST", "/api/auth-policies", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"secret":`) {
		t.Fatalf("generate must return the plaintext secret once, got: %s", rec.Body.String())
	}
	pol := s.registry.FindAuthPolicy("staff")
	if pol == nil || pol.SecretHash == "" {
		t.Fatal("expected a service secret hash to be applied")
	}

	// List must report has_secret but never leak the hash.
	lrec := httptest.NewRecorder()
	s.handleListAuthPolicies(lrec, httptest.NewRequest("GET", "/api/auth-policies", nil))
	if strings.Contains(lrec.Body.String(), pol.SecretHash) {
		t.Fatal("list must not expose the secret hash")
	}
	if !strings.Contains(lrec.Body.String(), `"has_secret":true`) {
		t.Fatal("list should report has_secret")
	}

	// Clearing removes the secret.
	crec := httptest.NewRecorder()
	s.handleSaveAuthPolicy(crec, httptest.NewRequest("POST", "/api/auth-policies", strings.NewReader(`{"id":"staff","users":["alice"],"clear_secret":true}`)))
	if crec.Code != 200 {
		t.Fatalf("clear failed: %d %s", crec.Code, crec.Body.String())
	}
	if pol := s.registry.FindAuthPolicy("staff"); pol == nil || pol.SecretHash != "" {
		t.Fatal("expected service secret to be cleared")
	}
}

func parseIPHelper(s string) net.IP { return net.ParseIP(s) }

func TestPromotePolicyIP(t *testing.T) {
	s := newPolicyTestServer(t)
	var err error
	s.ipAllow, err = NewIPAllowStore(filepath.Join(t.TempDir(), "ip_allowlist.json"))
	if err != nil {
		t.Fatalf("NewIPAllowStore: %v", err)
	}

	rec := httptest.NewRecorder()
	s.handleSaveIPPolicy(rec, httptest.NewRequest("POST", "/api/ip-policies", strings.NewReader(`{"id":"internal","ranges":[{"cidr":"10.0.0.0/8","comment":"lan"}]}`)))
	if rec.Code != 200 {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body.String())
	}
	if err := s.ipAllow.Grant("internal", "203.0.113.5", "alice", time.Hour); err != nil {
		t.Fatalf("grant: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/ip-policies/internal/ips/203.0.113.5/permanent", strings.NewReader(`{"comment":"alice home"}`))
	req.SetPathValue("id", "internal")
	req.SetPathValue("ip", "203.0.113.5")
	rec = httptest.NewRecorder()
	s.handlePromotePolicyIP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("promote failed: %d %s", rec.Code, rec.Body.String())
	}

	// Permanent range added with the comment, applied live, and the grant dropped.
	pol := s.registry.FindIPPolicy("internal")
	if pol == nil || !pol.Allows(parseIPHelper("203.0.113.5")) {
		t.Fatal("promoted IP not allowed by registry policy")
	}
	var found bool
	for _, rg := range pol.Ranges {
		if rg.CIDR == "203.0.113.5" && rg.Comment == "alice home" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected permanent range with comment, got %+v", pol.Ranges)
	}
	if len(s.ipAllow.List("internal")) != 0 {
		t.Fatal("temporary grant should be removed after promotion")
	}

	// Idempotent: promoting again updates the comment rather than duplicating.
	req = httptest.NewRequest("POST", "/", strings.NewReader(`{"comment":"updated"}`))
	req.SetPathValue("id", "internal")
	req.SetPathValue("ip", "203.0.113.5")
	rec = httptest.NewRecorder()
	s.handlePromotePolicyIP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("second promote failed: %d", rec.Code)
	}
	pol = s.registry.FindIPPolicy("internal")
	if n := len(pol.Ranges); n != 2 {
		t.Fatalf("expected 2 ranges, got %d: %+v", n, pol.Ranges)
	}
	if pol.Ranges[1].Comment != "updated" {
		t.Fatalf("comment not updated: %+v", pol.Ranges[1])
	}

	// Unknown policy and bad IP are rejected.
	for _, tc := range []struct {
		id, ip string
		want   int
	}{{"nope", "203.0.113.5", 404}, {"internal", "not-an-ip", 400}} {
		req = httptest.NewRequest("POST", "/", nil)
		req.SetPathValue("id", tc.id)
		req.SetPathValue("ip", tc.ip)
		rec = httptest.NewRecorder()
		s.handlePromotePolicyIP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s/%s: got %d want %d", tc.id, tc.ip, rec.Code, tc.want)
		}
	}
}
