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
	for _, want := range []string{"IP Policies", "Auth Policies", "accessPolicies()", "Static password"} {
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
}

func TestAuthPolicyCRUD_PasswordHashing(t *testing.T) {
	s := newPolicyTestServer(t)
	body := `{"id":"staff","users":["alice"],"username":"ci","password":"hunter2"}`
	rec := httptest.NewRecorder()
	s.handleSaveAuthPolicy(rec, httptest.NewRequest("POST", "/api/auth-policies", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body.String())
	}
	pol := s.registry.FindAuthPolicy("staff")
	if pol == nil || pol.PasswordHash == "" || pol.PasswordHash == "hunter2" {
		t.Fatal("expected password to be hashed and applied")
	}
	// List must not leak the hash.
	lrec := httptest.NewRecorder()
	s.handleListAuthPolicies(lrec, httptest.NewRequest("GET", "/api/auth-policies", nil))
	if strings.Contains(lrec.Body.String(), "hunter2") || strings.Contains(lrec.Body.String(), pol.PasswordHash) {
		t.Fatal("list must not expose the password hash")
	}
	if !strings.Contains(lrec.Body.String(), `"has_password":true`) {
		t.Fatal("list should report has_password")
	}
}

func parseIPHelper(s string) net.IP { return net.ParseIP(s) }
