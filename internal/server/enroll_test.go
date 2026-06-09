package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/internal/config"
)

func newEnrollTestServer(t *testing.T, tunnels []config.Tunnel) *Server {
	t.Helper()
	dir := t.TempDir()
	ipAllow, err := NewIPAllowStore(filepath.Join(dir, "ip_allowlist.json"))
	if err != nil {
		t.Fatalf("ip store: %v", err)
	}
	auditLog, err := admin.NewAuditLog(filepath.Join(dir, "audit.json"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	reg := NewRegistry()
	for _, tc := range tunnels {
		reg.Register(newTunnelState(specFromConfig(tc)))
	}
	return &Server{
		cfg: &config.Config{
			Server: config.ServerConfig{AdminHost: "admin.example.com", HTTPSPort: 443},
			Tunnel: tunnels,
		},
		registry: reg,
		ipAllow:  ipAllow,
		auditLog: auditLog,
	}
}

func TestFindTunnelByEnrollToken(t *testing.T) {
	s := newEnrollTestServer(t, []config.Tunnel{
		{ID: "a", EnrollToken: "secret-token-aaa"},
		{ID: "b"}, // no token
	})

	if _, ok := s.findTunnelByEnrollToken("secret-token-aaa"); !ok {
		t.Fatal("expected to find tunnel a by its token")
	}
	if _, ok := s.findTunnelByEnrollToken("wrong"); ok {
		t.Fatal("must not match a wrong token")
	}
	if _, ok := s.findTunnelByEnrollToken(""); ok {
		t.Fatal("empty token must never match (incl. the token-less tunnel b)")
	}
}

func TestHandleEnrollSubmit_GrantsIP(t *testing.T) {
	s := newEnrollTestServer(t, []config.Tunnel{
		{ID: "mcp", Type: "http", Hostnames: []string{"mcp.example.com"}, IPAllowlist: true, EnrollToken: "tok123"},
	})

	req := httptest.NewRequest("POST", "/enroll/tok123", nil)
	req.SetPathValue("token", "tok123")
	req.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()

	s.handleEnrollSubmit(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if !s.ipAllow.IsGranted("mcp", net.ParseIP("203.0.113.9")) {
		t.Fatal("expected the caller IP to be granted after enroll")
	}
	// HTTP tunnel → confirmation should offer a continue link to the app.
	if !strings.Contains(rec.Body.String(), "https://mcp.example.com") {
		t.Error("expected a continue-to-app link for an HTTP tunnel")
	}
}

func TestHandleEnrollSubmit_BadToken(t *testing.T) {
	s := newEnrollTestServer(t, []config.Tunnel{{ID: "x", EnrollToken: "good"}})
	req := httptest.NewRequest("POST", "/enroll/nope", nil)
	req.SetPathValue("token", "nope")
	req.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()
	s.handleEnrollSubmit(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for bad token, got %d", rec.Code)
	}
}

func TestHandleEnrollPage_States(t *testing.T) {
	s := newEnrollTestServer(t, []config.Tunnel{
		{ID: "mcp", Type: "http", Hostnames: []string{"mcp.example.com"}, IPAllowlist: true, EnrollToken: "tok", AllowIPs: []string{"198.51.100.0/24"}},
	})

	get := func(remote string) string {
		req := httptest.NewRequest("GET", "/enroll/tok", nil)
		req.SetPathValue("token", "tok")
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.handleEnrollPage(rec, req)
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		return rec.Body.String()
	}

	// New visitor → authorize prompt.
	if b := get("203.0.113.5:1"); !strings.Contains(b, "Authorize my IP") {
		t.Error("new visitor should see the authorize prompt")
	}
	// Permanently allowlisted (in 198.51.100.0/24) → already-have-access, no form.
	if b := get("198.51.100.7:1"); !strings.Contains(b, "permanently allowed") || strings.Contains(b, "Authorize my IP") {
		t.Error("permanent IP should see permanent-access message and no authorize button")
	}
	// Already self-enrolled → extend option with remaining time.
	s.ipAllow.Grant("mcp", "203.0.113.5", "enrollment-link", ipGrantTTL)
	if b := get("203.0.113.5:1"); !strings.Contains(b, "Extend 7 days") || !strings.Contains(b, "expires in") {
		t.Error("already-enrolled visitor should see an extend option and remaining time")
	}
}
