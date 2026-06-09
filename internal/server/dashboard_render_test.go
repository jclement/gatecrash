package server

import (
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/web"
)

// TestDashboardRendersWithIPAllowlist renders the real embedded dashboard
// template against a tunnel view that exercises the new IP allowlist fields,
// catching template parse/exec errors the stubbed admin tests can't.
func TestDashboardRendersWithIPAllowlist(t *testing.T) {
	tmplFS, err := fs.Sub(web.EmbeddedFS, "templates")
	if err != nil {
		t.Fatalf("sub fs: %v", err)
	}
	h, err := admin.NewHandlers("test", time.Hour, tmplFS)
	if err != nil {
		t.Fatalf("NewHandlers (template parse): %v", err)
	}

	rec := httptest.NewRecorder()
	h.Render(rec, "pages/dashboard.html", &admin.PageData{
		Title:  "Dashboard",
		Active: "dashboard",
		Data: struct {
			Tunnels   []admin.TunnelView
			Redirects []RedirectView
			SSHPort   int
		}{
			Tunnels: []admin.TunnelView{{
				ID:          "mcp",
				Type:        "http",
				Hostnames:   []string{"mcp.example.com"},
				IPAllowlist: true,
				AllowIPs:    []string{"203.0.113.4", "10.0.0.0/8"},
			}},
			SSHPort: 2222,
		},
	})

	if rec.Code != 200 {
		t.Fatalf("render status = %d", rec.Code)
	}
	body := rec.Body.String()
	// The edit button should carry the new args through to openEditTunnel.
	if !strings.Contains(body, "203.0.113.4, 10.0.0.0/8") {
		t.Error("expected AllowIPsCSV to render in the dashboard")
	}
	// An allowlist tunnel should expose the IPs management button.
	if !strings.Contains(body, "openIPModal('mcp')") {
		t.Error("expected IPs button for an ip_allowlist tunnel")
	}
}

// TestLoginRendersReturnURL renders the real login template with an OIDC login
// URL that carries a return path, confirming the template compiles (JS-context
// escaping of OIDCLoginURL included) and threads the return through.
func TestLoginRendersReturnURL(t *testing.T) {
	tmplFS, err := fs.Sub(web.EmbeddedFS, "templates")
	if err != nil {
		t.Fatalf("sub fs: %v", err)
	}
	h, err := admin.NewHandlers("test", time.Hour, tmplFS)
	if err != nil {
		t.Fatalf("NewHandlers (template parse): %v", err)
	}
	rec := httptest.NewRecorder()
	h.Render(rec, "pages/login.html", &admin.PageData{
		Title:          "Login",
		OIDCConfigured: true,
		OIDCLoginURL:   "/oidc/login?return=%2Fauthorize-ip%3Ftunnel%3Dmcp",
	})
	if rec.Code != 200 {
		t.Fatalf("render status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "/oidc/login?return=") {
		t.Error("expected OIDC login URL with return param in rendered login page")
	}
}
