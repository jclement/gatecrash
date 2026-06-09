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
				ID:         "mcp",
				Type:       "http",
				Hostnames:  []string{"mcp.example.com"},
				IPPolicy:   "internal",
				AuthPolicy: "staff",
			}},
			SSHPort: 2222,
		},
	})

	if rec.Code != 200 {
		t.Fatalf("render status = %d", rec.Code)
	}
	body := rec.Body.String()
	// The grid should show the policy badges and the edit button should carry
	// the policy refs through to openEditTunnel.
	if !strings.Contains(body, ">internal<") || !strings.Contains(body, ">staff<") {
		t.Error("expected ip/auth policy badges in the dashboard")
	}
	if !strings.Contains(body, "'internal', 'staff')") {
		t.Error("expected openEditTunnel to receive the policy refs")
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
