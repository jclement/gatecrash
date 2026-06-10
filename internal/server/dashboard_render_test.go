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

// TestAuthPagesRender renders the real login/passkeys/users/invite templates to
// confirm they compile and execute.
func TestAuthPagesRender(t *testing.T) {
	tmplFS, err := fs.Sub(web.EmbeddedFS, "templates")
	if err != nil {
		t.Fatalf("sub fs: %v", err)
	}
	h, err := admin.NewHandlers("test", time.Hour, tmplFS)
	if err != nil {
		t.Fatalf("NewHandlers (template parse): %v", err)
	}
	cases := []struct {
		page string
		data *admin.PageData
	}{
		{"pages/login.html", &admin.PageData{Title: "Sign in"}},
		{"pages/login.html", &admin.PageData{Title: "Not initialized", Data: struct{ NeedsSetup bool }{true}}},
		{"pages/passkeys.html", &admin.PageData{Title: "Passkeys", Active: "passkeys", UserID: "u_1", Name: "admin", IsAdmin: true, CSRFToken: "x",
			Data: struct {
				Passkeys  []admin.PasskeyView
				CanDelete bool
			}{}}},
		{"pages/users.html", &admin.PageData{Title: "Users", Active: "users", UserID: "u_1", IsAdmin: true, CSRFToken: "x"}},
		{"pages/invite.html", &admin.PageData{Title: "Set up your passkey", Data: struct{ Name, Token string }{"alice", "tok"}}},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.Render(rec, c.page, c.data)
		if rec.Code != 200 {
			t.Errorf("%s render status = %d", c.page, rec.Code)
		}
	}
}
