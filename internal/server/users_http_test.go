package server

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/internal/config"
)

func newUsersTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	users, _ := admin.NewUserStore(filepath.Join(dir, "users.json"))
	auditLog, _ := admin.NewAuditLog(filepath.Join(dir, "audit.json"))
	return &Server{
		cfg:        &config.Config{Server: config.ServerConfig{AdminHost: "admin.example.com", HTTPSPort: 443}},
		users:      users,
		auditLog:   auditLog,
		sessionMgr: admin.NewSessionManager("secret"),
	}
}

func TestUserCRUD_InviteAndList(t *testing.T) {
	s := newUsersTestServer(t)

	// Create returns a shareable invite link on the admin host.
	rec := httptest.NewRecorder()
	s.handleCreateUser(rec, httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"id":"alice","role":"user"}`)))
	if rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "https://admin.example.com/invite/") {
		t.Fatalf("expected an invite URL, got %s", rec.Body.String())
	}

	// Invalid role rejected.
	rec = httptest.NewRecorder()
	s.handleCreateUser(rec, httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"id":"bob","role":"superuser"}`)))
	if rec.Code == 200 {
		t.Fatal("expected invalid role to be rejected")
	}

	// List shows the pending invite (no passkeys yet).
	rec = httptest.NewRecorder()
	s.handleListUsers(rec, httptest.NewRequest("GET", "/api/users", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"id":"alice"`) || !strings.Contains(body, `"has_passkeys":false`) || !strings.Contains(body, `/invite/`) {
		t.Fatalf("list missing pending user/invite: %s", body)
	}
}
