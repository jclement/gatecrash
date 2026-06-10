package admin

import (
	"path/filepath"
	"testing"
)

func newTestUserStore(t *testing.T) *UserStore {
	t.Helper()
	s, err := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

func TestUserStore_InviteRegisterReset(t *testing.T) {
	s := newTestUserStore(t)
	if !s.NeedsSetup() {
		t.Fatal("fresh store needs setup")
	}

	tok, err := s.Create("admin", RoleAdmin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Pending invite, no passkeys yet → still needs setup.
	if !s.NeedsSetup() {
		t.Fatal("admin without passkeys still needs setup")
	}
	if u := s.FindByInvite(tok); u == nil || u.ID != "admin" {
		t.Fatal("invite token should resolve to the user")
	}
	if s.FindByInvite("wrong") != nil {
		t.Fatal("wrong token must not resolve")
	}

	// Register a passkey → invite consumed, setup complete.
	if err := s.AddCredential("admin", StoredCredential{ID: []byte("cred-1")}); err != nil {
		t.Fatalf("add cred: %v", err)
	}
	if s.NeedsSetup() {
		t.Fatal("admin with a passkey completes setup")
	}
	if s.FindByInvite(tok) != nil {
		t.Fatal("invite must be consumed after registration")
	}
	if u := s.FindByCredentialID([]byte("cred-1")); u == nil || u.ID != "admin" {
		t.Fatal("discoverable lookup by credential id should find the user")
	}

	// Reset → keys wiped, new invite.
	tok2, err := s.Reset("admin")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if s.Get("admin").HasPasskeys() {
		t.Fatal("reset should wipe passkeys")
	}
	if tok2 == tok || s.FindByInvite(tok2) == nil {
		t.Fatal("reset should issue a fresh, valid invite")
	}
}

func TestUserStore_LastAdminProtected(t *testing.T) {
	s := newTestUserStore(t)
	s.Create("admin", RoleAdmin)
	s.AddCredential("admin", StoredCredential{ID: []byte("a")})

	if err := s.Delete("admin"); err == nil {
		t.Fatal("must not delete the last admin")
	}
	if err := s.SetRole("admin", RoleUser); err == nil {
		t.Fatal("must not demote the last admin")
	}
	if err := s.RemoveCredential("admin", []byte("a")); err == nil {
		t.Fatal("must not remove the last admin's last passkey")
	}

	// With a second admin, the protections relax.
	s.Create("admin2", RoleAdmin)
	s.AddCredential("admin2", StoredCredential{ID: []byte("b")})
	if err := s.SetRole("admin", RoleUser); err != nil {
		t.Fatalf("should demote when another admin exists: %v", err)
	}
}

func TestUserStore_PersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, _ := NewUserStore(path)
	s.Create("bob", RoleUser)
	s.AddCredential("bob", StoredCredential{ID: []byte("k")})

	again, err := NewUserStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if u := again.Get("bob"); u == nil || u.Role != RoleUser || !u.HasPasskeys() {
		t.Fatal("user should persist across reload")
	}
}
