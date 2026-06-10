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

	id, tok, err := s.Create("admin", RoleAdmin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == "admin" || id == "" {
		t.Fatalf("id should be an opaque GUID, got %q", id)
	}
	// Pending invite, no passkeys yet → still needs setup.
	if !s.NeedsSetup() {
		t.Fatal("admin without passkeys still needs setup")
	}
	if u := s.FindByInvite(tok); u == nil || u.ID != id || u.Name != "admin" {
		t.Fatal("invite token should resolve to the user")
	}
	if s.FindByInvite("wrong") != nil {
		t.Fatal("wrong token must not resolve")
	}

	// Register a passkey → invite consumed, setup complete.
	if err := s.AddCredential(id, StoredCredential{ID: []byte("cred-1")}); err != nil {
		t.Fatalf("add cred: %v", err)
	}
	if s.NeedsSetup() {
		t.Fatal("admin with a passkey completes setup")
	}
	if s.FindByInvite(tok) != nil {
		t.Fatal("invite must be consumed after registration")
	}
	if u := s.FindByCredentialID([]byte("cred-1")); u == nil || u.ID != id {
		t.Fatal("discoverable lookup by credential id should find the user")
	}

	// Rename is free; the id is immutable.
	if err := s.Rename(id, "Administrator"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if u := s.Get(id); u == nil || u.Name != "Administrator" {
		t.Fatal("rename should change the label, not the id")
	}

	// Reset → keys wiped, new invite.
	tok2, err := s.Reset(id)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if s.Get(id).HasPasskeys() {
		t.Fatal("reset should wipe passkeys")
	}
	if tok2 == tok || s.FindByInvite(tok2) == nil {
		t.Fatal("reset should issue a fresh, valid invite")
	}
}

func TestUserStore_NameUniqueAndRequired(t *testing.T) {
	s := newTestUserStore(t)
	if _, _, err := s.Create("", RoleUser); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if _, _, err := s.Create("alice", RoleUser); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, _, err := s.Create("Alice", RoleUser); err == nil {
		t.Fatal("duplicate name (case-insensitive) must be rejected")
	}
}

func TestUserStore_LastAdminProtected(t *testing.T) {
	s := newTestUserStore(t)
	id, _, _ := s.Create("admin", RoleAdmin)
	s.AddCredential(id, StoredCredential{ID: []byte("a")})

	if err := s.Delete(id); err == nil {
		t.Fatal("must not delete the last admin")
	}
	if err := s.SetRole(id, RoleUser); err == nil {
		t.Fatal("must not demote the last admin")
	}
	if err := s.RemoveCredential(id, []byte("a")); err == nil {
		t.Fatal("must not remove the last admin's last passkey")
	}

	// With a second admin, the protections relax.
	id2, _, _ := s.Create("admin2", RoleAdmin)
	s.AddCredential(id2, StoredCredential{ID: []byte("b")})
	if err := s.SetRole(id, RoleUser); err != nil {
		t.Fatalf("should demote when another admin exists: %v", err)
	}
}

func TestUserStore_PersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, _ := NewUserStore(path)
	id, _, _ := s.Create("bob", RoleUser)
	s.AddCredential(id, StoredCredential{ID: []byte("k")})

	again, err := NewUserStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if u := again.Get(id); u == nil || u.Name != "bob" || u.Role != RoleUser || !u.HasPasskeys() {
		t.Fatal("user should persist across reload")
	}
}

func TestUserStore_BootstrapInvite(t *testing.T) {
	s := newTestUserStore(t)
	tok, err := s.BootstrapInvite()
	if err != nil || tok == "" {
		t.Fatalf("bootstrap invite: tok=%q err=%v", tok, err)
	}
	// Idempotent: same token until the invite is consumed.
	if tok2, _ := s.BootstrapInvite(); tok2 != tok {
		t.Fatal("bootstrap invite should be stable across calls")
	}
	u := s.FindByInvite(tok)
	if u == nil || !u.IsAdmin() {
		t.Fatal("bootstrap invite should resolve to a pending admin")
	}
	s.AddCredential(u.ID, StoredCredential{ID: []byte("c")})
	// Once an admin has a passkey, no more bootstrap.
	if tok3, _ := s.BootstrapInvite(); tok3 != "" {
		t.Fatal("bootstrap invite should be empty once initialized")
	}
}
