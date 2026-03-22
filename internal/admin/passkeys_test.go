package admin

import (
	"path/filepath"
	"testing"
)

func TestPasskeyStore_NewEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, err := NewPasskeyStore(path)
	if err != nil {
		t.Fatalf("NewPasskeyStore: %v", err)
	}

	if store.IsSetupComplete() {
		t.Fatal("new store should not be setup complete")
	}
	if len(store.Credentials()) != 0 {
		t.Fatal("new store should have no credentials")
	}
}

func TestPasskeyStore_AddAndFind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, _ := NewPasskeyStore(path)

	cred := StoredCredential{
		ID:        []byte{1, 2, 3},
		PublicKey: []byte{4, 5, 6},
		Name:      "Test Key",
	}

	if err := store.AddCredential(cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	if !store.IsSetupComplete() {
		t.Fatal("should be setup complete after adding credential")
	}

	found := store.FindCredentialByID([]byte{1, 2, 3})
	if found == nil {
		t.Fatal("should find credential by ID")
	}
	if found.Name != "Test Key" {
		t.Fatalf("wrong name: %s", found.Name)
	}

	if store.FindCredentialByID([]byte{9, 9, 9}) != nil {
		t.Fatal("should not find nonexistent credential")
	}
}

func TestPasskeyStore_RemoveCredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, _ := NewPasskeyStore(path)
	store.AddCredential(StoredCredential{ID: []byte{1}, Name: "Key 1"})
	store.AddCredential(StoredCredential{ID: []byte{2}, Name: "Key 2"})

	if err := store.RemoveCredential([]byte{1}); err != nil {
		t.Fatalf("RemoveCredential: %v", err)
	}

	if len(store.Credentials()) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(store.Credentials()))
	}

	// Cannot remove last
	if err := store.RemoveCredential([]byte{2}); err == nil {
		t.Fatal("should not remove last credential")
	}

	// Remove nonexistent
	if err := store.RemoveCredential([]byte{99}); err == nil {
		t.Fatal("should error on nonexistent credential")
	}
}

func TestPasskeyStore_UpdateSignCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, _ := NewPasskeyStore(path)
	store.AddCredential(StoredCredential{ID: []byte{1}, Name: "Key 1"})

	if err := store.UpdateSignCount([]byte{1}, 42); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}

	found := store.FindCredentialByID([]byte{1})
	if found.SignCount != 42 {
		t.Fatalf("expected sign count 42, got %d", found.SignCount)
	}

	if err := store.UpdateSignCount([]byte{99}, 1); err == nil {
		t.Fatal("should error on nonexistent credential")
	}
}

func TestPasskeyStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store1, _ := NewPasskeyStore(path)
	store1.AddCredential(StoredCredential{ID: []byte{1, 2, 3}, Name: "Persisted"})

	store2, err := NewPasskeyStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if !store2.IsSetupComplete() {
		t.Fatal("setup complete should persist")
	}

	creds := store2.Credentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential after reload, got %d", len(creds))
	}
	if creds[0].Name != "Persisted" {
		t.Fatalf("credential name should persist: %s", creds[0].Name)
	}
}

func TestPasskeyStore_CredentialsCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, _ := NewPasskeyStore(path)
	store.AddCredential(StoredCredential{ID: []byte{1}, Name: "Key 1"})

	creds := store.Credentials()
	creds[0].Name = "Modified"

	original := store.Credentials()
	if original[0].Name != "Key 1" {
		t.Fatal("Credentials() should return a copy")
	}
}
