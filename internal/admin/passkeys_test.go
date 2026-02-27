package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewPasskeyStore_NoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, err := NewPasskeyStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

	store, err := NewPasskeyStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred := StoredCredential{
		ID:        []byte{1, 2, 3, 4},
		PublicKey: []byte{5, 6, 7, 8},
		Name:      "test-key",
	}

	if err := store.AddCredential(cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	if !store.IsSetupComplete() {
		t.Fatal("should be setup complete after adding credential")
	}

	found := store.FindCredentialByID([]byte{1, 2, 3, 4})
	if found == nil {
		t.Fatal("should find credential by ID")
	}
	if found.Name != "test-key" {
		t.Fatalf("wrong name: %s", found.Name)
	}

	notFound := store.FindCredentialByID([]byte{9, 9, 9})
	if notFound != nil {
		t.Fatal("should not find non-existent credential")
	}
}

func TestPasskeyStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	// Create and add
	store1, _ := NewPasskeyStore(path)
	store1.AddCredential(StoredCredential{
		ID:   []byte{1, 2, 3},
		Name: "persisted-key",
	})

	// Reload from disk
	store2, err := NewPasskeyStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if !store2.IsSetupComplete() {
		t.Fatal("should persist setup_complete")
	}

	creds := store2.Credentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Name != "persisted-key" {
		t.Fatalf("wrong name: %s", creds[0].Name)
	}
}

func TestPasskeyStore_RemoveCredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, _ := NewPasskeyStore(path)
	store.AddCredential(StoredCredential{ID: []byte{1}, Name: "key1"})
	store.AddCredential(StoredCredential{ID: []byte{2}, Name: "key2"})

	// Remove second key
	if err := store.RemoveCredential([]byte{2}); err != nil {
		t.Fatalf("RemoveCredential: %v", err)
	}

	if len(store.Credentials()) != 1 {
		t.Fatalf("expected 1 credential after removal")
	}

	// Can't remove last credential
	if err := store.RemoveCredential([]byte{1}); err == nil {
		t.Fatal("should not allow removing last credential")
	}
}

func TestPasskeyStore_UpdateSignCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, _ := NewPasskeyStore(path)
	store.AddCredential(StoredCredential{ID: []byte{1, 2}, Name: "key1"})

	if err := store.UpdateSignCount([]byte{1, 2}, 42); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}

	cred := store.FindCredentialByID([]byte{1, 2})
	if cred.SignCount != 42 {
		t.Fatalf("expected sign count 42, got %d", cred.SignCount)
	}

	// Non-existent credential
	if err := store.UpdateSignCount([]byte{9, 9}, 1); err == nil {
		t.Fatal("should fail for non-existent credential")
	}
}

func TestPasskeyStore_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")

	store, _ := NewPasskeyStore(path)
	store.AddCredential(StoredCredential{ID: []byte{1}, Name: "key"})

	// Verify no temp file left behind
	_, err := os.Stat(path + ".tmp")
	if !os.IsNotExist(err) {
		t.Fatal("temp file should not exist after save")
	}

	// Verify main file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("main file should exist: %v", err)
	}
}
