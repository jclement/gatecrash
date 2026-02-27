package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateHostKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")

	// Generate new key
	signer1, err := loadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if signer1 == nil {
		t.Fatal("signer should not be nil")
	}

	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("host key file should exist")
	}

	// Verify permissions
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	// Load existing key
	signer2, err := loadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if signer2 == nil {
		t.Fatal("loaded signer should not be nil")
	}

	// Should be the same key
	if string(signer1.PublicKey().Marshal()) != string(signer2.PublicKey().Marshal()) {
		t.Fatal("loaded key should match generated key")
	}
}
