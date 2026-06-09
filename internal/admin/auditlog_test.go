package admin

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	n := 0
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

func TestAuditLog_AppendReloadNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	a, err := NewAuditLog(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	a.Log("alice", "login", "first")
	a.Log("bob", "tunnel.create", "second")

	got := a.Entries(10, 0)
	if len(got) != 2 || got[0].Actor != "bob" {
		t.Fatalf("expected newest-first [bob, alice], got %+v", got)
	}
	// On disk: NDJSON, oldest-first, one parseable object per line.
	if countLines(t, path) != 2 {
		t.Fatalf("expected 2 NDJSON lines")
	}
	data, _ := os.ReadFile(path)
	if bytes.TrimSpace(data)[0] == '[' {
		t.Fatal("expected NDJSON, not a JSON array")
	}

	// Reopen → recent ring reloaded, newest-first.
	b, err := NewAuditLog(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if b.Count() != 2 || b.Entries(10, 0)[0].Actor != "bob" {
		t.Fatalf("reload mismatch: count=%d", b.Count())
	}
}

func TestAuditLog_LegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	// Legacy format: JSON array, newest-first.
	legacy := []AuditEntry{{Actor: "newest"}, {Actor: "older"}}
	data, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuditLog(path)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if a.Count() != 2 || a.Entries(10, 0)[0].Actor != "newest" {
		t.Fatalf("migrated ring wrong: %+v", a.Entries(10, 0))
	}
	// File is now NDJSON (2 lines), and appends keep working.
	if countLines(t, path) != 2 {
		t.Fatalf("expected 2 lines post-migration")
	}
	a.Log("z", "x", "y")
	if countLines(t, path) != 3 {
		t.Fatalf("append after migration should add a line")
	}
}

func TestAuditLog_RingCapButDiskKeepsAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	a, _ := NewAuditLog(path)
	total := auditRingSize + 25
	for i := 0; i < total; i++ {
		a.Log("u", "act", "d")
	}
	if a.Count() != auditRingSize {
		t.Fatalf("ring should cap at %d, got %d", auditRingSize, a.Count())
	}
	if got := countLines(t, path); got != total {
		t.Fatalf("disk should retain all %d entries, got %d", total, got)
	}
}
