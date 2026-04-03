package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxAuditEntries = 1000

// AuditEntry represents a single audit log event.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
}

// AuditLog stores admin panel audit events in a JSON file.
type AuditLog struct {
	path    string
	mu      sync.RWMutex
	entries []AuditEntry
}

// NewAuditLog loads or creates an audit log at the given path.
func NewAuditLog(path string) (*AuditLog, error) {
	a := &AuditLog{path: path}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return a, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading audit log: %w", err)
	}

	if err := json.Unmarshal(data, &a.entries); err != nil {
		return nil, fmt.Errorf("parsing audit log: %w", err)
	}

	return a, nil
}

// Log records a new audit event. Newest entries are first.
func (a *AuditLog) Log(actor, action, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := AuditEntry{
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Detail:    detail,
	}

	// Prepend (newest first)
	a.entries = append([]AuditEntry{entry}, a.entries...)

	// Cap at max entries
	if len(a.entries) > maxAuditEntries {
		a.entries = a.entries[:maxAuditEntries]
	}

	// Best-effort save -- log errors but don't fail
	if err := a.save(); err != nil {
		fmt.Fprintf(os.Stderr, "audit log save error: %v\n", err)
	}
}

// Entries returns a slice of audit entries with offset-based pagination.
func (a *AuditLog) Entries(limit, offset int) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if offset >= len(a.entries) {
		return nil
	}

	end := offset + limit
	if end > len(a.entries) {
		end = len(a.entries)
	}

	result := make([]AuditEntry, end-offset)
	copy(result, a.entries[offset:end])
	return result
}

// Count returns the total number of audit entries.
func (a *AuditLog) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

func (a *AuditLog) save() error {
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	data, err := json.MarshalIndent(a.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling audit log: %w", err)
	}

	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmp, a.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}
