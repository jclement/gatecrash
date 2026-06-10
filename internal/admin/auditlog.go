package admin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	// auditRingSize is how many recent entries are kept in memory to serve the
	// admin UI (newest first). The full history lives on disk.
	auditRingSize = 1000
	// auditMaxFileSize triggers rotation of the on-disk log. One previous
	// generation is kept (<path>.1), bounding disk use at ~2x this.
	auditMaxFileSize = 16 << 20 // 16 MiB
)

// AuditEntry represents a single audit log event.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
}

// AuditLog is an append-only NDJSON audit log: one JSON object per line, appended
// with O(1) cost (no whole-file rewrites). The most recent entries are also kept
// in memory (newest first) to serve the admin UI cheaply.
type AuditLog struct {
	path   string
	mu     sync.RWMutex
	recent []AuditEntry // newest-first, capped at auditRingSize
	size   int64        // current on-disk size, for rotation
}

// NewAuditLog loads or creates an audit log at the given path. A legacy
// JSON-array file (from older versions) is transparently migrated to NDJSON.
func NewAuditLog(path string) (*AuditLog, error) {
	a := &AuditLog{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return a, nil
		}
		return nil, fmt.Errorf("reading audit log: %w", err)
	}

	// Legacy format: a single JSON array. Load it and rewrite as NDJSON.
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '[' {
		var legacy []AuditEntry
		if err := json.Unmarshal(trimmed, &legacy); err != nil {
			return nil, fmt.Errorf("parsing legacy audit log: %w", err)
		}
		if err := a.migrateFromLegacy(legacy); err != nil {
			return nil, fmt.Errorf("migrating audit log: %w", err)
		}
		return a, nil
	}

	// NDJSON: one entry per line. Skip malformed lines (e.g. a torn final line
	// from a crash mid-append).
	a.size = int64(len(data))
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if json.Unmarshal(line, &e) == nil {
			a.pushRecent(e)
		}
	}
	return a, nil
}

// migrateFromLegacy rewrites a legacy []AuditEntry (newest-first on disk) into
// the NDJSON file (oldest-first) and seeds the in-memory ring.
func (a *AuditLog) migrateFromLegacy(legacy []AuditEntry) error {
	var buf bytes.Buffer
	// Legacy stored newest-first; write oldest-first so the file reads
	// chronologically like a normal append log.
	for i := len(legacy) - 1; i >= 0; i-- {
		line, err := json.Marshal(legacy[i])
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := a.atomicWrite(buf.Bytes()); err != nil {
		return err
	}
	a.size = int64(buf.Len())
	a.recent = append(a.recent, legacy...) // legacy is already newest-first
	if len(a.recent) > auditRingSize {
		a.recent = a.recent[:auditRingSize]
	}
	return nil
}

// pushRecent inserts an entry at the front of the newest-first ring.
func (a *AuditLog) pushRecent(e AuditEntry) {
	a.recent = append([]AuditEntry{e}, a.recent...)
	if len(a.recent) > auditRingSize {
		a.recent = a.recent[:auditRingSize]
	}
}

// Log records a new audit event. Newest entries are first in the UI.
func (a *AuditLog) Log(actor, action, detail string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Detail:    detail,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.pushRecent(entry)
	if err := a.appendLine(entry); err != nil {
		fmt.Fprintf(os.Stderr, "audit log append error: %v\n", err)
	}
}

// appendLine appends one NDJSON record and rotates the file if it's grown large.
// Caller must hold a.mu.
func (a *AuditLog) appendLine(e AuditEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	n, werr := f.Write(line)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}

	a.size += int64(n)
	if a.size > auditMaxFileSize {
		// Keep one previous generation; start a fresh file on the next append.
		if rerr := os.Rename(a.path, a.path+".1"); rerr == nil {
			a.size = 0
		}
	}
	return nil
}

// atomicWrite replaces the log file atomically (used only for migration).
func (a *AuditLog) atomicWrite(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Entries returns recent audit entries (newest first) with offset-based
// pagination, served from the in-memory ring.
func (a *AuditLog) Entries(limit, offset int) []AuditEntry {
	entries, _ := a.Query(limit, offset, "", "")
	return entries
}

// Query returns recent entries (newest first) matching the optional actor and
// action filters (empty = any), with offset-based pagination, plus the total
// number of matching entries in the window (for pagination).
func (a *AuditLog) Query(limit, offset int, actor, action string) (entries []AuditEntry, total int) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	match := 0
	for _, e := range a.recent { // newest-first
		if actor != "" && e.Actor != actor {
			continue
		}
		if action != "" && e.Action != action {
			continue
		}
		if match >= offset && len(entries) < limit {
			entries = append(entries, e)
		}
		match++
	}
	return entries, match
}

// Facets returns the distinct actors and actions present in the window, sorted,
// for populating filter controls.
func (a *AuditLog) Facets() (actors, actions []string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	seenActor := map[string]struct{}{}
	seenAction := map[string]struct{}{}
	for _, e := range a.recent {
		if _, ok := seenActor[e.Actor]; !ok {
			seenActor[e.Actor] = struct{}{}
			actors = append(actors, e.Actor)
		}
		if _, ok := seenAction[e.Action]; !ok {
			seenAction[e.Action] = struct{}{}
			actions = append(actions, e.Action)
		}
	}
	sort.Strings(actors)
	sort.Strings(actions)
	return actors, actions
}

// Count returns the number of recent entries available to the UI.
func (a *AuditLog) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.recent)
}
