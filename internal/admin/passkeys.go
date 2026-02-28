package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PasskeyStore manages passkey credentials in a JSON file.
type PasskeyStore struct {
	path string
	mu   sync.RWMutex
	data PasskeyData
}

// PasskeyData is the on-disk representation of stored passkeys.
type PasskeyData struct {
	SetupComplete bool                `json:"setup_complete"`
	Credentials   []StoredCredential  `json:"credentials"`
}

// StoredCredential represents a single WebAuthn credential.
type StoredCredential struct {
	ID             []byte    `json:"id"`
	PublicKey      []byte    `json:"public_key"`
	Name           string    `json:"name"`
	AAGUID         []byte    `json:"aaguid"`
	SignCount      uint32    `json:"sign_count"`
	CreatedAt      time.Time `json:"created_at"`
	LastUsedAt     time.Time `json:"last_used_at"`
	Transport      []string  `json:"transport"`
	AttType        string    `json:"att_type"`
	BackupEligible bool      `json:"backup_eligible"`
	BackupState    bool      `json:"backup_state"`
}

// NewPasskeyStore loads or creates a passkey store at the given path.
func NewPasskeyStore(path string) (*PasskeyStore, error) {
	s := &PasskeyStore{path: path}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		s.data = PasskeyData{}
		return s, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading passkey store: %w", err)
	}

	if err := json.Unmarshal(data, &s.data); err != nil {
		return nil, fmt.Errorf("parsing passkey store: %w", err)
	}

	return s, nil
}

// IsSetupComplete returns whether the initial passkey registration has been done.
func (s *PasskeyStore) IsSetupComplete() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.SetupComplete
}

// Credentials returns all stored credentials.
func (s *PasskeyStore) Credentials() []StoredCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	creds := make([]StoredCredential, len(s.data.Credentials))
	copy(creds, s.data.Credentials)
	return creds
}

// AddCredential stores a new credential and marks setup as complete.
func (s *PasskeyStore) AddCredential(cred StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred.CreatedAt = time.Now()
	cred.LastUsedAt = time.Now()
	s.data.Credentials = append(s.data.Credentials, cred)
	s.data.SetupComplete = true

	return s.save()
}

// UpdateSignCount updates the sign count and last used time for a credential.
func (s *PasskeyStore) UpdateSignCount(credID []byte, count uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.Credentials {
		if bytesEqual(s.data.Credentials[i].ID, credID) {
			s.data.Credentials[i].SignCount = count
			s.data.Credentials[i].LastUsedAt = time.Now()
			return s.save()
		}
	}

	return fmt.Errorf("credential not found")
}

// RemoveCredential removes a credential by ID. Won't remove the last one.
func (s *PasskeyStore) RemoveCredential(credID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.data.Credentials) <= 1 {
		return fmt.Errorf("cannot remove last credential")
	}

	for i := range s.data.Credentials {
		if bytesEqual(s.data.Credentials[i].ID, credID) {
			s.data.Credentials = append(s.data.Credentials[:i], s.data.Credentials[i+1:]...)
			return s.save()
		}
	}

	return fmt.Errorf("credential not found")
}

// FindCredentialByID looks up a credential by its ID.
func (s *PasskeyStore) FindCredentialByID(credID []byte) *StoredCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.data.Credentials {
		if bytesEqual(s.data.Credentials[i].ID, credID) {
			cred := s.data.Credentials[i]
			return &cred
		}
	}
	return nil
}

func (s *PasskeyStore) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling passkey data: %w", err)
	}

	// Atomic write via temp file + rename
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
