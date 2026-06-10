package admin

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// User roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// inviteTTL is how long an invite link is valid for registering a passkey.
const inviteTTL = 7 * 24 * time.Hour

// maxNameLen bounds a user's display label.
const maxNameLen = 64

// StoredCredential is a single WebAuthn passkey credential on disk.
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

// User is a member of the gatecrash directory. The ID is an opaque, immutable
// GUID — it is what passkeys, sessions, and access policies bind to, so it can
// never change. Name is a free, renameable display label. Users authenticate
// with one or more passkeys.
type User struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Role          string             `json:"role"`
	Credentials   []StoredCredential `json:"credentials"`
	InviteToken   string             `json:"invite_token,omitempty"`
	InviteExpires time.Time          `json:"invite_expires,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`

	// SessionEpoch is a monotonically increasing revocation counter. Every issued
	// session JWT carries the epoch current at mint time; a session whose epoch is
	// older than this is rejected. Bumping it (logout, passkey reset, role change)
	// invalidates all of the user's outstanding sessions across devices, which is
	// what makes logout and credential reset actually revoke a stolen cookie.
	SessionEpoch int `json:"session_epoch,omitempty"`
}

func (u *User) IsAdmin() bool     { return u.Role == RoleAdmin }
func (u *User) HasPasskeys() bool { return len(u.Credentials) > 0 }

// CredentialName returns the label of the credential with the given ID, or "" if
// the user has no such credential. Used to record which passkey was used.
func (u *User) CredentialName(id []byte) string {
	for _, c := range u.Credentials {
		if bytes.Equal(c.ID, id) {
			return c.Name
		}
	}
	return ""
}
func (u *User) InviteActive(now time.Time) bool {
	return u.InviteToken != "" && now.Before(u.InviteExpires)
}

// UserStore persists the user directory to a JSON file. It is safe for
// concurrent use.
type UserStore struct {
	path  string
	mu    sync.RWMutex
	users []*User
}

// NewUserStore loads or creates a user store at the given path.
func NewUserStore(path string) (*UserStore, error) {
	s := &UserStore{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading user store: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.users); err != nil {
			return nil, fmt.Errorf("parsing user store: %w", err)
		}
	}
	return s, nil
}

// NeedsSetup reports whether the directory has no admin yet (first boot).
func (s *UserStore) NeedsSetup() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.IsAdmin() && u.HasPasskeys() {
			return false
		}
	}
	return true
}

// save writes the store atomically. Caller must hold s.mu.
func (s *UserStore) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// getLocked returns the user with the given ID (caller holds s.mu).
func (s *UserStore) getLocked(id string) *User {
	for _, u := range s.users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

// Get returns a copy of the user with the given ID, or nil.
func (s *UserStore) Get(id string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u := s.getLocked(id); u != nil {
		return cloneUser(u)
	}
	return nil
}

// Epoch returns a user's current session revocation epoch and whether the user
// exists. It is the source consulted by SessionManager/TunnelSession to reject
// stale (logged-out / reset / re-roled) or deleted-user sessions.
func (s *UserStore) Epoch(id string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u := s.getLocked(id); u != nil {
		return u.SessionEpoch, true
	}
	return 0, false
}

// BumpEpoch increments a user's session epoch, invalidating all of their
// outstanding sessions, and persists it. A missing user is a no-op.
func (s *UserStore) BumpEpoch(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(id)
	if u == nil {
		return nil
	}
	u.SessionEpoch++
	return s.save()
}

// All returns copies of every user, sorted by ID (admins first).
func (s *UserStore) All() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, len(s.users))
	for i, u := range s.users {
		out[i] = cloneUser(u)
	}
	sortUsers(out)
	return out
}

func (s *UserStore) adminCountLocked() int {
	n := 0
	for _, u := range s.users {
		if u.IsAdmin() {
			n++
		}
	}
	return n
}

// Create adds a new user with the given display name and role, assigning an
// opaque GUID id, and issues an invite token. Returns the new id and the
// plaintext invite token (shown once).
func (s *UserStore) Create(name, role string) (id, inviteToken string, err error) {
	name, err = cleanName(name)
	if err != nil {
		return "", "", err
	}
	if role != RoleAdmin && role != RoleUser {
		return "", "", fmt.Errorf("invalid role %q", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nameTakenLocked(name, "") {
		return "", "", fmt.Errorf("a user named %q already exists", name)
	}
	id, err = s.newUserIDLocked()
	if err != nil {
		return "", "", err
	}
	tok, err := randomToken()
	if err != nil {
		return "", "", err
	}
	s.users = append(s.users, &User{
		ID:            id,
		Name:          name,
		Role:          role,
		InviteToken:   tok,
		InviteExpires: time.Now().Add(inviteTTL),
		CreatedAt:     time.Now(),
	})
	if err := s.save(); err != nil {
		return "", "", err
	}
	return id, tok, nil
}

// Rename changes a user's display label. The id is immutable.
func (s *UserStore) Rename(id, name string) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(id)
	if u == nil {
		return fmt.Errorf("user not found")
	}
	if s.nameTakenLocked(name, id) {
		return fmt.Errorf("a user named %q already exists", name)
	}
	u.Name = name
	return s.save()
}

// BootstrapInvite ensures there is a first admin awaiting passkey registration
// and returns its active invite token. It returns "" when an admin already has a
// passkey (already initialized — no bootstrap needed). Idempotent: it reuses an
// existing pending bootstrap admin and a still-valid invite, only minting a new
// token when none is active. This replaces an open first-login page: the only
// way to claim the first admin is the link printed to the logs / config file.
func (s *UserStore) BootstrapInvite() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.IsAdmin() && u.HasPasskeys() {
			return "", nil // already initialized
		}
	}
	now := time.Now()
	var admin *User
	for _, u := range s.users {
		if u.IsAdmin() && !u.HasPasskeys() {
			admin = u
			break
		}
	}
	if admin == nil {
		id, err := s.newUserIDLocked()
		if err != nil {
			return "", err
		}
		admin = &User{ID: id, Name: "admin", Role: RoleAdmin, CreatedAt: now}
		s.users = append(s.users, admin)
	}
	if !admin.InviteActive(now) {
		tok, err := randomToken()
		if err != nil {
			return "", err
		}
		admin.InviteToken = tok
		admin.InviteExpires = now.Add(inviteTTL)
	}
	if err := s.save(); err != nil {
		return "", err
	}
	return admin.InviteToken, nil
}

// cleanName trims and validates a display label.
func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if len([]rune(name)) > maxNameLen {
		return "", fmt.Errorf("name too long (max %d characters)", maxNameLen)
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("name contains invalid characters")
		}
	}
	return name, nil
}

// nameTakenLocked reports whether another user (id != exceptID) has this name
// (case-insensitive). Caller holds s.mu.
func (s *UserStore) nameTakenLocked(name, exceptID string) bool {
	for _, u := range s.users {
		if u.ID != exceptID && strings.EqualFold(u.Name, name) {
			return true
		}
	}
	return false
}

// newUserIDLocked mints a short, opaque, unique user id. Caller holds s.mu.
func (s *UserStore) newUserIDLocked() (string, error) {
	for i := 0; i < 5; i++ {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		id := "u_" + hex.EncodeToString(b)
		if s.getLocked(id) == nil {
			return id, nil
		}
	}
	return "", fmt.Errorf("could not allocate a unique user id")
}

// Delete removes a user. The last admin cannot be removed.
func (s *UserStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(id)
	if u == nil {
		return fmt.Errorf("user %q not found", id)
	}
	if u.IsAdmin() && s.adminCountLocked() <= 1 {
		return fmt.Errorf("cannot remove the last admin")
	}
	kept := s.users[:0]
	for _, x := range s.users {
		if x.ID != id {
			kept = append(kept, x)
		}
	}
	s.users = kept
	return s.save()
}

// SetRole changes a user's role. The last admin cannot be demoted.
func (s *UserStore) SetRole(id, role string) error {
	if role != RoleAdmin && role != RoleUser {
		return fmt.Errorf("invalid role %q", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(id)
	if u == nil {
		return fmt.Errorf("user %q not found", id)
	}
	if u.IsAdmin() && role != RoleAdmin && s.adminCountLocked() <= 1 {
		return fmt.Errorf("cannot demote the last admin")
	}
	u.Role = role
	// Revoke outstanding sessions so a role change takes effect immediately
	// rather than at the old token's expiry.
	u.SessionEpoch++
	return s.save()
}

// Reset clears a user's passkeys and issues a fresh invite token.
func (s *UserStore) Reset(id string) (inviteToken string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(id)
	if u == nil {
		return "", fmt.Errorf("user %q not found", id)
	}
	tok, err := randomToken()
	if err != nil {
		return "", err
	}
	u.Credentials = nil
	u.InviteToken = tok
	u.InviteExpires = time.Now().Add(inviteTTL)
	// Clearing passkeys is a security action — revoke any live sessions too.
	u.SessionEpoch++
	if err := s.save(); err != nil {
		return "", err
	}
	return tok, nil
}

// FindByInvite returns the user holding a matching, unexpired invite token.
func (s *UserStore) FindByInvite(token string) *User {
	if token == "" {
		return nil
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.InviteActive(now) && subtle.ConstantTimeCompare([]byte(u.InviteToken), []byte(token)) == 1 {
			return cloneUser(u)
		}
	}
	return nil
}

// AddCredential appends a passkey to a user and consumes any pending invite.
func (s *UserStore) AddCredential(userID string, c StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(userID)
	if u == nil {
		return fmt.Errorf("user %q not found", userID)
	}
	u.Credentials = append(u.Credentials, c)
	u.InviteToken = ""
	u.InviteExpires = time.Time{}
	return s.save()
}

// RemoveCredential deletes a passkey from a user. It won't remove the last
// passkey of the last admin (which would lock everyone out).
func (s *UserStore) RemoveCredential(userID string, credID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(userID)
	if u == nil {
		return fmt.Errorf("user %q not found", userID)
	}
	if u.IsAdmin() && len(u.Credentials) <= 1 && s.adminCountLocked() <= 1 {
		return fmt.Errorf("cannot remove the last admin's last passkey")
	}
	kept := u.Credentials[:0]
	for _, c := range u.Credentials {
		if !bytes.Equal(c.ID, credID) {
			kept = append(kept, c)
		}
	}
	u.Credentials = kept
	return s.save()
}

// FindByCredentialID returns the user who owns the given credential (for
// usernameless/discoverable login).
func (s *UserStore) FindByCredentialID(credID []byte) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		for _, c := range u.Credentials {
			if bytes.Equal(c.ID, credID) {
				return cloneUser(u)
			}
		}
	}
	return nil
}

// UpdateSignCount records a credential's sign count and last-used time.
func (s *UserStore) UpdateSignCount(userID string, credID []byte, count uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.getLocked(userID)
	if u == nil {
		return
	}
	for i := range u.Credentials {
		if bytes.Equal(u.Credentials[i].ID, credID) {
			u.Credentials[i].SignCount = count
			u.Credentials[i].LastUsedAt = time.Now()
			_ = s.save()
			return
		}
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func cloneUser(u *User) *User {
	cp := *u
	cp.Credentials = append([]StoredCredential(nil), u.Credentials...)
	return &cp
}

func sortUsers(users []*User) {
	// admins first, then by ID
	for i := 1; i < len(users); i++ {
		for j := i; j > 0; j-- {
			a, b := users[j-1], users[j]
			less := (a.IsAdmin() && !b.IsAdmin()) || (a.IsAdmin() == b.IsAdmin() && a.ID < b.ID)
			if less {
				break
			}
			users[j-1], users[j] = users[j], users[j-1]
		}
	}
}
