//go:build dev

package admin

// DevAdminID is the fixed, stable ID of the auto-provisioned dev admin used by
// the local no-auth dev mode. It is a constant so sessions and CSRF tokens stay
// stable across restarts. This file only compiles under the "dev" build tag, so
// it can never exist in a released binary.
const DevAdminID = "dev-admin"

// EnsureDevAdmin makes sure a passkey-less admin with DevAdminID exists, so the
// no-auth dev bypass has a real directory record to bind sessions to. It is
// idempotent and dev-build-only.
func (s *UserStore) EnsureDevAdmin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.getLocked(DevAdminID); u != nil {
		if u.Role != RoleAdmin {
			u.Role = RoleAdmin
			return s.save()
		}
		return nil
	}
	s.users = append(s.users, &User{
		ID:   DevAdminID,
		Name: "dev",
		Role: RoleAdmin,
	})
	return s.save()
}
