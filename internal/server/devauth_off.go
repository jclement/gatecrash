//go:build !dev

package server

import "net/http"

// The dev auth/self-signed bypass only compiles when the "dev" build tag is
// passed to `go build`. Release builds (goreleaser, `mise run build`) never set
// it, so every method below is a no-op the compiler can inline away, and none of
// the actual bypass logic (devauth_on.go) exists in a shipped binary.

// devNoAuth reports whether the admin panel auth bypass is active. Always false
// in release builds.
func (s *Server) devNoAuth() bool { return false }

// devSelfSigned reports whether the server should serve a self-signed
// certificate instead of obtaining ACME certificates. Always false in release
// builds.
func (s *Server) devSelfSigned() bool { return false }

// devSeedAdmin is a no-op in release builds.
func (s *Server) devSeedAdmin() {}

// devEnsureSession is a no-op in release builds. It reports whether a dev
// session was established for the request (always false here).
func (s *Server) devEnsureSession(http.ResponseWriter, *http.Request) bool { return false }
