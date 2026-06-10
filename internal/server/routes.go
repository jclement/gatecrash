package server

import "net/http"

// setupAdminRoutes registers the admin panel HTTP handlers.
func (s *Server) setupAdminRoutes() {
	// Static files — always public
	s.adminMux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.staticFS)))

	// Health check — always public
	s.adminMux.HandleFunc("GET /health", s.handleHealth)

	// Auth pages — public
	s.adminMux.HandleFunc("GET /login", s.handleLogin)
	// Login ceremony (usernameless/discoverable) — public
	s.adminMux.HandleFunc("POST /auth/login/begin", rateLimit(s.authLimiter, s.handleLoginBegin))
	s.adminMux.HandleFunc("POST /auth/login/finish", rateLimit(s.authLimiter, s.handleLoginFinish))
	// The first admin is bootstrapped via an invite link printed to the logs /
	// config file at startup (see writeBootstrapInvite) — there is no open
	// first-login page to race. Invite-based passkey registration — token-gated.
	s.adminMux.HandleFunc("GET /invite/{token}", s.handleInvitePage)
	s.adminMux.HandleFunc("POST /invite/{token}/begin", rateLimit(s.authLimiter, s.handleInviteBegin))
	s.adminMux.HandleFunc("POST /invite/{token}/finish", rateLimit(s.authLimiter, s.handleInviteFinish))
	// Add a passkey to your own account (logged-in)
	s.adminMux.HandleFunc("POST /auth/register/begin", rateLimit(s.authLimiter, s.requireAuth(s.handleRegisterBegin)))
	s.adminMux.HandleFunc("POST /auth/register/finish", rateLimit(s.authLimiter, s.requireAuth(s.handleRegisterFinish)))
	// Cross-host tunnel login handoff. Not behind requireAuth: when signed out it
	// renders the bespoke "service protected" sign-in page itself (then reloads to
	// mint the handoff token once authenticated).
	s.adminMux.HandleFunc("GET /tunnel-login", s.handleTunnelLogin)
	s.adminMux.HandleFunc("POST /logout", s.handleLogout)

	// Any logged-in user
	s.adminMux.HandleFunc("GET /passkeys", s.requireAuth(s.handlePasskeys))
	s.adminMux.HandleFunc("POST /api/passkeys/delete", s.requireCSRF(s.handleDeletePasskey))
	s.adminMux.HandleFunc("GET /api/session/keepalive", s.handleSessionKeepalive)

	// Admin only
	s.adminMux.HandleFunc("GET /", s.requireAuth(s.handleRoot))
	s.adminMux.HandleFunc("GET /help", s.requireAdmin(s.handleHelp))
	s.adminMux.HandleFunc("GET /authorize-ip", s.requireAdmin(s.handleAuthorizeIPPage))
	s.adminMux.HandleFunc("POST /authorize-ip", s.requireAdmin(s.handleAuthorizeIPSubmit))
	s.adminMux.HandleFunc("GET /api/bandwidth", s.requireAdminAPI(s.handleAPIBandwidth))
	s.adminMux.HandleFunc("GET /api/tunnels", s.requireAdminAPI(s.handleAPITunnels))
	s.adminMux.HandleFunc("GET /api/tunnels/html", s.requireAdminAPI(s.handleAPITunnelsHTML))
	s.adminMux.HandleFunc("GET /api/redirects/html", s.requireAdminAPI(s.handleAPIRedirectsHTML))
	s.adminMux.HandleFunc("POST /api/tunnels", s.requireAdminCSRF(s.handleCreateTunnel))
	s.adminMux.HandleFunc("PUT /api/tunnels/{id}", s.requireAdminCSRF(s.handleEditTunnel))
	s.adminMux.HandleFunc("DELETE /api/tunnels/{id}", s.requireAdminCSRF(s.handleDeleteTunnel))
	s.adminMux.HandleFunc("POST /api/tunnels/{id}/regenerate", s.requireAdminCSRF(s.handleRegenerateSecret))
	s.adminMux.HandleFunc("POST /api/tunnels/{id}/test", s.requireAdminCSRF(s.handleTunnelTest))
	// Users (admin)
	s.adminMux.HandleFunc("GET /users", s.requireAdmin(s.handleUsersPage))
	s.adminMux.HandleFunc("GET /api/users", s.requireAdminAPI(s.handleListUsers))
	s.adminMux.HandleFunc("POST /api/users", s.requireAdminCSRF(s.handleCreateUser))
	s.adminMux.HandleFunc("DELETE /api/users/{id}", s.requireAdminCSRF(s.handleDeleteUser))
	s.adminMux.HandleFunc("POST /api/users/{id}/reset", s.requireAdminCSRF(s.handleResetUser))
	s.adminMux.HandleFunc("POST /api/users/{id}/role", s.requireAdminCSRF(s.handleSetUserRole))
	s.adminMux.HandleFunc("POST /api/users/{id}/rename", s.requireAdminCSRF(s.handleRenameUser))
	// Access policies (admin)
	s.adminMux.HandleFunc("GET /access-policies", s.requireAdmin(s.handleAccessPoliciesPage))
	s.adminMux.HandleFunc("GET /api/ip-policies", s.requireAdminAPI(s.handleListIPPolicies))
	s.adminMux.HandleFunc("POST /api/ip-policies", s.requireAdminCSRF(s.handleSaveIPPolicy))
	s.adminMux.HandleFunc("DELETE /api/ip-policies/{id}", s.requireAdminCSRF(s.handleDeleteIPPolicy))
	s.adminMux.HandleFunc("GET /api/ip-policies/{id}/ips", s.requireAdminAPI(s.handleListPolicyIPs))
	s.adminMux.HandleFunc("DELETE /api/ip-policies/{id}/ips/{ip}", s.requireAdminCSRF(s.handleRevokePolicyIP))
	s.adminMux.HandleFunc("POST /api/ip-policies/{id}/enroll-token", s.requireAdminCSRF(s.handleRotateEnrollToken))
	s.adminMux.HandleFunc("DELETE /api/ip-policies/{id}/enroll-token", s.requireAdminCSRF(s.handleDeleteEnrollToken))
	s.adminMux.HandleFunc("GET /api/auth-policies", s.requireAdminAPI(s.handleListAuthPolicies))
	s.adminMux.HandleFunc("POST /api/auth-policies", s.requireAdminCSRF(s.handleSaveAuthPolicy))
	s.adminMux.HandleFunc("DELETE /api/auth-policies/{id}", s.requireAdminCSRF(s.handleDeleteAuthPolicy))
	// Public, unauthenticated, rate-limited self-service enrollment link.
	s.adminMux.HandleFunc("GET /enroll/{token}", rateLimit(s.authLimiter, s.handleEnrollPage))
	s.adminMux.HandleFunc("POST /enroll/{token}", rateLimit(s.authLimiter, s.handleEnrollSubmit))
	s.adminMux.HandleFunc("POST /api/redirects", s.requireAdminCSRF(s.handleCreateRedirect))
	s.adminMux.HandleFunc("PUT /api/redirects/{from}", s.requireAdminCSRF(s.handleEditRedirect))
	s.adminMux.HandleFunc("DELETE /api/redirects/{from}", s.requireAdminCSRF(s.handleDeleteRedirect))
	// Audit log (admin)
	s.adminMux.HandleFunc("GET /auditlog", s.requireAdmin(s.handleAuditLogPage))
	s.adminMux.HandleFunc("GET /api/auditlog", s.requireAdminAPI(s.handleAPIAuditLog))

	s.adminMux.HandleFunc("GET /api/update", s.requireAdminAPI(s.handleGetUpdate))
	s.adminMux.HandleFunc("POST /api/update", s.requireAdminCSRF(s.handlePostUpdate))
	s.adminMux.HandleFunc("GET /api/events", s.requireAdminAPI(s.sse.ServeHTTP))
}
