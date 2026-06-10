package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	ssh "github.com/gliderlabs/ssh"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/internal/config"
	"github.com/jclement/gatecrash/internal/token"
	"github.com/jclement/gatecrash/internal/update"
	"github.com/jclement/gatecrash/web"
)

// Server is the main gatecrash server orchestrator.
type Server struct {
	cfg             *config.Config
	configPath      string
	version         string
	registry        *Registry
	sshServer       *ssh.Server
	adminMux        *http.ServeMux
	tlsConfig       *tls.Config
	sse             *SSEBroadcaster
	staticFS        fs.FS  // embedded or disk-based static assets
	hostFingerprint string // SSH host key fingerprint (SHA256)

	// Config mutation lock — protects s.cfg reads/writes from admin API and config reload
	cfgMu sync.RWMutex

	// TCP listener management
	tcpMu        sync.Mutex
	tcpListeners map[int]net.Listener // port → listener

	// Update state
	updateMu     sync.RWMutex
	updateResult *update.CheckResult

	// Bandwidth history
	bwTracker *bandwidthTracker

	// Rate limiter for HTTP auth endpoints
	authLimiter *ipRateLimiter

	// SSH auth abuse protection: a per-IP attempt limiter plus a semaphore that
	// bounds concurrent bcrypt evaluations (each tunnel-token check is a cost-12
	// bcrypt), so a flood of attempts can't pin every core.
	sshAuthLimiter        *ipRateLimiter
	bcryptSem             chan struct{}
	sshAuthAcquireTimeout time.Duration

	// Per-IP limiter for tunnel HTTP Basic auth attempts, so a password-protected
	// tunnel can't be flooded with bad credentials (each is a cost-12 bcrypt).
	tunnelAuthLimiter *ipRateLimiter

	// Auth components
	users         *admin.UserStore
	sessionMgr    *admin.SessionManager
	webauthn      *admin.WebAuthnHandler
	adminH        *admin.Handlers
	auditLog      *admin.AuditLog
	tunnelSession *admin.TunnelSession

	// Path to the one-time first-admin invite file, removed once setup completes.
	bootstrapInvitePath string

	// Self-service IP allowlist grants (TTL'd), persisted to ip_allowlist.json.
	ipAllow *IPAllowStore

	// Pending tunnel-login handoff tokens. After a user signs in on the admin
	// host, a one-time token is parked here and the browser is redirected to the
	// tunnel hostname to establish its session.
	pendingTunnelAuthMu sync.Mutex
	pendingTunnelAuth   map[string]*pendingTunnelAuthResult
}

// pendingTunnelAuthResult holds an authenticated user's identity for a one-time
// cross-host login handoff.
type pendingTunnelAuthResult struct {
	userID    string
	role      string
	hostname  string
	returnURL string
	expires   time.Time
}

// runIPAllowCleanup periodically prunes expired self-service IP grants.
func (s *Server) runIPAllowCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ipAllow.pruneExpired()
		}
	}
}

// specFromConfig maps a config tunnel into the registry's TunnelSpec.
func specFromConfig(tc config.Tunnel) TunnelSpec {
	return TunnelSpec{
		ID:             tc.ID,
		Type:           tc.Type,
		Hostnames:      tc.Hostnames,
		ListenPort:     tc.ListenPort,
		PreserveHost:   tc.PreserveHost,
		TLSPassthrough: tc.TLSPassthrough,
		IPPolicyID:     tc.IPPolicy,
		AuthPolicyID:   tc.AuthPolicy,
	}
}

// policiesFromConfig builds runtime policy states from config.
func policiesFromConfig(cfg *config.Config) ([]*IPPolicyState, []*AuthPolicyState) {
	ip := make([]*IPPolicyState, 0, len(cfg.IPPolicy))
	for _, p := range cfg.IPPolicy {
		ip = append(ip, newIPPolicyState(p))
	}
	auth := make([]*AuthPolicyState, 0, len(cfg.AuthPolicy))
	for _, p := range cfg.AuthPolicy {
		auth = append(auth, newAuthPolicyState(p))
	}
	return ip, auth
}

// New creates a new server instance.
func New(cfg *config.Config, configPath, version string) *Server {
	return &Server{
		cfg:               cfg,
		configPath:        configPath,
		version:           version,
		registry:          NewRegistry(),
		adminMux:          http.NewServeMux(),
		sse:               NewSSEBroadcaster(),
		pendingTunnelAuth: make(map[string]*pendingTunnelAuthResult),
		bwTracker:         newBandwidthTracker(120), // ~4 min at 2s intervals
		authLimiter:       newIPRateLimiter(20, time.Minute),

		// Per-IP cap is generous (legit clients behind one NAT may reconnect
		// together); the semaphore is what actually bounds CPU.
		sshAuthLimiter:        newIPRateLimiter(30, time.Minute),
		bcryptSem:             make(chan struct{}, max(2, runtime.NumCPU())),
		sshAuthAcquireTimeout: 3 * time.Second,
		tunnelAuthLimiter:     newIPRateLimiter(30, time.Minute),
	}
}

// Run starts all server components and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	// IP allowlist grant store (used for enforcement on HTTP and TCP tunnels;
	// always initialized so enforcement works even without the admin panel).
	ipAllow, err := NewIPAllowStore(filepath.Join(filepath.Dir(s.configPath), "ip_allowlist.json"))
	if err != nil {
		return fmt.Errorf("ip allowlist store: %w", err)
	}
	s.ipAllow = ipAllow
	go s.runIPAllowCleanup(ctx)

	// Load access policies into the registry.
	s.registry.SetPolicies(policiesFromConfig(s.cfg))

	// Build tunnel registry from config
	for _, tc := range s.cfg.Tunnel {
		s.registry.Register(newTunnelState(specFromConfig(tc)))

		hasSecret := tc.SecretHash != ""
		slog.Info("registered tunnel",
			"id", tc.ID,
			"type", tc.Type,
			"has_secret", hasSecret,
		)
	}

	// Setup SSH server
	sshSrv, err := s.newSSHServer()
	if err != nil {
		return fmt.Errorf("SSH server: %w", err)
	}
	s.sshServer = sshSrv

	// Reject configs with unenforceable access-control combinations.
	if err := s.cfg.Validate(); err != nil {
		return err
	}

	// Setup admin panel — enabled only when admin_host is configured
	if s.cfg.Server.AdminHost != "" {
		if err := s.initAdmin(); err != nil {
			return fmt.Errorf("admin init: %w", err)
		}
		s.setupAdminRoutes()
		slog.Info("admin panel enabled", "hostname", s.cfg.Server.AdminHost)
	} else {
		slog.Info("admin panel disabled (set server.admin_host in config to enable)")
	}

	// Setup TLS (ACME for configured hostnames, self-signed fallback)
	tlsConfig, err := s.setupTLS()
	if err != nil {
		return fmt.Errorf("TLS setup: %w", err)
	}
	s.tlsConfig = tlsConfig

	// Start TCP forward listeners
	for _, t := range s.registry.AllTunnels() {
		if t.TunnelType() == "tcp" && t.Port() > 0 {
			if err := s.serveTCPForward(t); err != nil {
				return fmt.Errorf("TCP forward for %s: %w", t.ID, err)
			}
		}
	}

	// Start config file watcher
	watcher := config.NewWatcher(s.configPath)
	go watcher.Start()
	defer watcher.Stop()

	// Start periodic update checker
	if s.cfg.Update.Enabled && s.version != "dev" && !update.IsDocker() {
		go s.runUpdateChecker(s.cfg.Update.GitHubRepo, s.cfg.CheckIntervalDuration())
	}

	// Start bandwidth sampler
	go s.runBandwidthSampler(ctx)

	// Cleanup expired pending tunnel auth tokens
	go s.cleanupPendingTunnelAuth(ctx)

	// errCh collects fatal listener errors from the goroutines below.
	errCh := make(chan error, 3)

	// Start SSH server. Use an explicit keepalive-enabling listener instead of
	// ListenAndServe so accepted tunnel connections get OS-level TCP keepalives —
	// gliderlabs does not enable them, leaving half-open clients undetected.
	go func() {
		slog.Info("SSH server listening", "addr", sshSrv.Addr)
		ln, err := net.Listen("tcp", sshSrv.Addr)
		if err != nil {
			slog.Error("SSH listen failed", "addr", sshSrv.Addr, "error", err)
			errCh <- fmt.Errorf("SSH listen: %w", err)
			return
		}
		kal := keepAliveListener{TCPListener: ln.(*net.TCPListener), period: 30 * time.Second}
		if err := sshSrv.Serve(kal); err != nil && err != ssh.ErrServerClosed {
			slog.Error("SSH server error", "error", err)
		}
	}()

	// Start HTTPS listener
	go func() {
		httpsAddr := fmt.Sprintf("%s:%d", s.cfg.Server.BindAddr, s.cfg.Server.HTTPSPort)
		rawListener, err := net.Listen("tcp", httpsAddr)
		if err != nil {
			errCh <- fmt.Errorf("HTTPS listen: %w", err)
			return
		}
		listener := s.newSNIListener(rawListener)
		slog.Info("HTTPS server listening", "addr", httpsAddr)
		// ReadHeaderTimeout bounds slow-loris attacks that trickle request headers
		// to pin connections; IdleTimeout reaps idle keep-alive conns. We do NOT
		// set ReadTimeout/WriteTimeout: those would sever long-lived WebSocket and
		// streamed responses (and legitimately idle connections).
		srv := &http.Server{
			Handler:           s,
			ReadHeaderTimeout: 20 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		errCh <- srv.Serve(listener)
	}()

	// Optional HTTP→HTTPS redirect listener
	if s.cfg.Server.HTTPPort > 0 {
		go func() {
			httpAddr := fmt.Sprintf("%s:%d", s.cfg.Server.BindAddr, s.cfg.Server.HTTPPort)
			slog.Info("HTTP server listening (redirect to HTTPS)", "addr", httpAddr)
			redirectSrv := &http.Server{
				Addr:              httpAddr,
				Handler:           http.HandlerFunc(s.httpToHTTPSRedirect),
				ReadHeaderTimeout: 20 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			errCh <- redirectSrv.ListenAndServe()
		}()
	}

	// Wait for shutdown signal or config changes
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	for {
		select {
		case sig := <-sigCh:
			slog.Info("received signal, shutting down", "signal", sig)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s.sshServer.Shutdown(shutdownCtx)
			return nil
		case err := <-errCh:
			return fmt.Errorf("server error: %w", err)
		case <-ctx.Done():
			slog.Info("context cancelled, shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s.sshServer.Shutdown(shutdownCtx)
			return nil
		case newCfg := <-watcher.OnChange():
			s.handleConfigReload(newCfg)
		case err := <-watcher.OnError():
			slog.Error("config error (keeping old config)", "error", err)
			s.sse.Broadcast("config-error", err.Error())
		}
	}
}

// initAdmin initializes the admin panel components (users, sessions, WebAuthn, templates).
func (s *Server) initAdmin() error {
	dataDir := filepath.Dir(s.configPath)

	// User directory
	users, err := admin.NewUserStore(filepath.Join(dataDir, "users.json"))
	if err != nil {
		return fmt.Errorf("user store: %w", err)
	}
	s.users = users

	// Session manager
	s.sessionMgr = admin.NewSessionManager(s.cfg.Server.Secret)

	// Audit log
	auditLog, err := admin.NewAuditLog(filepath.Join(dataDir, "audit.json"))
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	s.auditLog = auditLog

	// Per-hostname tunnel session manager (cross-host login handoff)
	s.tunnelSession = admin.NewTunnelSession(s.cfg.Server.Secret)

	// WebAuthn - determine rpID and origin from admin_host
	rpID := s.cfg.Server.AdminHost
	rpOrigin := "https://" + s.cfg.Server.AdminHost
	if s.cfg.Server.HTTPSPort != 443 {
		rpOrigin = fmt.Sprintf("https://%s:%d", s.cfg.Server.AdminHost, s.cfg.Server.HTTPSPort)
	}
	wah, err := admin.NewWebAuthnHandler(rpID, rpOrigin, users)
	if err != nil {
		return fmt.Errorf("WebAuthn: %w", err)
	}
	s.webauthn = wah

	// Template and static file systems — embedded in production, disk in dev for hot reload
	var tmplFS fs.FS
	if s.version == "dev" {
		tmplFS = os.DirFS("web/templates")
		s.staticFS = os.DirFS("web/static")
	} else {
		var err2 error
		tmplFS, err2 = fs.Sub(web.EmbeddedFS, "templates")
		if err2 != nil {
			return fmt.Errorf("embedded templates: %w", err2)
		}
		s.staticFS, err2 = fs.Sub(web.EmbeddedFS, "static")
		if err2 != nil {
			return fmt.Errorf("embedded static: %w", err2)
		}
	}

	ah, err := admin.NewHandlers(s.version, s.cfg.CheckIntervalDuration(), tmplFS)
	if err != nil {
		return fmt.Errorf("admin handlers: %w", err)
	}
	s.adminH = ah

	// Bootstrap the first admin via a one-time invite link written to the config
	// dir and logged — no open first-login page to race on a public box.
	s.writeBootstrapInvite(dataDir)

	slog.Info("admin panel initialized", "rpID", rpID)
	return nil
}

// writeBootstrapInvite ensures a first-admin invite exists (until one admin has a
// passkey), writing it to bootstrap-invite.txt (0600) and logging it. It needs
// admin_host configured to build a usable URL. Idempotent across restarts.
func (s *Server) writeBootstrapInvite(dataDir string) {
	s.bootstrapInvitePath = filepath.Join(dataDir, "bootstrap-invite.txt")
	if s.cfg.Server.AdminHost == "" {
		return // no admin panel host yet; nothing to link to
	}
	token, err := s.users.BootstrapInvite()
	if err != nil {
		slog.Error("failed to prepare bootstrap invite", "error", err)
		return
	}
	if token == "" {
		s.clearBootstrapInviteFile() // already initialized; clear any stale file
		return
	}
	link := s.inviteURL(token)
	content := fmt.Sprintf("Gatecrash — first-admin setup link (one-time use):\n\n%s\n\nOpen it to register your admin passkey. This file is removed automatically once the link is used.\n", link)
	if err := os.WriteFile(s.bootstrapInvitePath, []byte(content), 0o600); err != nil {
		slog.Error("failed to write bootstrap invite file", "error", err)
	}
	slog.Warn("ADMIN SETUP REQUIRED — open this one-time link to create the first admin",
		"url", link, "file", s.bootstrapInvitePath)
}

// clearBootstrapInviteFile removes the on-disk bootstrap invite (best effort).
func (s *Server) clearBootstrapInviteFile() {
	if s.bootstrapInvitePath == "" {
		return
	}
	if err := os.Remove(s.bootstrapInvitePath); err != nil && !os.IsNotExist(err) {
		slog.Warn("could not remove bootstrap invite file", "error", err)
	}
}

// actorName resolves the current session's display label for audit entries,
// falling back to the raw session id if the user can't be resolved.
func (s *Server) actorName(r *http.Request) string {
	if u := s.sessionUser(r); u != nil {
		return u.Name
	}
	return s.sessionMgr.GetActor(r)
}

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
	// Cross-host tunnel login handoff (any logged-in user)
	s.adminMux.HandleFunc("GET /tunnel-login", s.requireAuth(s.handleTunnelLogin))
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

// sessionUser returns the live directory record for the request's session, or
// nil if there's no valid session or the user no longer exists. Looking the user
// up (rather than trusting the JWT) makes deletes and role changes take effect
// immediately, not at session expiry.
func (s *Server) sessionUser(r *http.Request) *admin.User {
	if !s.sessionMgr.ValidateSession(r) {
		return nil
	}
	return s.users.Get(s.sessionMgr.UserID(r))
}

// requireAuth wraps a page handler: any logged-in user. On first boot (no admin
// yet) it shows the not-initialized notice; otherwise it redirects to login,
// preserving the destination.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.webauthn.NeedsSetup() {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if s.sessionUser(r) == nil {
			s.sessionMgr.ClearSession(w)
			loginURL := "/login"
			if ret := r.URL.RequestURI(); ret != "/" && isSafeReturnURL(ret) {
				loginURL = "/login?return=" + url.QueryEscape(ret)
			}
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireAdmin wraps a page handler: must be a logged-in admin (verified live).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if u := s.sessionUser(r); u == nil || !u.IsAdmin() {
			s.serveErrorPage(w, r, http.StatusForbidden, "Admin Only",
				"You don't have access to this page.")
			return
		}
		next(w, r)
	})
}

// requireAuthAPI wraps an API handler: any logged-in user, 401 JSON otherwise.
func (s *Server) requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessionUser(r) == nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requireAdminAPI wraps an API handler: must be a logged-in admin (verified live).
func (s *Server) requireAdminAPI(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuthAPI(func(w http.ResponseWriter, r *http.Request) {
		if u := s.sessionUser(r); u == nil || !u.IsAdmin() {
			http.Error(w, `{"error":"admin only"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// requireCSRF wraps a mutating API handler: logged-in user + valid CSRF token.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuthAPI(func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionMgr.ValidCSRFToken(r, r.Header.Get("X-CSRF-Token")) {
			http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// requireAdminCSRF wraps a mutating admin API handler: admin (verified live) + CSRF.
func (s *Server) requireAdminCSRF(next http.HandlerFunc) http.HandlerFunc {
	return s.requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if u := s.sessionUser(r); u == nil || !u.IsAdmin() {
			http.Error(w, `{"error":"admin only"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// handleLogin renders the usernameless passkey login page. Before the first
// admin exists it shows a not-initialized notice instead (the operator claims
// the first admin via the bootstrap invite link from the logs / config file).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.webauthn.NeedsSetup() {
		s.adminH.Render(w, "pages/login.html", &admin.PageData{
			Title: "Not initialized",
			Data:  struct{ NeedsSetup bool }{NeedsSetup: true},
		})
		return
	}
	if s.sessionMgr.ValidateSession(r) {
		if ret := r.URL.Query().Get("return"); ret != "" && isSafeReturnURL(ret) {
			http.Redirect(w, r, ret, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.landingFor(r), http.StatusSeeOther)
		return
	}
	s.adminH.Render(w, "pages/login.html", &admin.PageData{Title: "Sign in"})
}

// landingFor returns where to send a user after login: dashboard for admins,
// their passkey page for regular users.
func (s *Server) landingFor(r *http.Request) string {
	if s.sessionMgr.IsAdmin(r) {
		return "/"
	}
	return "/passkeys"
}

// handlePasskeys renders the current user's passkey-management page.
func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	u := s.users.Get(s.sessionMgr.UserID(r))
	if u == nil {
		s.sessionMgr.ClearSession(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	passkeys := make([]admin.PasskeyView, len(u.Credentials))
	for i, c := range u.Credentials {
		passkeys[i] = admin.PasskeyView{
			Name:       c.Name,
			CreatedAt:  c.CreatedAt.Format("Jan 2, 2006"),
			LastUsedAt: c.LastUsedAt.Format("Jan 2, 2006"),
			IDB64:      base64.RawURLEncoding.EncodeToString(c.ID),
		}
	}
	s.adminH.Render(w, "pages/passkeys.html", &admin.PageData{
		Title:     "Passkeys",
		Active:    "passkeys",
		UserID:    u.ID,
		Name:      u.Name,
		IsAdmin:   u.IsAdmin(),
		CSRFToken: s.sessionMgr.CSRFToken(r),
		Data: struct {
			Passkeys  []admin.PasskeyView
			CanDelete bool
		}{Passkeys: passkeys, CanDelete: len(u.Credentials) > 1},
	})
}

// handleDeletePasskey removes one of the current user's passkeys.
func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(req.ID)
	if err != nil {
		http.Error(w, "invalid credential ID", http.StatusBadRequest)
		return
	}
	if err := s.users.RemoveCredential(s.sessionMgr.UserID(r), credID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout clears the session and redirects to login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.sessionMgr.ValidCSRFToken(r, r.FormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	s.sessionMgr.ClearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// RedirectView is the template data for a single redirect row.
type RedirectView struct {
	From         string
	To           string
	PreservePath bool
	CertValid    bool
	CertExpiry   string
	CertError    string
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	adminHost := s.cfg.Server.AdminHost
	sshAddr := fmt.Sprintf("%s:%d", adminHost, s.cfg.Server.SSHPort)
	s.cfgMu.RUnlock()
	s.adminH.Render(w, "pages/help.html", &admin.PageData{
		Title:   "Help",
		Active:  "help",
		UserID:  s.sessionMgr.UserID(r),
		IsAdmin: true,
		Data: struct {
			SSHAddr     string
			Fingerprint string
			AdminHost   string
		}{
			SSHAddr:     sshAddr,
			Fingerprint: s.hostFingerprint,
			AdminHost:   adminHost,
		},
	})
}

// handleRoot serves the admin dashboard to admins. Non-admins have no dashboard,
// so for now they're sent to their passkey page (a friendlier "no access"
// landing will replace the redirect later).
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if u := s.sessionUser(r); u == nil || !u.IsAdmin() {
		http.Redirect(w, r, "/passkeys", http.StatusSeeOther)
		return
	}
	s.handleAdminDashboard(w, r)
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	tunnels := s.buildTunnelViews()
	redirects := s.buildRedirectViews()

	s.adminH.Render(w, "pages/dashboard.html", &admin.PageData{
		Title:     "Dashboard",
		Active:    "dashboard",
		CSRFToken: s.sessionMgr.CSRFToken(r),
		UserID:    s.sessionMgr.UserID(r),
		IsAdmin:   true,
		Data: struct {
			Tunnels   []admin.TunnelView
			Redirects []RedirectView
			SSHPort   int
		}{
			Tunnels:   tunnels,
			Redirects: redirects,
			SSHPort:   s.cfg.Server.SSHPort,
		},
	})
}

func (s *Server) handleAPITunnelsHTML(w http.ResponseWriter, r *http.Request) {
	tunnels := s.buildTunnelViews()
	s.adminH.RenderPartial(w, "pages/dashboard.html", "tunnel-rows", tunnels)
}

func (s *Server) handleAPIRedirectsHTML(w http.ResponseWriter, r *http.Request) {
	redirects := s.buildRedirectViews()
	s.adminH.RenderPartial(w, "pages/dashboard.html", "redirect-rows", redirects)
}

func (s *Server) buildTunnelViews() []admin.TunnelView {
	tunnels := s.registry.AllTunnels()
	views := make([]admin.TunnelView, len(tunnels))
	for i, t := range tunnels {
		hostnames := t.HostnameList()
		var hostCerts []admin.HostCert
		for _, h := range hostnames {
			ci := s.getCertInfo(h)
			hc := admin.HostCert{Hostname: h, Valid: ci.valid, Error: ci.err}
			if !ci.expiry.IsZero() {
				hc.Expiry = ci.expiry.Format("Jan 2, 2006")
			}
			hostCerts = append(hostCerts, hc)
		}
		views[i] = admin.TunnelView{
			ID:             t.ID,
			Type:           t.TunnelType(),
			Hostnames:      hostnames,
			ListenPort:     t.Port(),
			PreserveHost:   t.PreservesHost(),
			TLSPassthrough: t.IsTLSPassthrough(),
			IPPolicy:       t.IPPolicy(),
			AuthPolicy:     t.AuthPolicy(),
			Connected:      t.IsConnected(),
			ClientCount:    t.ClientCount(),
			Clients:        buildClientViews(t),
			Requests:       t.Metrics.RequestCount.Load(),
			BytesIn:        t.Metrics.BytesIn.Load(),
			BytesOut:       t.Metrics.BytesOut.Load(),
			ActiveConns:    int32(t.Metrics.ActiveConns.Load()),
			HostCerts:      hostCerts,
			ServerVersion:  strings.TrimPrefix(s.version, "v"),
		}
	}
	return views
}

func buildClientViews(t *TunnelState) []admin.ClientView {
	infos := t.ClientInfos()
	views := make([]admin.ClientView, len(infos))
	for i, info := range infos {
		views[i] = admin.ClientView{
			Addr:    info.Addr,
			Uptime:  admin.FormatUptime(info.ConnectedAt),
			Version: info.Version,
		}
	}
	return views
}

func (s *Server) buildRedirectViews() []RedirectView {
	s.cfgMu.RLock()
	redirects := s.cfg.Redirect
	s.cfgMu.RUnlock()

	views := make([]RedirectView, len(redirects))
	for i, r := range redirects {
		ci := s.getCertInfo(r.From)
		rv := RedirectView{
			From:         r.From,
			To:           r.To,
			PreservePath: r.PreservePath,
			CertValid:    ci.valid,
			CertError:    ci.err,
		}
		if !ci.expiry.IsZero() {
			rv.CertExpiry = ci.expiry.Format("Jan 2, 2006")
		}
		views[i] = rv
	}
	return views
}

// --- Tunnel CRUD ---

var tunnelIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type tunnelRequest struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	Hostnames      []string `json:"hostnames"`
	ListenPort     int      `json:"listen_port"`
	PreserveHost   bool     `json:"preserve_host"`
	TLSPassthrough bool     `json:"tls_passthrough"`
	IPPolicy       string   `json:"ip_policy"`
	AuthPolicy     string   `json:"auth_policy"`
}

func (s *Server) validateTunnel(req tunnelRequest, excludeID string) error {
	if req.ID == "" || !tunnelIDPattern.MatchString(req.ID) {
		return fmt.Errorf("invalid tunnel ID: must be lowercase alphanumeric with hyphens")
	}
	if req.Type != "http" && req.Type != "tcp" {
		return fmt.Errorf("type must be \"http\" or \"tcp\"")
	}
	if req.Type == "http" && len(req.Hostnames) == 0 {
		return fmt.Errorf("HTTP tunnels require at least one hostname")
	}
	if req.Type == "tcp" && req.ListenPort <= 0 {
		return fmt.Errorf("TCP tunnels require a listen_port > 0")
	}
	if req.IPPolicy != "" && s.registry.FindIPPolicy(req.IPPolicy) == nil {
		return fmt.Errorf("unknown ip_policy %q", req.IPPolicy)
	}
	if req.AuthPolicy != "" {
		if s.registry.FindAuthPolicy(req.AuthPolicy) == nil {
			return fmt.Errorf("unknown auth_policy %q", req.AuthPolicy)
		}
		if req.Type == "tcp" {
			return fmt.Errorf("auth_policy is not supported on TCP tunnels")
		}
		if req.TLSPassthrough {
			return fmt.Errorf("auth_policy is not supported with TLS passthrough (auth is bypassed at the TLS layer)")
		}
	}

	// Check for conflicts
	for _, t := range s.cfg.Tunnel {
		if t.ID == excludeID {
			continue
		}
		if t.ID == req.ID && excludeID == "" {
			return fmt.Errorf("tunnel ID %q already exists", req.ID)
		}
		if req.Type == "http" {
			for _, h := range req.Hostnames {
				for _, th := range t.Hostnames {
					if strings.EqualFold(h, th) {
						return fmt.Errorf("hostname %q conflicts with tunnel %q", h, t.ID)
					}
				}
			}
		}
		if req.Type == "tcp" && t.Type == "tcp" && req.ListenPort == t.ListenPort {
			return fmt.Errorf("port %d conflicts with tunnel %q", req.ListenPort, t.ID)
		}
	}

	// Check hostname conflicts with admin_host
	if req.Type == "http" && s.cfg.Server.AdminHost != "" {
		for _, h := range req.Hostnames {
			if strings.EqualFold(h, s.cfg.Server.AdminHost) {
				return fmt.Errorf("hostname %q conflicts with admin_host", h)
			}
		}
	}

	// Check port conflicts with SSH port
	if req.Type == "tcp" && req.ListenPort == s.cfg.Server.SSHPort {
		return fmt.Errorf("port %d conflicts with SSH port", req.ListenPort)
	}

	// Check port conflicts with HTTPS and HTTP ports
	if req.Type == "tcp" && req.ListenPort == s.cfg.Server.HTTPSPort {
		return fmt.Errorf("port %d conflicts with HTTPS port", req.ListenPort)
	}
	if req.Type == "tcp" && s.cfg.Server.HTTPPort > 0 && req.ListenPort == s.cfg.Server.HTTPPort {
		return fmt.Errorf("port %d conflicts with HTTP port", req.ListenPort)
	}

	return nil
}

func (s *Server) secretResponse(tunnelID, plaintext string) map[string]string {
	tok := token.FormatToken(tunnelID, plaintext)
	sshAddr := fmt.Sprintf("%s:%d", s.cfg.Server.AdminHost, s.cfg.Server.SSHPort)
	return map[string]string{
		"server":   sshAddr,
		"host_key": s.hostFingerprint,
		"token":    tok,
		"command":  fmt.Sprintf("gatecrash --server %s --host-key %s --token %s --target 127.0.0.1:8000", sshAddr, s.hostFingerprint, tok),
		"docker":   fmt.Sprintf("docker run -e GATECRASH_SERVER=%s -e GATECRASH_HOST_KEY=%s -e GATECRASH_TOKEN=%s -e GATECRASH_TARGET=app:8000 ghcr.io/jclement/gatecrash:latest", sshAddr, s.hostFingerprint, tok),
	}
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	var req tunnelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	if err := s.validateTunnel(req, ""); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	plaintext, hash, err := token.GenerateSecret()
	if err != nil {
		slog.Error("failed to generate secret", "error", err)
		http.Error(w, "failed to generate secret", http.StatusInternalServerError)
		return
	}

	s.cfg.Tunnel = append(s.cfg.Tunnel, config.Tunnel{
		ID:             req.ID,
		Type:           req.Type,
		Hostnames:      req.Hostnames,
		ListenPort:     req.ListenPort,
		SecretHash:     hash,
		PreserveHost:   req.PreserveHost,
		TLSPassthrough: req.TLSPassthrough,
		IPPolicy:       req.IPPolicy,
		AuthPolicy:     req.AuthPolicy,
	})
	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("tunnel created", "id", req.ID, "type", req.Type)
	s.auditLog.Log(s.actorName(r), "tunnel.create", fmt.Sprintf("Created %s tunnel %q", req.Type, req.ID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.secretResponse(req.ID, plaintext))
}

func (s *Server) handleEditTunnel(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.PathValue("id")
	if tunnelID == "" {
		http.Error(w, "missing tunnel ID", http.StatusBadRequest)
		return
	}

	var req tunnelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.ID = tunnelID

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	if err := s.validateTunnel(req, tunnelID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	found := false
	for i := range s.cfg.Tunnel {
		if s.cfg.Tunnel[i].ID == tunnelID {
			s.cfg.Tunnel[i].Type = req.Type
			s.cfg.Tunnel[i].Hostnames = req.Hostnames
			s.cfg.Tunnel[i].ListenPort = req.ListenPort
			s.cfg.Tunnel[i].PreserveHost = req.PreserveHost
			s.cfg.Tunnel[i].TLSPassthrough = req.TLSPassthrough
			s.cfg.Tunnel[i].IPPolicy = req.IPPolicy
			s.cfg.Tunnel[i].AuthPolicy = req.AuthPolicy
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("tunnel updated", "id", tunnelID)
	s.auditLog.Log(s.actorName(r), "tunnel.edit", fmt.Sprintf("Updated tunnel %q", tunnelID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.PathValue("id")
	if tunnelID == "" {
		http.Error(w, "missing tunnel ID", http.StatusBadRequest)
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	found := false
	for i := range s.cfg.Tunnel {
		if s.cfg.Tunnel[i].ID == tunnelID {
			s.cfg.Tunnel = append(s.cfg.Tunnel[:i], s.cfg.Tunnel[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("tunnel deleted", "id", tunnelID)
	s.auditLog.Log(s.actorName(r), "tunnel.delete", fmt.Sprintf("Deleted tunnel %q", tunnelID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// --- Redirect CRUD ---

type redirectRequest struct {
	From         string `json:"from"`
	To           string `json:"to"`
	PreservePath bool   `json:"preserve_path"`
}

func (s *Server) validateRedirect(req redirectRequest, excludeFrom string) error {
	if req.From == "" {
		return fmt.Errorf("from hostname is required")
	}
	if req.To == "" {
		return fmt.Errorf("to URL is required")
	}

	// Check for conflicts with admin_host
	if strings.EqualFold(req.From, s.cfg.Server.AdminHost) {
		return fmt.Errorf("hostname %q conflicts with admin_host", req.From)
	}

	// Check for conflicts with tunnel hostnames
	for _, t := range s.cfg.Tunnel {
		for _, h := range t.Hostnames {
			if strings.EqualFold(req.From, h) {
				return fmt.Errorf("hostname %q conflicts with tunnel %q", req.From, t.ID)
			}
		}
	}

	// Check for duplicate redirects
	for _, r := range s.cfg.Redirect {
		if r.From == excludeFrom {
			continue
		}
		if strings.EqualFold(r.From, req.From) {
			return fmt.Errorf("redirect from %q already exists", req.From)
		}
	}

	return nil
}

func (s *Server) handleCreateRedirect(w http.ResponseWriter, r *http.Request) {
	var req redirectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	if err := s.validateRedirect(req, ""); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.cfg.Redirect = append(s.cfg.Redirect, config.Redirect{
		From:         req.From,
		To:           req.To,
		PreservePath: req.PreservePath,
	})
	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("redirect created", "from", req.From, "to", req.To)
	s.auditLog.Log(s.actorName(r), "redirect.create", fmt.Sprintf("Created redirect %q -> %q", req.From, req.To))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleEditRedirect(w http.ResponseWriter, r *http.Request) {
	fromHost := r.PathValue("from")
	if fromHost == "" {
		http.Error(w, "missing redirect from", http.StatusBadRequest)
		return
	}

	var req redirectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.From = fromHost

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	if err := s.validateRedirect(req, fromHost); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	found := false
	for i := range s.cfg.Redirect {
		if s.cfg.Redirect[i].From == fromHost {
			s.cfg.Redirect[i].To = req.To
			s.cfg.Redirect[i].PreservePath = req.PreservePath
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "redirect not found", http.StatusNotFound)
		return
	}

	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("redirect updated", "from", fromHost)
	s.auditLog.Log(s.actorName(r), "redirect.edit", fmt.Sprintf("Updated redirect %q", fromHost))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteRedirect(w http.ResponseWriter, r *http.Request) {
	fromHost := r.PathValue("from")
	if fromHost == "" {
		http.Error(w, "missing redirect from", http.StatusBadRequest)
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	found := false
	for i := range s.cfg.Redirect {
		if s.cfg.Redirect[i].From == fromHost {
			s.cfg.Redirect = append(s.cfg.Redirect[:i], s.cfg.Redirect[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "redirect not found", http.StatusNotFound)
		return
	}

	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("redirect deleted", "from", fromHost)
	s.auditLog.Log(s.actorName(r), "redirect.delete", fmt.Sprintf("Deleted redirect %q", fromHost))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleRegenerateSecret(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.PathValue("id")
	if tunnelID == "" {
		http.Error(w, "missing tunnel ID", http.StatusBadRequest)
		return
	}

	// Generate new secret
	plaintext, hash, err := token.GenerateSecret()
	if err != nil {
		slog.Error("failed to generate secret", "error", err)
		http.Error(w, "failed to generate secret", http.StatusInternalServerError)
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	// Update config file with new hash
	for i := range s.cfg.Tunnel {
		if s.cfg.Tunnel[i].ID == tunnelID {
			s.cfg.Tunnel[i].SecretHash = hash
			break
		}
	}
	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("regenerated tunnel secret", "tunnel", tunnelID)
	s.auditLog.Log(s.actorName(r), "tunnel.regenerate", fmt.Sprintf("Regenerated secret for tunnel %q", tunnelID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.secretResponse(tunnelID, plaintext))
}

func (s *Server) handleTunnelTest(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.PathValue("id")
	if tunnelID == "" {
		http.Error(w, "missing tunnel ID", http.StatusBadRequest)
		return
	}

	tunnel := s.registry.FindByID(tunnelID)
	if tunnel == nil {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	conn := tunnel.PickConn()
	if conn == nil {
		w.Header().Set("Content-Type", "application/x-ndjson")
		json.NewEncoder(w).Encode(diagEvent{Phase: "error", Error: "tunnel is offline"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	enc := json.NewEncoder(w)
	s.runDiagnosticStream(conn, func(e diagEvent) {
		enc.Encode(e)
		flusher.Flush()
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleAPITunnels(w http.ResponseWriter, r *http.Request) {
	tunnels := s.registry.AllTunnels()
	type clientJSON struct {
		Addr    string `json:"addr"`
		Uptime  string `json:"uptime"`
		Version string `json:"version,omitempty"`
	}
	type tunnelJSON struct {
		ID            string       `json:"id"`
		Type          string       `json:"type"`
		Connected     bool         `json:"connected"`
		ClientCount   int          `json:"client_count"`
		Clients       []clientJSON `json:"clients,omitempty"`
		ActiveConns   int32        `json:"active_conns"`
		BytesIn       int64        `json:"bytes_in"`
		BytesOut      int64        `json:"bytes_out"`
		Requests      int64        `json:"requests"`
		ServerVersion string       `json:"server_version,omitempty"`
	}
	result := make([]tunnelJSON, len(tunnels))
	for i, t := range tunnels {
		var clients []clientJSON
		for _, info := range t.ClientInfos() {
			clients = append(clients, clientJSON{
				Addr:    info.Addr,
				Uptime:  admin.FormatUptime(info.ConnectedAt),
				Version: info.Version,
			})
		}
		result[i] = tunnelJSON{
			ID:            t.ID,
			Type:          t.TunnelType(),
			Connected:     t.IsConnected(),
			ClientCount:   t.ClientCount(),
			Clients:       clients,
			ActiveConns:   t.Metrics.ActiveConns.Load(),
			BytesIn:       t.Metrics.BytesIn.Load(),
			BytesOut:      t.Metrics.BytesOut.Load(),
			Requests:      t.Metrics.RequestCount.Load(),
			ServerVersion: strings.TrimPrefix(s.version, "v"),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// runBandwidthSampler periodically snapshots aggregate tunnel bytes and records rates.
func (s *Server) runBandwidthSampler(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var totalIn, totalOut int64
			for _, t := range s.registry.AllTunnels() {
				totalIn += t.Metrics.BytesIn.Load()
				totalOut += t.Metrics.BytesOut.Load()
			}
			s.bwTracker.record(totalIn, totalOut)
		}
	}
}

// handleSessionKeepalive validates and refreshes the session, extending its expiry.
// Returns 401 if the session is invalid, 200 with a refreshed cookie if valid.
func (s *Server) handleSessionKeepalive(w http.ResponseWriter, r *http.Request) {
	if !s.sessionMgr.ValidateSession(r) {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
		return
	}
	// Re-issue the session cookie to extend its expiry (sliding window),
	// preserving the session identity so the CSRF token stays stable across tabs.
	if err := s.sessionMgr.RefreshSession(w, r); err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (s *Server) handleAPIBandwidth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.bwTracker.history())
}

func (s *Server) handleGetUpdate(w http.ResponseWriter, r *http.Request) {
	s.updateMu.RLock()
	result := s.updateResult
	s.updateMu.RUnlock()

	resp := struct {
		Available bool   `json:"available"`
		Current   string `json:"current"`
		Latest    string `json:"latest"`
		IsDocker  bool   `json:"is_docker"`
	}{
		Current:  strings.TrimPrefix(s.version, "v"),
		IsDocker: update.IsDocker(),
	}
	if result != nil {
		resp.Available = result.UpdateAvailable
		resp.Latest = result.LatestVersion
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePostUpdate(w http.ResponseWriter, r *http.Request) {
	if update.IsDocker() {
		http.Error(w, "self-update is not supported in Docker; update your image instead", http.StatusBadRequest)
		return
	}

	s.updateMu.RLock()
	result := s.updateResult
	s.updateMu.RUnlock()

	if result == nil || !result.UpdateAvailable {
		http.Error(w, "no update available", http.StatusBadRequest)
		return
	}
	if result.DownloadURL == "" {
		http.Error(w, "no binary available for this platform", http.StatusBadRequest)
		return
	}

	if err := update.SelfUpdate(result.DownloadURL, result.ChecksumURL, "gatecrash-server"); err != nil {
		slog.Error("update failed", "error", err)
		http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("update complete, restarting", "new_version", result.LatestVersion)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": result.LatestVersion})

	// Exit so systemd (or Docker) restarts us with the new binary
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

// handleConfigReload applies a new config, updating the tunnel registry and config reference.
func (s *Server) handleConfigReload(newCfg *config.Config) {
	// Reject configs with unenforceable access-control combinations or bad
	// policy references.
	if err := newCfg.Validate(); err != nil {
		slog.Error("config reload rejected", "error", err)
		s.sse.Broadcast("config-error", err.Error())
		return
	}

	tunnels := make([]TunnelSpec, len(newCfg.Tunnel))
	for i, tc := range newCfg.Tunnel {
		tunnels[i] = specFromConfig(tc)
	}
	s.registry.SetPolicies(policiesFromConfig(newCfg))
	s.registry.Reload(tunnels)

	s.cfgMu.Lock()
	s.cfg = newCfg
	s.cfgMu.Unlock()

	// Start/stop TCP listeners to match new config
	s.reconcileTCPListeners()

	slog.Info("config reloaded",
		"tunnels", len(newCfg.Tunnel),
		"redirects", len(newCfg.Redirect),
	)

	s.sse.Broadcast("config-reload", "ok")
}

func (s *Server) runUpdateChecker(repo string, interval time.Duration) {
	s.checkForUpdate(repo)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.checkForUpdate(repo)
	}
}

func (s *Server) checkForUpdate(repo string) {
	result, err := update.Check(repo, s.version, "gatecrash-server")
	if err != nil {
		slog.Debug("update check failed", "error", err)
		return
	}
	s.updateMu.Lock()
	s.updateResult = result
	s.updateMu.Unlock()
	if result.UpdateAvailable {
		slog.Info("update available", "current", result.CurrentVersion, "latest", result.LatestVersion)
		s.sse.Broadcast("update-available", result.LatestVersion)
	}
}

// cleanupPendingTunnelAuth periodically removes expired pending tunnel auth tokens.
func (s *Server) cleanupPendingTunnelAuth(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.pendingTunnelAuthMu.Lock()
			for k, v := range s.pendingTunnelAuth {
				if now.After(v.expires) {
					delete(s.pendingTunnelAuth, k)
				}
			}
			s.pendingTunnelAuthMu.Unlock()
		}
	}
}

// handleTunnelLogin runs on the admin host for a logged-in user. It parks a
// one-time token carrying the user's identity and redirects to the tunnel
// hostname to establish its session. requireAuth ensures the user is signed in
// (redirecting through /login first if not).
func (s *Server) handleTunnelLogin(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" || s.registry.FindByHostname(hostname) == nil {
		http.Error(w, "unknown tunnel hostname", http.StatusBadRequest)
		return
	}

	returnURL := r.URL.Query().Get("return")
	if returnURL != "" {
		if u, err := url.Parse(returnURL); err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), hostname) {
			returnURL = ""
		}
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	oneTimeToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	s.pendingTunnelAuthMu.Lock()
	s.pendingTunnelAuth[oneTimeToken] = &pendingTunnelAuthResult{
		userID:    s.sessionMgr.UserID(r),
		role:      s.sessionMgr.Role(r),
		hostname:  hostname,
		returnURL: returnURL,
		expires:   time.Now().Add(60 * time.Second),
	}
	s.pendingTunnelAuthMu.Unlock()

	s.cfgMu.RLock()
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()
	completeURL := fmt.Sprintf("https://%s/.gatecrash/auth/complete?token=%s", hostname, oneTimeToken)
	if httpsPort != 443 {
		completeURL = fmt.Sprintf("https://%s:%d/.gatecrash/auth/complete?token=%s", hostname, httpsPort, oneTimeToken)
	}
	http.Redirect(w, r, completeURL, http.StatusFound)
}

// --- Audit Log Handlers ---

func (s *Server) handleAuditLogPage(w http.ResponseWriter, r *http.Request) {
	s.adminH.Render(w, "pages/auditlog.html", &admin.PageData{
		Title:     "Audit Log",
		Active:    "auditlog",
		CSRFToken: s.sessionMgr.CSRFToken(r),
		UserID:    s.sessionMgr.UserID(r),
		IsAdmin:   true,
	})
}

func (s *Server) handleAPIAuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &limit); err != nil || n != 1 || limit < 1 {
			limit = 50
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &offset); err != nil || n != 1 || offset < 0 {
			offset = 0
		}
	}
	if limit > 200 {
		limit = 200
	}

	actor := r.URL.Query().Get("actor")
	action := r.URL.Query().Get("action")

	entries, total := s.auditLog.Query(limit, offset, actor, action)
	actors, actions := s.auditLog.Facets()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
		"actors":  actors,
		"actions": actions,
	})
}

func (s *Server) httpToHTTPSRedirect(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	httpsPort := s.cfg.Server.HTTPSPort
	configuredHosts := s.cfg.AllHostnames()
	s.cfgMu.RUnlock()

	host := stripPort(r.Host)

	// Reject requests for unconfigured hosts to prevent open redirect abuse.
	configured := false
	for _, h := range configuredHosts {
		if strings.EqualFold(h, host) {
			configured = true
			break
		}
	}
	if !configured {
		http.NotFound(w, r)
		return
	}

	if httpsPort != 443 {
		host = fmt.Sprintf("%s:%d", host, httpsPort)
	}
	target := "https://" + host + r.RequestURI
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
