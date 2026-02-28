package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
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
	cfg        *config.Config
	configPath string
	version    string
	registry   *Registry
	sshServer  *ssh.Server
	adminMux   *http.ServeMux
	tlsConfig  *tls.Config
	sse              *SSEBroadcaster
	staticFS         fs.FS // embedded or disk-based static assets
	hostFingerprint  string // SSH host key fingerprint (SHA256)

	// Config mutation lock — protects s.cfg reads/writes from admin API and config reload
	cfgMu sync.RWMutex

	// TCP listener management
	tcpMu        sync.Mutex
	tcpListeners map[int]net.Listener // port → listener

	// Update state
	updateMu     sync.RWMutex
	updateResult *update.CheckResult

	// Auth components
	passkeyStore *admin.PasskeyStore
	sessionMgr   *admin.SessionManager
	webauthn     *admin.WebAuthnHandler
	adminH       *admin.Handlers
}

// New creates a new server instance.
func New(cfg *config.Config, configPath, version string) *Server {
	return &Server{
		cfg:        cfg,
		configPath: configPath,
		version:    version,
		registry:   NewRegistry(),
		adminMux:   http.NewServeMux(),
		sse:        NewSSEBroadcaster(),
	}
}

// Run starts all server components and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	// Build tunnel registry from config
	for _, tc := range s.cfg.Tunnel {
		t := &TunnelState{
			ID:             tc.ID,
			Type:           tc.Type,
			Hostnames:      tc.Hostnames,
			ListenPort:     tc.ListenPort,
			PreserveHost:   tc.PreserveHost,
			TLSPassthrough: tc.TLSPassthrough,
		}
		s.registry.Register(t)

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
		if t.Type == "tcp" && t.ListenPort > 0 {
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

	// Start SSH server
	go func() {
		slog.Info("SSH server listening", "addr", sshSrv.Addr)
		if err := sshSrv.ListenAndServe(); err != nil {
			slog.Error("SSH server error", "error", err)
		}
	}()

	// Start HTTPS listener
	errCh := make(chan error, 2)

	go func() {
		httpsAddr := fmt.Sprintf("%s:%d", s.cfg.Server.BindAddr, s.cfg.Server.HTTPSPort)
		rawListener, err := net.Listen("tcp", httpsAddr)
		if err != nil {
			errCh <- fmt.Errorf("HTTPS listen: %w", err)
			return
		}
		listener := s.newSNIListener(rawListener)
		slog.Info("HTTPS server listening", "addr", httpsAddr)
		errCh <- http.Serve(listener, s)
	}()

	// Optional HTTP→HTTPS redirect listener
	if s.cfg.Server.HTTPPort > 0 {
		go func() {
			httpAddr := fmt.Sprintf("%s:%d", s.cfg.Server.BindAddr, s.cfg.Server.HTTPPort)
			slog.Info("HTTP server listening (redirect to HTTPS)", "addr", httpAddr)
			errCh <- http.ListenAndServe(httpAddr, http.HandlerFunc(s.httpToHTTPSRedirect))
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

// initAdmin initializes the admin panel components (passkeys, sessions, WebAuthn, templates).
func (s *Server) initAdmin() error {
	// Passkey store
	dataDir := filepath.Dir(s.configPath)
	store, err := admin.NewPasskeyStore(filepath.Join(dataDir, "passkeys.json"))
	if err != nil {
		return fmt.Errorf("passkey store: %w", err)
	}
	s.passkeyStore = store

	// Session manager
	s.sessionMgr = admin.NewSessionManager(s.cfg.Server.Secret)

	// WebAuthn - determine rpID and origin from admin_host
	rpID := s.cfg.Server.AdminHost
	rpOrigin := "https://" + s.cfg.Server.AdminHost
	if s.cfg.Server.HTTPSPort != 443 {
		rpOrigin = fmt.Sprintf("https://%s:%d", s.cfg.Server.AdminHost, s.cfg.Server.HTTPSPort)
	}

	wah, err := admin.NewWebAuthnHandler(rpID, rpOrigin, store, s.sessionMgr)
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

	ah, err := admin.NewHandlers(s.version, tmplFS)
	if err != nil {
		return fmt.Errorf("admin handlers: %w", err)
	}
	s.adminH = ah

	slog.Info("admin panel initialized", "rpID", rpID)
	return nil
}

// setupAdminRoutes registers the admin panel HTTP handlers.
func (s *Server) setupAdminRoutes() {
	// Static files — always public
	s.adminMux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.staticFS)))

	// Health check — always public
	s.adminMux.HandleFunc("GET /health", s.handleHealth)

	// Auth pages — public (these are the login/setup pages themselves)
	s.adminMux.HandleFunc("GET /login", s.handleLogin)
	s.adminMux.HandleFunc("GET /setup", s.handleSetup)

	// WebAuthn API endpoints
	// Registration requires either setup mode (no passkeys) or an authenticated session
	s.adminMux.HandleFunc("POST /auth/register/begin", s.requireAuthOrSetup(s.webauthn.HandleRegisterBegin))
	s.adminMux.HandleFunc("POST /auth/register/finish", s.requireAuthOrSetup(s.webauthn.HandleRegisterFinish))
	// Login endpoints are public (called by JS on login page)
	s.adminMux.HandleFunc("POST /auth/login/begin", s.webauthn.HandleLoginBegin)
	s.adminMux.HandleFunc("POST /auth/login/finish", s.webauthn.HandleLoginFinish)

	// Logout
	s.adminMux.HandleFunc("POST /logout", s.handleLogout)

	// Protected routes — require auth
	s.adminMux.HandleFunc("GET /", s.requireAuth(s.handleAdminDashboard))
	s.adminMux.HandleFunc("GET /help", s.requireAuth(s.handleHelp))
	s.adminMux.HandleFunc("GET /passkeys", s.requireAuth(s.handlePasskeys))
	s.adminMux.HandleFunc("POST /passkeys/delete", s.requireAuth(s.handleDeletePasskey))
	s.adminMux.HandleFunc("GET /api/tunnels", s.requireAuth(s.handleAPITunnels))
	s.adminMux.HandleFunc("GET /api/tunnels/html", s.requireAuth(s.handleAPITunnelsHTML))
	s.adminMux.HandleFunc("GET /api/redirects/html", s.requireAuth(s.handleAPIRedirectsHTML))
	s.adminMux.HandleFunc("POST /api/tunnels", s.requireAuth(s.handleCreateTunnel))
	s.adminMux.HandleFunc("PUT /api/tunnels/{id}", s.requireAuth(s.handleEditTunnel))
	s.adminMux.HandleFunc("DELETE /api/tunnels/{id}", s.requireAuth(s.handleDeleteTunnel))
	s.adminMux.HandleFunc("POST /api/tunnels/{id}/regenerate", s.requireAuth(s.handleRegenerateSecret))
	s.adminMux.HandleFunc("POST /api/redirects", s.requireAuth(s.handleCreateRedirect))
	s.adminMux.HandleFunc("PUT /api/redirects/{from}", s.requireAuth(s.handleEditRedirect))
	s.adminMux.HandleFunc("DELETE /api/redirects/{from}", s.requireAuth(s.handleDeleteRedirect))
	s.adminMux.HandleFunc("GET /api/update", s.requireAuth(s.handleGetUpdate))
	s.adminMux.HandleFunc("POST /api/update", s.requireAuth(s.handlePostUpdate))
	s.adminMux.HandleFunc("GET /api/events", s.requireAuth(s.sse.ServeHTTP))
}

// requireAuthOrSetup allows access if no passkeys exist (setup mode) or the user is authenticated.
// Used for passkey registration endpoints — first registration is open, subsequent ones require auth.
func (s *Server) requireAuthOrSetup(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.webauthn.NeedsSetup() {
			next(w, r)
			return
		}
		if !s.sessionMgr.ValidateSession(r) {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requireAuth wraps a handler with authentication checks.
// If no passkeys are registered, redirects to setup.
// If not authenticated, redirects to login.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.webauthn.NeedsSetup() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if !s.sessionMgr.ValidateSession(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// handleLogin renders the login page.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.webauthn.NeedsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.sessionMgr.ValidateSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.adminH.Render(w, "pages/login.html", &admin.PageData{
		Title: "Login",
	})
}

// handleSetup renders the first-time passkey registration page.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.webauthn.NeedsSetup() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.adminH.Render(w, "pages/setup.html", &admin.PageData{
		Title: "Setup",
	})
}

// handlePasskeys renders the passkey management page.
func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	creds := s.passkeyStore.Credentials()
	passkeys := make([]admin.PasskeyView, len(creds))
	for i, c := range creds {
		passkeys[i] = admin.PasskeyView{
			Name:       c.Name,
			CreatedAt:  c.CreatedAt.Format("Jan 2, 2006"),
			LastUsedAt: c.LastUsedAt.Format("Jan 2, 2006"),
			IDB64:      base64.RawURLEncoding.EncodeToString(c.ID),
		}
	}

	s.adminH.Render(w, "pages/passkeys.html", &admin.PageData{
		Title:  "Passkeys",
		Active: "passkeys",
		Data: struct {
			Passkeys  []admin.PasskeyView
			CanDelete bool
			CSRFToken string
		}{
			Passkeys:  passkeys,
			CanDelete: len(creds) > 1,
			CSRFToken: s.sessionMgr.CSRFToken(r),
		},
	})
}

// handleDeletePasskey removes a passkey.
func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.sessionMgr.ValidCSRFToken(r, r.FormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	idB64 := r.FormValue("id")
	if idB64 == "" {
		http.Redirect(w, r, "/passkeys", http.StatusSeeOther)
		return
	}

	credID, err := base64.RawURLEncoding.DecodeString(idB64)
	if err != nil {
		http.Error(w, "invalid credential ID", http.StatusBadRequest)
		return
	}

	if err := s.passkeyStore.RemoveCredential(credID); err != nil {
		slog.Error("failed to remove passkey", "error", err)
	}

	http.Redirect(w, r, "/passkeys", http.StatusSeeOther)
}

// handleLogout clears the session and redirects to login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
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
	sshAddr := fmt.Sprintf("%s:%d", s.cfg.Server.AdminHost, s.cfg.Server.SSHPort)
	s.adminH.Render(w, "pages/help.html", &admin.PageData{
		Title:  "Help",
		Active: "help",
		Data: struct {
			SSHAddr     string
			Fingerprint string
		}{
			SSHAddr:     sshAddr,
			Fingerprint: s.hostFingerprint,
		},
	})
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	tunnels := s.buildTunnelViews()
	redirects := s.buildRedirectViews()

	s.adminH.Render(w, "pages/dashboard.html", &admin.PageData{
		Title:  "Dashboard",
		Active: "dashboard",
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
		var hostCerts []admin.HostCert
		for _, h := range t.Hostnames {
			ci := s.getCertInfo(h)
			hc := admin.HostCert{Hostname: h, Valid: ci.valid, Error: ci.err}
			if !ci.expiry.IsZero() {
				hc.Expiry = ci.expiry.Format("Jan 2, 2006")
			}
			hostCerts = append(hostCerts, hc)
		}
		views[i] = admin.TunnelView{
			ID:             t.ID,
			Type:           t.Type,
			Hostnames:      t.Hostnames,
			ListenPort:     t.ListenPort,
			PreserveHost:   t.PreserveHost,
			TLSPassthrough: t.TLSPassthrough,
			Connected:      t.IsConnected(),
			ClientCount:    t.ClientCount(),
			Clients:        buildClientViews(t),
			Requests:       t.Metrics.RequestCount.Load(),
			BytesIn:        t.Metrics.BytesIn.Load(),
			BytesOut:       t.Metrics.BytesOut.Load(),
			ActiveConns:    int32(t.Metrics.ActiveConns.Load()),
			HostCerts:      hostCerts,
		}
	}
	return views
}

func buildClientViews(t *TunnelState) []admin.ClientView {
	infos := t.ClientInfos()
	views := make([]admin.ClientView, len(infos))
	for i, info := range infos {
		views[i] = admin.ClientView{
			Addr:   info.Addr,
			Uptime: admin.FormatUptime(info.ConnectedAt),
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

	return nil
}

func (s *Server) secretResponse(tunnelID, plaintext string) map[string]string {
	tok := token.FormatToken(tunnelID, plaintext)
	sshAddr := fmt.Sprintf("%s:%d", s.cfg.Server.AdminHost, s.cfg.Server.SSHPort)
	return map[string]string{
		"token":   tok,
		"command": fmt.Sprintf("gatecrash client --server %s --host-key %s --token %s --target 127.0.0.1:8000", sshAddr, s.hostFingerprint, tok),
		"docker":  fmt.Sprintf("docker run -e GATECRASH_SERVER=%s -e GATECRASH_HOST_KEY=%s -e GATECRASH_TOKEN=%s -e GATECRASH_TARGET=app:8000 ghcr.io/jclement/gatecrash:latest gatecrash client", sshAddr, s.hostFingerprint, tok),
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
	})
	if err := s.cfg.Save(s.configPath); err != nil {
		slog.Error("failed to save config", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	slog.Info("tunnel created", "id", req.ID, "type", req.Type)
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.secretResponse(tunnelID, plaintext))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleAPITunnels(w http.ResponseWriter, r *http.Request) {
	tunnels := s.registry.AllTunnels()
	type clientJSON struct {
		Addr   string `json:"addr"`
		Uptime string `json:"uptime"`
	}
	type tunnelJSON struct {
		ID          string       `json:"id"`
		Type        string       `json:"type"`
		Connected   bool         `json:"connected"`
		ClientCount int          `json:"client_count"`
		Clients     []clientJSON `json:"clients,omitempty"`
		ActiveConns int32        `json:"active_conns"`
		BytesIn     int64        `json:"bytes_in"`
		BytesOut    int64        `json:"bytes_out"`
		Requests    int64        `json:"requests"`
	}
	result := make([]tunnelJSON, len(tunnels))
	for i, t := range tunnels {
		var clients []clientJSON
		for _, info := range t.ClientInfos() {
			clients = append(clients, clientJSON{
				Addr:   info.Addr,
				Uptime: admin.FormatUptime(info.ConnectedAt),
			})
		}
		result[i] = tunnelJSON{
			ID:          t.ID,
			Type:        t.Type,
			Connected:   t.IsConnected(),
			ClientCount: t.ClientCount(),
			Clients:     clients,
			ActiveConns: t.Metrics.ActiveConns.Load(),
			BytesIn:     t.Metrics.BytesIn.Load(),
			BytesOut:    t.Metrics.BytesOut.Load(),
			Requests:    t.Metrics.RequestCount.Load(),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
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

	if err := update.SelfUpdate(result.DownloadURL); err != nil {
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
	tunnels := make([]struct {
		ID             string
		Type           string
		Hostnames      []string
		ListenPort     int
		PreserveHost   bool
		TLSPassthrough bool
	}, len(newCfg.Tunnel))
	for i, tc := range newCfg.Tunnel {
		tunnels[i] = struct {
			ID             string
			Type           string
			Hostnames      []string
			ListenPort     int
			PreserveHost   bool
			TLSPassthrough bool
		}{
			ID:             tc.ID,
			Type:           tc.Type,
			Hostnames:      tc.Hostnames,
			ListenPort:     tc.ListenPort,
			PreserveHost:   tc.PreserveHost,
			TLSPassthrough: tc.TLSPassthrough,
		}
	}
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
	result, err := update.Check(repo, s.version)
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

func (s *Server) httpToHTTPSRedirect(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()

	host := stripPort(r.Host)
	if httpsPort != 443 {
		host = fmt.Sprintf("%s:%d", host, httpsPort)
	}
	target := "https://" + host + r.RequestURI
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
