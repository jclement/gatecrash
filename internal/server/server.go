package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	ssh "github.com/gliderlabs/ssh"

	"github.com/jclement/gatecrash/internal/admin"
	"github.com/jclement/gatecrash/internal/config"
	"github.com/jclement/gatecrash/internal/token"
	"github.com/jclement/gatecrash/web"
)

// Server is the main gatecrash server orchestrator.
type Server struct {
	cfg        *config.Config
	configPath string
	version    string
	noWebAdmin bool
	registry   *Registry
	sshServer  *ssh.Server
	adminMux   *http.ServeMux
	tlsConfig  *tls.Config
	sse        *SSEBroadcaster
	staticFS   fs.FS // embedded or disk-based static assets

	// Auth components
	passkeyStore *admin.PasskeyStore
	sessionMgr   *admin.SessionManager
	webauthn     *admin.WebAuthnHandler
	adminH       *admin.Handlers
}

// New creates a new server instance.
func New(cfg *config.Config, configPath, version string, noWebAdmin bool) *Server {
	return &Server{
		cfg:        cfg,
		configPath: configPath,
		version:    version,
		noWebAdmin: noWebAdmin,
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
			ID:           tc.ID,
			Type:         tc.Type,
			Hostnames:    tc.Hostnames,
			ListenPort:   tc.ListenPort,
			PreserveHost: tc.PreserveHost,
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

	// Setup admin routes
	if !s.noWebAdmin {
		if err := s.initAdmin(); err != nil {
			return fmt.Errorf("admin init: %w", err)
		}
		s.setupAdminRoutes()
	}

	// Setup TLS if hostnames are configured
	tlsConfig, err := s.setupTLS()
	if err != nil {
		slog.Warn("TLS setup failed, running HTTP only", "error", err)
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

	// Start SSH server
	go func() {
		slog.Info("SSH server listening", "addr", sshSrv.Addr)
		if err := sshSrv.ListenAndServe(); err != nil {
			slog.Error("SSH server error", "error", err)
		}
	}()

	// Start HTTP/HTTPS server
	errCh := make(chan error, 2)

	if s.tlsConfig != nil {
		go func() {
			httpsAddr := fmt.Sprintf("%s:443", s.cfg.Server.BindAddr)
			listener, err := tls.Listen("tcp", httpsAddr, s.tlsConfig)
			if err != nil {
				errCh <- fmt.Errorf("HTTPS listen: %w", err)
				return
			}
			slog.Info("HTTPS server listening", "addr", httpsAddr)
			errCh <- http.Serve(listener, s)
		}()

		go func() {
			httpAddr := fmt.Sprintf("%s:80", s.cfg.Server.BindAddr)
			slog.Info("HTTP server listening (redirect)", "addr", httpAddr)
			errCh <- http.ListenAndServe(httpAddr, http.HandlerFunc(httpToHTTPSRedirect))
		}()
	} else {
		go func() {
			httpAddr := fmt.Sprintf("%s:8080", s.cfg.Server.BindAddr)
			slog.Info("HTTP server listening", "addr", httpAddr)
			errCh <- http.ListenAndServe(httpAddr, s)
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

	// WebAuthn - determine rpID and origin from config
	rpID := "localhost"
	rpOrigin := "http://localhost:8080"
	if s.cfg.Server.AdminHost != "" {
		rpID = s.cfg.Server.AdminHost
		rpOrigin = "https://" + s.cfg.Server.AdminHost
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

	// WebAuthn API endpoints — public (called by JS on login/setup pages)
	s.adminMux.HandleFunc("POST /auth/register/begin", s.webauthn.HandleRegisterBegin)
	s.adminMux.HandleFunc("POST /auth/register/finish", s.webauthn.HandleRegisterFinish)
	s.adminMux.HandleFunc("POST /auth/login/begin", s.webauthn.HandleLoginBegin)
	s.adminMux.HandleFunc("POST /auth/login/finish", s.webauthn.HandleLoginFinish)

	// Logout
	s.adminMux.HandleFunc("POST /logout", s.handleLogout)

	// Protected routes — require auth
	s.adminMux.HandleFunc("GET /", s.requireAuth(s.handleAdminDashboard))
	s.adminMux.HandleFunc("GET /passkeys", s.requireAuth(s.handlePasskeys))
	s.adminMux.HandleFunc("POST /passkeys/delete", s.requireAuth(s.handleDeletePasskey))
	s.adminMux.HandleFunc("GET /api/tunnels", s.requireAuth(s.handleAPITunnels))
	s.adminMux.HandleFunc("GET /api/tunnels/html", s.requireAuth(s.handleAPITunnelsHTML))
	s.adminMux.HandleFunc("POST /api/tunnels/{id}/regenerate", s.requireAuth(s.handleRegenerateSecret))
	s.adminMux.HandleFunc("GET /api/events", s.requireAuth(s.sse.ServeHTTP))
}

// requireAuth wraps a handler with authentication checks.
// If no passkeys are registered, redirects to setup.
// If not authenticated, redirects to login.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prefix := adminPrefix(r)

		// If no passkeys registered, redirect to setup
		if s.webauthn.NeedsSetup() {
			http.Redirect(w, r, prefix+"/setup", http.StatusSeeOther)
			return
		}

		// Check session
		if !s.sessionMgr.ValidateSession(r) {
			http.Redirect(w, r, prefix+"/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

// handleLogin renders the login page.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// If no passkeys, go to setup instead
	if s.webauthn.NeedsSetup() {
		prefix := adminPrefix(r)
		http.Redirect(w, r, prefix+"/setup", http.StatusSeeOther)
		return
	}
	// If already authenticated, go to dashboard
	if s.sessionMgr.ValidateSession(r) {
		prefix := adminPrefix(r)
		http.Redirect(w, r, prefix+"/", http.StatusSeeOther)
		return
	}
	s.adminH.Render(w, "pages/login.html", &admin.PageData{
		Title:    "Login",
		BasePath: adminPrefix(r),
	})
}

// handleSetup renders the first-time passkey registration page.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	// If already set up, redirect to login
	if !s.webauthn.NeedsSetup() {
		prefix := adminPrefix(r)
		http.Redirect(w, r, prefix+"/login", http.StatusSeeOther)
		return
	}
	s.adminH.Render(w, "pages/setup.html", &admin.PageData{
		Title:    "Setup",
		BasePath: adminPrefix(r),
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
		Title:    "Passkeys",
		Active:   "passkeys",
		BasePath: adminPrefix(r),
		Data: struct {
			Passkeys  []admin.PasskeyView
			CanDelete bool
		}{
			Passkeys:  passkeys,
			CanDelete: len(creds) > 1,
		},
	})
}

// handleDeletePasskey removes a passkey.
func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	prefix := adminPrefix(r)
	idB64 := r.FormValue("id")
	if idB64 == "" {
		http.Redirect(w, r, prefix+"/passkeys", http.StatusSeeOther)
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

	http.Redirect(w, r, prefix+"/passkeys", http.StatusSeeOther)
}

// handleLogout clears the session and redirects to login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessionMgr.ClearSession(w)
	prefix := adminPrefix(r)
	http.Redirect(w, r, prefix+"/login", http.StatusSeeOther)
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	tunnels := s.buildTunnelViews()
	prefix := adminPrefix(r)
	basePath := prefix
	if basePath == "" {
		basePath = ""
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<base href="%s/">
<title>Gatecrash</title>
<link rel="icon" type="image/png" href="static/favicon.png">
<link rel="stylesheet" href="static/css/bulma.min.css">
<link rel="stylesheet" href="static/css/app.css">
<script src="static/js/htmx.min.js"></script>
<script src="static/js/htmx-sse.js"></script>
</head>
<body>
<nav class="navbar is-spaced">
  <div class="container">
    <div class="navbar-brand">
      <a class="navbar-item" href=".">
        <img src="static/logo.png" alt="Gatecrash" style="max-height:28px;margin-right:8px">
        <span class="has-text-weight-bold is-size-5">Gatecrash</span>
      </a>
    </div>
    <div class="navbar-menu">
      <div class="navbar-start">
        <a class="navbar-item is-active" href=".">Dashboard</a>
        <a class="navbar-item" href="passkeys">Passkeys</a>
      </div>
      <div class="navbar-end">
        <div class="navbar-item"><span class="tag is-light">v%s</span></div>
        <div class="navbar-item"><span class="tag is-light">SSH :%d</span></div>
        <div class="navbar-item">
          <form method="POST" action="logout">
            <button type="submit" class="button is-small is-light">Logout</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</nav>
<main class="section">
<div class="container">
  <div id="config-error"></div>
  <div hx-ext="sse" sse-connect="api/events">
    <div sse-swap="config-reload" hx-get="api/tunnels/html" hx-trigger="sse:config-reload" hx-swap="innerHTML" hx-target="#tunnel-table-body"></div>
    <div sse-swap="tunnel-connect" hx-get="api/tunnels/html" hx-trigger="sse:tunnel-connect" hx-swap="innerHTML" hx-target="#tunnel-table-body"></div>
    <div sse-swap="tunnel-disconnect" hx-get="api/tunnels/html" hx-trigger="sse:tunnel-disconnect" hx-swap="innerHTML" hx-target="#tunnel-table-body"></div>
  </div>
  <table class="table is-fullwidth is-hoverable">
    <thead>
      <tr>
        <th>Status</th>
        <th>Tunnel</th>
        <th>Type</th>
        <th>Routes</th>
        <th>Client</th>
        <th>Requests</th>
        <th>Traffic</th>
        <th>Active</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody id="tunnel-table-body" hx-get="api/tunnels/html" hx-trigger="every 5s" hx-swap="innerHTML">`, basePath, s.version, s.cfg.Server.SSHPort)

	s.writeTunnelRows(w, tunnels)

	fmt.Fprintf(w, `
    </tbody>
  </table>
</div>
</main>

<!-- Secret Modal -->
<div class="modal" id="secret-modal">
  <div class="modal-background" onclick="closeSecretModal()"></div>
  <div class="modal-card">
    <header class="modal-card-head">
      <p class="modal-card-title">New Tunnel Secret</p>
      <button class="delete" onclick="closeSecretModal()"></button>
    </header>
    <section class="modal-card-body">
      <div class="notification is-warning is-light">
        Save this information now — the secret will not be shown again.
      </div>
      <div class="field">
        <label class="label">Token</label>
        <div class="control">
          <div class="field has-addons">
            <div class="control is-expanded">
              <input class="input is-family-code" id="secret-token" readonly>
            </div>
            <div class="control">
              <button class="button" onclick="copyField('secret-token', this)">Copy</button>
            </div>
          </div>
        </div>
      </div>
      <div class="field">
        <label class="label">Client Command</label>
        <div class="control">
          <div class="field has-addons">
            <div class="control is-expanded">
              <input class="input is-family-code is-size-7" id="secret-command" readonly>
            </div>
            <div class="control">
              <button class="button" onclick="copyField('secret-command', this)">Copy</button>
            </div>
          </div>
        </div>
      </div>
      <div class="field">
        <label class="label">Docker Command</label>
        <div class="control">
          <div class="field has-addons">
            <div class="control is-expanded">
              <input class="input is-family-code is-size-7" id="secret-docker" readonly>
            </div>
            <div class="control">
              <button class="button" onclick="copyField('secret-docker', this)">Copy</button>
            </div>
          </div>
        </div>
      </div>
    </section>
    <footer class="modal-card-foot">
      <button class="button" onclick="closeSecretModal()">Done</button>
    </footer>
  </div>
</div>

<footer class="footer" style="padding:0.75rem">
  <div class="content has-text-centered">
    <p class="is-size-7 has-text-grey">Gatecrash v%s</p>
  </div>
</footer>

<script>
async function regenerateSecret(tunnelId) {
  if (!confirm('Generate a new secret for tunnel "' + tunnelId + '"? The old secret will stop working.')) return;
  const resp = await fetch('api/tunnels/' + tunnelId + '/regenerate', {method: 'POST'});
  if (!resp.ok) { alert('Failed: ' + await resp.text()); return; }
  const data = await resp.json();
  document.getElementById('secret-token').value = data.token;
  document.getElementById('secret-command').value = data.command;
  document.getElementById('secret-docker').value = data.docker;
  document.getElementById('secret-modal').classList.add('is-active');
}

function closeSecretModal() {
  document.getElementById('secret-modal').classList.remove('is-active');
}

function copyField(id, btn) {
  const el = document.getElementById(id);
  navigator.clipboard.writeText(el.value);
  const orig = btn.textContent;
  btn.textContent = 'Copied!';
  btn.classList.add('is-success');
  setTimeout(() => { btn.textContent = orig; btn.classList.remove('is-success'); }, 2000);
}
</script>
</body>
</html>`, s.version)
}

func (s *Server) handleAPITunnelsHTML(w http.ResponseWriter, r *http.Request) {
	tunnels := s.buildTunnelViews()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.writeTunnelRows(w, tunnels)
}

func (s *Server) writeTunnelRows(w http.ResponseWriter, tunnels []admin.TunnelView) {
	if len(tunnels) == 0 {
		fmt.Fprint(w, `<tr><td colspan="9" class="has-text-centered has-text-grey">No tunnels configured. Edit gatecrash.toml to add tunnels.</td></tr>`)
		return
	}
	for _, t := range tunnels {
		statusClass := "is-disconnected"
		if t.Connected {
			statusClass = "is-connected"
		}
		typeClass := "is-warning"
		if t.Type == "http" {
			typeClass = "is-info"
		}
		routes := ""
		if t.Type == "http" {
			for _, h := range t.Hostnames {
				routes += fmt.Sprintf(`<code>%s</code> `, h)
			}
		} else {
			routes = fmt.Sprintf(`<code>:%d</code>`, t.ListenPort)
		}
		clientInfo := `<span class="has-text-grey is-size-7">-</span>`
		if t.Connected {
			clientInfo = fmt.Sprintf(`<span class="is-size-7">%s</span>`, t.ClientAddr)
		}

		fmt.Fprintf(w, `<tr>
  <td><span class="status-dot %s"></span></td>
  <td><strong>%s</strong></td>
  <td><span class="tag %s is-light">%s</span></td>
  <td>%s</td>
  <td>%s</td>
  <td class="has-text-right"><span class="metric-value">%d</span></td>
  <td class="has-text-right is-size-7">%s in / %s out</td>
  <td class="has-text-right"><span class="metric-value">%d</span></td>
  <td><button class="button is-small is-outlined" onclick="regenerateSecret('%s')">New Secret</button></td>
</tr>`, statusClass, t.ID, typeClass, t.Type, routes, clientInfo,
			t.Requests, t.BytesInFmt(), t.BytesOutFmt(), t.ActiveConns, t.ID)
	}
}

func (s *Server) buildTunnelViews() []admin.TunnelView {
	tunnels := s.registry.AllTunnels()
	views := make([]admin.TunnelView, len(tunnels))
	for i, t := range tunnels {
		views[i] = admin.TunnelView{
			ID:          t.ID,
			Type:        t.Type,
			Hostnames:   t.Hostnames,
			ListenPort:  t.ListenPort,
			Connected:   t.IsConnected(),
			ClientAddr:  t.ClientAddr(),
			Requests:    t.Metrics.RequestCount.Load(),
			BytesIn:     t.Metrics.BytesIn.Load(),
			BytesOut:    t.Metrics.BytesOut.Load(),
			ActiveConns: int32(t.Metrics.ActiveConns.Load()),
		}
	}
	return views
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

	tok := token.FormatToken(tunnelID, plaintext)
	sshAddr := fmt.Sprintf("<server>:%d", s.cfg.Server.SSHPort)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tok,
		"command": fmt.Sprintf("gatecrash client --server %s --token %s --target 127.0.0.1:8000", sshAddr, tok),
		"docker":  fmt.Sprintf("docker run -e GATECRASH_SERVER=%s -e GATECRASH_TOKEN=%s -e GATECRASH_TARGET=app:8000 ghcr.io/jclement/gatecrash:latest gatecrash client", sshAddr, tok),
	})

	slog.Info("regenerated tunnel secret", "tunnel", tunnelID)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, s.version)
}

func (s *Server) handleAPITunnels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "[")
	for i, t := range s.registry.AllTunnels() {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"id":"%s","type":"%s","connected":%v,"active_conns":%d,"bytes_in":%d,"bytes_out":%d,"requests":%d}`,
			t.ID, t.Type, t.IsConnected(), t.Metrics.ActiveConns.Load(),
			t.Metrics.BytesIn.Load(), t.Metrics.BytesOut.Load(), t.Metrics.RequestCount.Load())
	}
	fmt.Fprint(w, "]")
}

// handleConfigReload applies a new config, updating the tunnel registry and config reference.
func (s *Server) handleConfigReload(newCfg *config.Config) {
	tunnels := make([]struct {
		ID           string
		Type         string
		Hostnames    []string
		ListenPort   int
		PreserveHost bool
	}, len(newCfg.Tunnel))
	for i, tc := range newCfg.Tunnel {
		tunnels[i] = struct {
			ID           string
			Type         string
			Hostnames    []string
			ListenPort   int
			PreserveHost bool
		}{
			ID:           tc.ID,
			Type:         tc.Type,
			Hostnames:    tc.Hostnames,
			ListenPort:   tc.ListenPort,
			PreserveHost: tc.PreserveHost,
		}
	}
	s.registry.Reload(tunnels)
	s.cfg = newCfg

	slog.Info("config reloaded",
		"tunnels", len(newCfg.Tunnel),
		"redirects", len(newCfg.Redirect),
	)

	s.sse.Broadcast("config-reload", "ok")
}

func httpToHTTPSRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.RequestURI
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
