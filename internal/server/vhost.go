package server

import (
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jclement/gatecrash/internal/admin"
)

// ServeHTTP routes requests based on Host header.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)

	// Snapshot config fields under read lock (released before proxying)
	s.cfgMu.RLock()
	redirects := s.cfg.Redirect
	adminHost := s.cfg.Server.AdminHost
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()

	// 1. Check redirects before tunnel lookup
	for _, redir := range redirects {
		if strings.EqualFold(host, redir.From) {
			target := redir.To
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				target = "https://" + target
			}
			if redir.PreservePath {
				target += r.URL.RequestURI()
			}
			slog.Debug("redirect", "from", host, "to", target)
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
	}

	// 2. Admin panel — served at admin_host's root
	if adminHost != "" && strings.EqualFold(host, adminHost) {
		s.serveAdmin(w, r)
		return
	}

	// 2.5 Handle auth completion on tunnel hostnames (redirected from admin host)
	if strings.HasPrefix(r.URL.Path, "/.gatecrash/oidc/complete") {
		s.handleTunnelOIDCComplete(w, r, host)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/.gatecrash/auth/complete") {
		s.handleTunnelPasskeyComplete(w, r, host)
		return
	}

	// 3. Look up tunnel by hostname
	tunnel := s.registry.FindByHostname(host)
	if tunnel == nil {
		slog.Debug("no tunnel for host", "host", host)
		s.serveErrorPage(w, r, http.StatusNotFound,
			"No Tunnel Configured",
			fmt.Sprintf("There is no tunnel configured for <strong>%s</strong>.", html.EscapeString(host)),
		)
		return
	}

	if !tunnel.IsConnected() {
		slog.Debug("tunnel offline", "tunnel", tunnel.ID, "host", host)
		s.serveErrorPage(w, r, http.StatusBadGateway,
			"Service Offline",
			fmt.Sprintf("The service at <strong>%s</strong> is currently offline.", html.EscapeString(host)),
		)
		return
	}

	// Strip any inbound trusted-identity header to prevent spoofing. The auth
	// policy re-injects it after a successful authentication.
	r.Header.Del("x-Gatecrash-User")

	// IP policy gate. Clients in a permanent range or holding a live self-service
	// grant pass; everyone else is shown a page to authorize their current IP.
	if pol := s.registry.FindIPPolicy(tunnel.IPPolicyID); pol != nil {
		ip := clientIP(r)
		if !pol.Allows(ip) && !s.ipAllow.IsGranted(pol.ID, ip) {
			slog.Debug("ip policy blocked", "tunnel", tunnel.ID, "policy", pol.ID, "ip", ip, "host", host)
			s.serveIPAuthorizePage(w, r, tunnel, host, adminHost, httpsPort)
			return
		}
	}

	// Auth policy gate (any enabled method satisfies it).
	if pol := s.registry.FindAuthPolicy(tunnel.AuthPolicyID); pol != nil {
		if !s.enforceAuthPolicy(w, r, host, pol) {
			return // enforceAuthPolicy already wrote a response (challenge/deny)
		}
	}

	s.proxyHTTP(w, r, tunnel)
}

// enforceAuthPolicy authenticates a request against an auth policy. Methods are
// OR'd. Returns true to proceed; false means it already wrote a response (a
// challenge redirect, a 401, or a 403).
func (s *Server) enforceAuthPolicy(w http.ResponseWriter, r *http.Request, host string, pol *AuthPolicyState) bool {
	r.Header.Del(pol.headerName())

	// 1. HTTP Basic (static password), if provided.
	if pol.usesPassword() {
		if user, ok := s.checkBasic(r, pol); ok {
			r.Header.Set(pol.headerName(), user)
			return true
		}
	}

	// 2. System session (OIDC or passkey, per global config).
	if pol.usesSystem() {
		if s.oidcProvider != nil && s.tunnelAuth != nil {
			if claims, ok := s.tunnelAuth.ValidateSession(r, host); ok {
				if !admin.MatchesClaim(claims.Raw, pol.ClaimName, pol.ClaimValue) {
					s.serveErrorPage(w, r, http.StatusForbidden, "Access Denied",
						fmt.Sprintf("You do not have access to <strong>%s</strong>.", html.EscapeString(host)))
					return false
				}
				val := claims.GetClaimValue(pol.HeaderClaim)
				if val == "" {
					val = claims.Email
				}
				r.Header.Set(pol.headerName(), val)
				return true
			}
		} else if s.passkeyTunnelAuth.ValidateSession(r, host) {
			return true
		}
	}

	// 3. No method satisfied — challenge. Prefer the browser system flow; fall
	// back to a Basic challenge for password-only policies.
	if pol.usesSystem() {
		if s.oidcProvider != nil && s.tunnelAuth != nil {
			s.initiateTunnelAuth(w, r, host)
		} else {
			s.initiateTunnelPasskeyAuth(w, r, host)
		}
		return false
	}
	if pol.usesPassword() {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, host))
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	s.serveErrorPage(w, r, http.StatusForbidden, "Access Denied", "No authentication method available.")
	return false
}

func (s *Server) serveErrorPage(w http.ResponseWriter, _ *http.Request, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%d — Gatecrash</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f5f5; color: #333; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; }
  .card { background: white; border-radius: 8px; padding: 48px; max-width: 480px;
          text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  .code { font-size: 72px; font-weight: 700; color: #ccc; margin-bottom: 8px; }
  h1 { font-size: 20px; margin-bottom: 12px; }
  p { color: #666; line-height: 1.6; font-size: 14px; }
  .footer { margin-top: 24px; font-size: 12px; color: #bbb; }
</style>
</head>
<body>
<div class="card">
  <div class="code">%d</div>
  <h1>%s</h1>
  <p>%s</p>
  <div class="footer">Gatecrash</div>
</div>
</body>
</html>`, status, status, title, message)
}

// isSafeReturnURL validates that a return URL is a relative path (not an open redirect).
func isSafeReturnURL(u string) bool {
	return len(u) > 0 && u[0] == '/' && (len(u) == 1 || u[1] != '/')
}

// clientIP extracts the source IP of a request. The gatecrash server is the
// public edge, so RemoteAddr is the real client address.
func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}

// serveIPAuthorizePage is shown to a client whose IP is not on a tunnel's
// allowlist. It offers a one-click flow to authorize the current IP, which runs
// through the admin host's authenticated /authorize-ip endpoint.
func (s *Server) serveIPAuthorizePage(w http.ResponseWriter, r *http.Request, tunnel *TunnelState, host, adminHost string, httpsPort int) {
	ip := ipString(clientIP(r))

	// Without an admin host there is no authenticated enrollment endpoint, so we
	// can only report the denial.
	if adminHost == "" {
		s.serveErrorPage(w, r, http.StatusForbidden, "Access Restricted",
			fmt.Sprintf("Access to <strong>%s</strong> is restricted by IP. Your address <strong>%s</strong> is not allowed.",
				html.EscapeString(host), html.EscapeString(ip)))
		return
	}

	base := "https://" + adminHost
	if httpsPort != 443 {
		base = fmt.Sprintf("https://%s:%d", adminHost, httpsPort)
	}
	returnURL := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
	authorizeURL := fmt.Sprintf("%s/authorize-ip?tunnel=%s&return=%s",
		base, url.QueryEscape(tunnel.ID), url.QueryEscape(returnURL))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Restricted — Gatecrash</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f5f5; color: #333; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; }
  .card { background: white; border-radius: 8px; padding: 48px; max-width: 480px;
          text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  h1 { font-size: 20px; margin-bottom: 12px; }
  p { color: #666; line-height: 1.6; font-size: 14px; margin-bottom: 12px; }
  .ip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #333; }
  .btn { display: inline-block; margin-top: 16px; padding: 12px 24px; background: #2563eb;
         color: white; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 600; }
  .btn:hover { background: #1d4ed8; }
  .footer { margin-top: 24px; font-size: 12px; color: #bbb; }
</style>
</head>
<body>
<div class="card">
  <h1>Access Restricted</h1>
  <p>Access to <strong>%s</strong> is limited to authorized IP addresses.</p>
  <p>Your current address is <span class="ip">%s</span>.</p>
  <a class="btn" href="%s">Authorize this IP</a>
  <p style="margin-top:16px;font-size:12px;color:#999;">You'll be asked to sign in to authorize. The grant lasts 7 days.</p>
  <div class="footer">Gatecrash</div>
</div>
</body>
</html>`, html.EscapeString(host), html.EscapeString(ip), html.EscapeString(authorizeURL))
}

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

// initiateTunnelAuth redirects the user to the OIDC provider for tunnel authentication.
// The OIDC callback always goes through the admin host, avoiding the need to register
// per-tunnel redirect URIs with the OIDC provider.
func (s *Server) initiateTunnelAuth(w http.ResponseWriter, r *http.Request, hostname string) {
	returnURL := r.URL.RequestURI()
	authURL, _, err := s.oidcProvider.AuthURL("tunnel", returnURL, hostname)
	if err != nil {
		slog.Error("failed to generate tunnel OIDC auth URL", "error", err, "hostname", hostname)
		s.serveErrorPage(w, r, http.StatusInternalServerError,
			"Authentication Error",
			"Failed to initiate authentication.")
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleTunnelOIDCComplete handles the final step of tunnel OIDC auth.
// The browser is redirected here from the admin host after a successful OIDC exchange,
// carrying a one-time token that maps to the stored auth result.
func (s *Server) handleTunnelOIDCComplete(w http.ResponseWriter, r *http.Request, hostname string) {
	if s.tunnelAuth == nil {
		http.Error(w, "tunnel auth is not configured", http.StatusBadRequest)
		return
	}

	oneTimeToken := r.URL.Query().Get("token")
	if oneTimeToken == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	// Look up and consume the pending auth result
	s.pendingTunnelAuthMu.Lock()
	result, ok := s.pendingTunnelAuth[oneTimeToken]
	if ok {
		delete(s.pendingTunnelAuth, oneTimeToken)
	}
	s.pendingTunnelAuthMu.Unlock()

	if !ok || time.Now().After(result.expires) {
		s.serveErrorPage(w, r, http.StatusForbidden,
			"Authentication Failed",
			"Authentication token is invalid or expired. Please try again.")
		return
	}

	// Verify the hostname matches what was in the OIDC flow
	if result.hostname != hostname {
		http.Error(w, "hostname mismatch", http.StatusBadRequest)
		return
	}

	// Evaluate the optional claim filter from the tunnel's auth policy.
	if tunnel := s.registry.FindByHostname(hostname); tunnel != nil {
		if pol := s.registry.FindAuthPolicy(tunnel.AuthPolicyID); pol != nil &&
			!admin.MatchesClaim(result.claims.Raw, pol.ClaimName, pol.ClaimValue) {
			s.serveErrorPage(w, r, http.StatusForbidden,
				"Access Denied",
				fmt.Sprintf("You do not have access to <strong>%s</strong>.", html.EscapeString(hostname)))
			return
		}
	}

	// Create tunnel auth session cookie on this hostname
	if err := s.tunnelAuth.CreateSession(w, result.claims, hostname); err != nil {
		slog.Error("failed to create tunnel auth session", "error", err)
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}

	// Redirect to the original URL (validated to prevent open redirect)
	returnURL := "/"
	if result.returnURL != "" && isSafeReturnURL(result.returnURL) {
		returnURL = result.returnURL
	}
	http.Redirect(w, r, returnURL, http.StatusFound)
}

// initiateTunnelPasskeyAuth redirects the user to the admin host to verify their passkey session.
func (s *Server) initiateTunnelPasskeyAuth(w http.ResponseWriter, r *http.Request, hostname string) {
	s.cfgMu.RLock()
	adminHost := s.cfg.Server.AdminHost
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()

	returnURL := r.URL.RequestURI()
	verifyURL := fmt.Sprintf("https://%s/tunnel-auth/verify?hostname=%s&return=%s",
		adminHost, url.QueryEscape(hostname), url.QueryEscape(returnURL))
	if httpsPort != 443 {
		verifyURL = fmt.Sprintf("https://%s:%d/tunnel-auth/verify?hostname=%s&return=%s",
			adminHost, httpsPort, url.QueryEscape(hostname), url.QueryEscape(returnURL))
	}

	http.Redirect(w, r, verifyURL, http.StatusFound)
}

// handleTunnelPasskeyComplete handles the final step of passkey-based tunnel auth.
// The browser is redirected here from the admin host after verifying the admin session,
// carrying a one-time token that maps to the stored auth result.
func (s *Server) handleTunnelPasskeyComplete(w http.ResponseWriter, r *http.Request, hostname string) {
	oneTimeToken := r.URL.Query().Get("token")
	if oneTimeToken == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	// Look up and consume the pending auth result
	s.pendingTunnelAuthMu.Lock()
	result, ok := s.pendingTunnelAuth[oneTimeToken]
	if ok {
		delete(s.pendingTunnelAuth, oneTimeToken)
	}
	s.pendingTunnelAuthMu.Unlock()

	if !ok || time.Now().After(result.expires) {
		s.serveErrorPage(w, r, http.StatusForbidden,
			"Authentication Failed",
			"Authentication token is invalid or expired. Please try again.")
		return
	}

	if !result.passkey {
		http.Error(w, "invalid token type", http.StatusBadRequest)
		return
	}

	// Verify the hostname matches
	if result.hostname != hostname {
		http.Error(w, "hostname mismatch", http.StatusBadRequest)
		return
	}

	// Create passkey tunnel session cookie on this hostname
	if err := s.passkeyTunnelAuth.CreateSession(w, hostname); err != nil {
		slog.Error("failed to create passkey tunnel session", "error", err)
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}

	// Redirect to the original URL
	returnURL := "/"
	if result.returnURL != "" && isSafeReturnURL(result.returnURL) {
		returnURL = result.returnURL
	}
	http.Redirect(w, r, returnURL, http.StatusFound)
}

// serveAdmin applies security headers and delegates to the admin mux.
func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'")
	s.adminMux.ServeHTTP(w, r)
}
