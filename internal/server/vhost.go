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

	// 2.5 Handle login completion on tunnel hostnames (handed off from admin host)
	if strings.HasPrefix(r.URL.Path, "/.gatecrash/auth/complete") {
		s.handleTunnelLoginComplete(w, r, host)
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

	// Strip any inbound trusted-identity headers to prevent spoofing, on every
	// path — including tunnels with no auth policy, which never reach
	// enforceAuthPolicy. The entire X-Gatecrash-* namespace is server-owned;
	// the auth policy re-injects identity only after a successful login. A
	// policy with a custom (non-namespaced) header name strips that too, below.
	stripTrustedHeaders(r.Header)

	// IP policy gate. Clients in a permanent range or holding a live self-service
	// grant pass; everyone else is shown a page to authorize their current IP.
	if pol := s.registry.FindIPPolicy(tunnel.IPPolicy()); pol != nil {
		ip := clientIP(r)
		if !pol.Allows(ip) && !s.ipAllow.IsGranted(pol.ID, ip) {
			slog.Debug("ip policy blocked", "tunnel", tunnel.ID, "policy", pol.ID, "ip", ip, "host", host)
			s.serveIPAuthorizePage(w, r, tunnel, host, adminHost, httpsPort)
			return
		}
	}

	// Auth policy gate (any enabled method satisfies it).
	if pol := s.registry.FindAuthPolicy(tunnel.AuthPolicy()); pol != nil {
		if !s.enforceAuthPolicy(w, r, host, pol) {
			return // enforceAuthPolicy already wrote a response (challenge/deny)
		}
	}

	s.proxyHTTP(w, r, tunnel)
}

// stripTrustedHeaders removes every server-owned identity header from an inbound
// request so a client can never spoof them. The whole X-Gatecrash-* namespace is
// reserved for the server; auth policies re-inject identity only after a verified
// login (or static-password) success.
func stripTrustedHeaders(h http.Header) {
	for name := range h {
		if len(name) >= len(trustedHeaderPrefix) &&
			strings.EqualFold(name[:len(trustedHeaderPrefix)], trustedHeaderPrefix) {
			h.Del(name)
		}
	}
}

const trustedHeaderPrefix = "X-Gatecrash-"

// enforceAuthPolicy authenticates a request against an auth policy: a logged-in
// user in the allowed set, OR the static password. Returns true to proceed;
// false means it already wrote a response (a login redirect, a 401, or a 403).
// On success it injects the identity headers.
func (s *Server) enforceAuthPolicy(w http.ResponseWriter, r *http.Request, host string, pol *AuthPolicyState) bool {
	r.Header.Del(pol.headerName())
	r.Header.Del("X-Gatecrash-Role")

	// 1. Static password (HTTP Basic), if provided.
	if pol.usesPassword() {
		if user, ok := s.checkBasic(r, pol); ok {
			r.Header.Set(pol.headerName(), user)
			r.Header.Set("X-Gatecrash-Role", "basic")
			return true
		}
	}

	// 2. Logged-in user (tunnel session established via the admin handoff). The
	// user must still exist and still be in the policy's allowed set.
	if pol.requiresLogin() {
		if userID, _, ok := s.tunnelSession.ValidateSession(r, host); ok {
			if u := s.users.Get(userID); u != nil {
				if !pol.allowsUser(userID) {
					s.serveErrorPage(w, r, http.StatusForbidden, "Access Denied",
						fmt.Sprintf("You do not have access to <strong>%s</strong>.", html.EscapeString(host)))
					return false
				}
				// Inject identity: the readable name on the (configurable) user
				// header, the stable opaque id, and the live role.
				r.Header.Set(pol.headerName(), u.Name)
				r.Header.Set("X-Gatecrash-Id", u.ID)
				r.Header.Set("X-Gatecrash-Role", u.Role)
				return true
			}
		}
		// Not logged in — start the cross-host login handoff.
		s.initiateTunnelLogin(w, r, host)
		return false
	}

	// 3. Password-only policy with no/invalid credentials → Basic challenge.
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

// initiateTunnelLogin redirects an unauthenticated visitor of a protected tunnel
// to the admin host, which (once they're signed in) hands a one-time token back
// to this hostname to establish a tunnel session.
func (s *Server) initiateTunnelLogin(w http.ResponseWriter, r *http.Request, hostname string) {
	s.cfgMu.RLock()
	adminHost := s.cfg.Server.AdminHost
	httpsPort := s.cfg.Server.HTTPSPort
	s.cfgMu.RUnlock()

	if adminHost == "" {
		s.serveErrorPage(w, r, http.StatusForbidden, "Access Denied",
			"This service requires authentication, but no admin host is configured.")
		return
	}
	returnURL := fmt.Sprintf("https://%s%s", hostname, r.URL.RequestURI())
	base := "https://" + adminHost
	if httpsPort != 443 {
		base = fmt.Sprintf("https://%s:%d", adminHost, httpsPort)
	}
	http.Redirect(w, r, fmt.Sprintf("%s/tunnel-login?hostname=%s&return=%s",
		base, url.QueryEscape(hostname), url.QueryEscape(returnURL)), http.StatusFound)
}

// handleTunnelLoginComplete consumes the one-time handoff token and sets the
// tunnel session cookie for the authenticated user on this hostname.
func (s *Server) handleTunnelLoginComplete(w http.ResponseWriter, r *http.Request, hostname string) {
	oneTimeToken := r.URL.Query().Get("token")
	if oneTimeToken == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	s.pendingTunnelAuthMu.Lock()
	result, ok := s.pendingTunnelAuth[oneTimeToken]
	if ok {
		delete(s.pendingTunnelAuth, oneTimeToken)
	}
	s.pendingTunnelAuthMu.Unlock()

	if !ok || time.Now().After(result.expires) {
		s.serveErrorPage(w, r, http.StatusForbidden, "Authentication Failed",
			"Login token is invalid or expired. Please try again.")
		return
	}
	if result.hostname != hostname {
		http.Error(w, "hostname mismatch", http.StatusBadRequest)
		return
	}
	if err := s.tunnelSession.CreateSession(w, hostname, result.userID, result.role); err != nil {
		slog.Error("failed to create tunnel session", "error", err)
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	dest := "/"
	if result.returnURL != "" {
		if u, err := url.Parse(result.returnURL); err == nil && u.Scheme == "https" && strings.EqualFold(u.Hostname(), hostname) {
			dest = result.returnURL
		}
	}
	http.Redirect(w, r, dest, http.StatusFound)
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
