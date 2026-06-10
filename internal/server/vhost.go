package server

import (
	"fmt"
	"html"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
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
// user in the allowed set, OR the service secret. Returns true to proceed;
// false means it already wrote a response (a login redirect, a 401, or a 403).
// On success it injects the identity headers.
func (s *Server) enforceAuthPolicy(w http.ResponseWriter, r *http.Request, host string, pol *AuthPolicyState) bool {
	r.Header.Del(pol.headerName())
	r.Header.Del("X-Gatecrash-Role")
	r.Header.Del("X-Gatecrash-Id")

	// 1. Service secret (HTTP Basic), for non-interactive clients.
	if pol.usesSecret() {
		if s.checkServiceSecret(r, pol) {
			r.Header.Set(pol.headerName(), ServiceAuthUsername)
			r.Header.Set("X-Gatecrash-Id", ServiceAuthUsername)
			r.Header.Set("X-Gatecrash-Role", "service")
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

	// 3. Secret-only policy with no/invalid credentials → Basic challenge.
	if pol.usesSecret() {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, host))
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	s.serveErrorPage(w, r, http.StatusForbidden, "Access Denied", "No authentication method available.")
	return false
}

// serveErrorPage renders a generic error/notice. message is trusted HTML so
// callers may include markup like <strong> — they must html.EscapeString any
// dynamic values they interpolate into it (unchanged from the previous contract).
func (s *Server) serveErrorPage(w http.ResponseWriter, _ *http.Request, status int, title, message string) {
	s.renderStandalonePage(w, status, "error", errorPageData{
		Title:   title,
		Status:  status,
		Heading: title,
		Message: template.HTML(message),
	})
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
	// The authorize link carries only the return URL — the admin host resolves the
	// tunnel from its hostname, so no internal tunnel ID is exposed to the visitor.
	returnURL := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
	authorizeURL := fmt.Sprintf("%s/authorize-ip?return=%s", base, url.QueryEscape(returnURL))

	s.renderStandalonePage(w, http.StatusForbidden, "ip-restricted", ipRestrictedPageData{
		Title:        "Access Restricted",
		Host:         host,
		IP:           ip,
		AuthorizeURL: authorizeURL,
	})
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
// initiateTunnelLogin and handleTunnelLoginComplete live in tunnellogin.go.

// serveAdmin applies security headers and delegates to the admin mux.
func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'")
	s.adminMux.ServeHTTP(w, r)
}
