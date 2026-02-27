package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

type adminCtxKey string

const ctxKeyAdminPrefix adminCtxKey = "admin_prefix"

// adminPrefix returns the URL prefix for admin routes from the request context.
func adminPrefix(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyAdminPrefix).(string); ok {
		return v
	}
	return ""
}

// ServeHTTP routes requests based on Host header.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)

	// 1. Always serve admin panel at /.well-known/gatecrash/
	if strings.HasPrefix(r.URL.Path, "/.well-known/gatecrash") {
		if s.noWebAdmin {
			http.NotFound(w, r)
			return
		}
		// Store the prefix in context so auth redirects work correctly
		ctx := context.WithValue(r.Context(), ctxKeyAdminPrefix, "/.well-known/gatecrash")
		r = r.WithContext(ctx)
		// Strip the prefix for admin mux routing
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/.well-known/gatecrash")
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		s.adminMux.ServeHTTP(w, r)
		return
	}

	// 2. Check redirects before tunnel lookup
	for _, redir := range s.cfg.Redirect {
		if host == redir.From {
			target := "https://" + redir.To
			if redir.PreservePath {
				target += r.URL.RequestURI()
			}
			slog.Debug("redirect", "from", host, "to", target)
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
	}

	// 3. Look up tunnel by hostname
	tunnel := s.registry.FindByHostname(host)
	if tunnel == nil {
		// If this is the admin host or an IP, serve admin panel
		if s.isAdminHost(host) && !s.noWebAdmin {
			s.adminMux.ServeHTTP(w, r)
			return
		}
		slog.Debug("no tunnel for host", "host", host)
		s.serveErrorPage(w, r, http.StatusNotFound,
			"No Tunnel Configured",
			fmt.Sprintf("There is no tunnel configured for <strong>%s</strong>.", host),
		)
		return
	}

	if !tunnel.IsConnected() {
		s.serveErrorPage(w, r, http.StatusBadGateway,
			"Service Offline",
			fmt.Sprintf("The tunnel <strong>%s</strong> is currently offline. The service may be restarting.", tunnel.ID),
		)
		return
	}

	s.proxyHTTP(w, r, tunnel)
}

func (s *Server) isAdminHost(host string) bool {
	if s.cfg.Server.AdminHost != "" {
		return host == s.cfg.Server.AdminHost
	}
	return isIPAddress(host)
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

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func isIPAddress(host string) bool {
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return net.ParseIP(host) != nil
}
