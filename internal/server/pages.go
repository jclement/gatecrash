package server

import (
	"bytes"
	"html/template"
	"log/slog"
	"net/http"
)

// This file renders the small standalone, public-facing pages (error, IP
// authorize/restricted, enrollment) through a single auto-escaping html/template
// set, replacing the per-page fmt.Fprintf string assembly that duplicated the
// card CSS and was one careless edit away from an HTML-injection bug. Unlike the
// admin pages these have no nav shell, so they don't go through admin.Handlers.

var standalonePages = template.Must(template.New("std").Parse(standalonePagesTmpl))

// renderStandalonePage renders one named standalone template with the given
// status. It buffers first so a template error can't emit a half-written page.
func (s *Server) renderStandalonePage(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := standalonePages.ExecuteTemplate(&buf, name, data); err != nil {
		slog.Error("failed to render standalone page", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// Page data types. Every type carries Title (used by the shared head template).

// errorPageData renders a generic error/notice. Message is trusted HTML: callers
// pass an already-escaped fragment (so they can include <strong>…</strong>),
// exactly as the previous serveErrorPage contract required.
type errorPageData struct {
	Title   string
	Status  int
	Heading string
	Message template.HTML
}

// enrollPageData renders the self-service enrollment page. Mode is one of
// "static" (already permanently allowed), "extend" (already granted), or "" (new).
type enrollPageData struct {
	Title     string
	Heading   string
	IP        string
	Label     string
	Remaining string
	Mode      string
	Token     string
}

// ipAuthorizePageData renders the logged-in "authorize this IP" form.
type ipAuthorizePageData struct {
	Title     string
	IP        string
	Name      string
	TunnelID  string
	ReturnURL string
	CSRF      string
}

// ipAuthorizedPageData renders the success confirmation after a grant.
type ipAuthorizedPageData struct {
	Title   string
	Heading string
	IP      string
	Name    string
}

// ipRestrictedPageData renders the "access restricted, sign in to authorize" page.
type ipRestrictedPageData struct {
	Title        string
	Host         string
	IP           string
	AuthorizeURL string
}

const standalonePagesTmpl = `
{{define "head"}}<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — Gatecrash</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f5f5; color: #333; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; }
  .card { background: white; border-radius: 8px; padding: 48px; max-width: 480px;
          text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  .code { font-size: 72px; font-weight: 700; color: #ccc; margin-bottom: 8px; }
  h1 { font-size: 20px; margin-bottom: 12px; }
  h1.success { color: #16a34a; }
  p { color: #666; line-height: 1.6; font-size: 14px; margin-bottom: 8px; }
  .ip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #333; }
  .btn { display: inline-block; margin: 16px 4px 0; padding: 12px 24px; background: #2563eb;
         color: white; border: none; cursor: pointer; border-radius: 6px; font-size: 14px;
         font-weight: 600; text-decoration: none; }
  .btn:hover { background: #1d4ed8; }
  form { display: inline-block; }
  .footer { margin-top: 24px; font-size: 12px; color: #bbb; }
</style>
</head>
<body>
<div class="card">
{{end}}

{{define "foot"}}  <div class="footer">Gatecrash</div>
</div>
</body>
</html>{{end}}

{{define "error"}}{{template "head" .}}  <div class="code">{{.Status}}</div>
  <h1>{{.Heading}}</h1>
  <p>{{.Message}}</p>
{{template "foot" .}}{{end}}

{{define "enroll"}}{{template "head" .}}  <h1>{{.Heading}}</h1>
{{if eq .Mode "static"}}  <p>Your IP <span class="ip">{{.IP}}</span> is permanently allowed by <strong>{{.Label}}</strong>.</p>
{{else if eq .Mode "extend"}}  <p>Your IP <span class="ip">{{.IP}}</span> is authorized by <strong>{{.Label}}</strong> — access expires in {{.Remaining}}.</p>
  <form method="POST" action="/enroll/{{.Token}}"><button class="btn" type="submit">Extend 7 days</button></form>
{{else}}  <p>You've been invited to access services protected by <strong>{{.Label}}</strong>. Authorize your current IP <span class="ip">{{.IP}}</span> for 7 days?</p>
  <form method="POST" action="/enroll/{{.Token}}"><button class="btn" type="submit">Authorize my IP</button></form>
{{end}}{{template "foot" .}}{{end}}

{{define "ip-authorize"}}{{template "head" .}}  <h1>Authorize this IP</h1>
  <p>Grant <span class="ip">{{.IP}}</span> access to <strong>{{.Name}}</strong> for 7 days?</p>
  <form method="POST" action="/authorize-ip">
    <input type="hidden" name="tunnel" value="{{.TunnelID}}">
    <input type="hidden" name="return" value="{{.ReturnURL}}">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <button class="btn" type="submit">Authorize this IP</button>
  </form>
{{template "foot" .}}{{end}}

{{define "ip-authorized"}}{{template "head" .}}  <h1 class="success">&#10003; {{.Heading}}</h1>
  <p>Your IP <span class="ip">{{.IP}}</span> may now access <strong>{{.Name}}</strong> for the next 7 days.</p>
  <p>You can close this page.</p>
{{template "foot" .}}{{end}}

{{define "ip-restricted"}}{{template "head" .}}  <h1>Access Restricted</h1>
  <p>Access to <strong>{{.Host}}</strong> is limited to authorized IP addresses.</p>
  <p>Your current address is <span class="ip">{{.IP}}</span>.</p>
  <a class="btn" href="{{.AuthorizeURL}}">Authorize this IP</a>
  <p style="margin-top:16px;font-size:12px;color:#999;">You'll be asked to sign in to authorize. The grant lasts 7 days.</p>
{{template "foot" .}}{{end}}
`
