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
// It deliberately carries no policy/tunnel identifier: the enrollment link is
// public, so internal IDs must not be disclosed to whoever holds it.
type enrollPageData struct {
	Title     string
	Heading   string
	IP        string
	Remaining string
	Mode      string
	Token     string
}

// ipAuthorizePageData renders the logged-in "authorize this IP" form. It carries
// the service hostname (Name) and the return URL, but no internal tunnel/policy
// ID — the admin host resolves the tunnel from the return URL's hostname.
type ipAuthorizePageData struct {
	Title     string
	IP        string
	Name      string
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

// serviceLoginPageData renders the bespoke "this service is protected — sign in"
// page shown during the cross-host auth handoff (not the admin login).
type serviceLoginPageData struct {
	Title       string
	ServiceHost string
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
{{if eq .Mode "static"}}  <p>Your IP <span class="ip">{{.IP}}</span> is already permanently allowed.</p>
{{else if eq .Mode "extend"}}  <p>Your IP <span class="ip">{{.IP}}</span> is authorized &mdash; access expires in {{.Remaining}}.</p>
  <form method="POST" action="/enroll/{{.Token}}"><button class="btn" type="submit">Extend 7 days</button></form>
{{else}}  <p>You've been invited to access a protected service. Authorize your current IP <span class="ip">{{.IP}}</span> for 7 days?</p>
  <form method="POST" action="/enroll/{{.Token}}"><button class="btn" type="submit">Authorize my IP</button></form>
{{end}}{{template "foot" .}}{{end}}

{{define "ip-authorize"}}{{template "head" .}}  <h1>Authorize this IP</h1>
  <p>Grant <span class="ip">{{.IP}}</span> access to <strong>{{.Name}}</strong> for 7 days?</p>
  <form method="POST" action="/authorize-ip">
    <input type="hidden" name="return" value="{{.ReturnURL}}">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <button class="btn" type="submit">Authorize this IP</button>
  </form>
{{template "foot" .}}{{end}}

{{define "ip-authorized"}}{{template "head" .}}  <h1 class="success">&#10003; {{.Heading}}</h1>
{{if .Name}}  <p>Your IP <span class="ip">{{.IP}}</span> may now access <strong>{{.Name}}</strong> for the next 7 days.</p>
{{else}}  <p>Your IP <span class="ip">{{.IP}}</span> is now authorized for the next 7 days.</p>
{{end}}  <p>You can close this page.</p>
{{template "foot" .}}{{end}}

{{define "ip-restricted"}}{{template "head" .}}  <h1>Access Restricted</h1>
  <p>Access to <strong>{{.Host}}</strong> is limited to authorized IP addresses.</p>
  <p>Your current address is <span class="ip">{{.IP}}</span>.</p>
  <a class="btn" href="{{.AuthorizeURL}}">Authorize this IP</a>
  <p style="margin-top:16px;font-size:12px;color:#999;">You'll be asked to sign in to authorize. The grant lasts 7 days.</p>
{{template "foot" .}}{{end}}

{{define "service-login"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — {{.ServiceHost}}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         min-height: 100vh; display: flex; align-items: center; justify-content: center;
         padding: 24px; color: #0f172a;
         background: linear-gradient(135deg, #eef2ff 0%, #f8fafc 55%, #eff6ff 100%); }
  .card { background: #fff; border-radius: 16px; padding: 40px 36px; max-width: 420px; width: 100%;
          text-align: center; box-shadow: 0 12px 40px rgba(2,6,23,.12); border: 1px solid #eef2f7; }
  .shield { width: 56px; height: 56px; margin: 0 auto 20px; border-radius: 15px; display: flex;
            align-items: center; justify-content: center; background: #eff6ff; color: #2563eb; }
  .shield svg { width: 30px; height: 30px; }
  .eyebrow { font-size: 12px; font-weight: 600; letter-spacing: .05em; text-transform: uppercase;
             color: #64748b; margin-bottom: 6px; }
  h1 { font-size: 21px; font-weight: 700; margin-bottom: 12px; letter-spacing: -.01em; }
  .host { display: inline-block; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-size: 13px; background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 8px;
          padding: 6px 12px; margin-bottom: 18px; word-break: break-all; max-width: 100%; }
  p.sub { font-size: 14px; color: #64748b; line-height: 1.6; margin-bottom: 24px; }
  button { width: 100%; padding: 13px 20px; background: #2563eb; color: #fff; border: none;
           border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer;
           display: inline-flex; align-items: center; justify-content: center; gap: 8px;
           transition: background .15s; }
  button:hover { background: #1d4ed8; }
  button:disabled { opacity: .6; cursor: default; }
  button svg { width: 18px; height: 18px; }
  .status { font-size: 12px; margin-top: 14px; min-height: 16px; color: #64748b; }
  .status.err { color: #dc2626; }
  .status.ok { color: #16a34a; }
  .foot { margin-top: 26px; font-size: 12px; color: #94a3b8; }
</style>
</head>
<body>
<div class="card">
  <div class="shield">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>
  </div>
  <div class="eyebrow">Protected service</div>
  <h1>Sign in to continue</h1>
  <div class="host">{{.ServiceHost}}</div>
  <p class="sub">This service is protected by Gatecrash. Sign in with your passkey to continue &mdash; access is limited to authorized users.</p>
  <button id="signin" type="button">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>
    Sign in with a passkey
  </button>
  <div id="status" class="status"></div>
  <div class="foot">&#128274; Secured by Gatecrash</div>
</div>
<script src="/static/js/webauthn.js"></script>
<script>
document.getElementById('signin').addEventListener('click', async function () {
  var btn = this, st = document.getElementById('status');
  btn.disabled = true; st.className = 'status'; st.textContent = 'Waiting for your passkey…';
  try {
    var r = await fetch('/auth/login/begin', { method: 'POST' });
    if (!r.ok) throw new Error('Could not start sign-in. Please try again.');
    var data = await r.json(), pk = data.publicKey;
    pk.challenge = base64urlToBuffer(pk.challenge);
    if (pk.allowCredentials) pk.allowCredentials = pk.allowCredentials.map(function (c) { return Object.assign({}, c, { id: base64urlToBuffer(c.id) }); });
    var a = await navigator.credentials.get({ publicKey: pk });
    var body = JSON.stringify({
      id: a.id, rawId: bufferToBase64url(a.rawId), type: a.type,
      response: {
        authenticatorData: bufferToBase64url(a.response.authenticatorData),
        clientDataJSON: bufferToBase64url(a.response.clientDataJSON),
        signature: bufferToBase64url(a.response.signature),
        userHandle: a.response.userHandle ? bufferToBase64url(a.response.userHandle) : null
      }
    });
    var f = await fetch('/auth/login/finish?challenge_id=' + encodeURIComponent(data.challenge_id),
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body });
    if (!f.ok) throw new Error('Authentication failed.');
    st.className = 'status ok'; st.textContent = 'Signed in! Redirecting…';
    // Reload: now signed in, /tunnel-login mints the handoff token and redirects to the service.
    setTimeout(function () { window.location.reload(); }, 500);
  } catch (e) {
    st.className = 'status err'; st.textContent = (e && e.message) ? e.message : 'Sign-in failed.';
    btn.disabled = false;
  }
});
</script>
</body>
</html>{{end}}
`
