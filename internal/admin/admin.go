package admin

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
)

// HostCert holds TLS certificate status for a single hostname.
type HostCert struct {
	Hostname string
	Valid    bool
	Expiry   string // formatted date, e.g. "May 15, 2026"
	Error    string // non-empty when cert is missing or invalid
}

// TunnelView is the template data for a single tunnel row.
type TunnelView struct {
	ID             string
	Type           string
	Hostnames      []string
	ListenPort     int
	PreserveHost   bool
	TLSPassthrough bool
	Connected      bool
	ClientCount    int
	ClientAddrs    []string
	Requests       int64
	BytesIn        int64
	BytesOut       int64
	ActiveConns    int32
	Token          string
	HostCerts      []HostCert
}

// HostnamesCSV returns hostnames as a comma-separated string.
func (t TunnelView) HostnamesCSV() string { return strings.Join(t.Hostnames, ", ") }

// ClientAddrsList returns client addresses as a newline-separated string for tooltips.
func (t TunnelView) ClientAddrsList() string { return strings.Join(t.ClientAddrs, "\n") }

// BytesInFmt formats bytes in as a human-readable string.
func (t TunnelView) BytesInFmt() string { return formatBytes(t.BytesIn) }

// BytesOutFmt formats bytes out as a human-readable string.
func (t TunnelView) BytesOutFmt() string { return formatBytes(t.BytesOut) }

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// PageData is the template rendering context.
type PageData struct {
	Title   string
	Active  string
	Version string
	Flash   *Flash
	Data    any
}

// PasskeyView represents a passkey for display in templates.
type PasskeyView struct {
	Name       string
	CreatedAt  string
	LastUsedAt string
	IDB64      string // base64url-encoded credential ID
}

// Flash is a one-time notification message.
type Flash struct {
	Type    string // "success", "danger", "warning", "info"
	Message string
}

// Handlers holds the admin panel HTTP handlers.
type Handlers struct {
	version   string
	tmplFuncs template.FuncMap
	tmplFS    fs.FS
	isDev     bool
	baseHTML  string              // cached base template source
	pages    map[string]*template.Template // pre-compiled: page name → base+page
}

// NewHandlers creates admin panel handlers.
func NewHandlers(version string, templateFS fs.FS) (*Handlers, error) {
	h := &Handlers{
		version: version,
		tmplFS:  templateFS,
		isDev:   version == "dev",
		tmplFuncs: template.FuncMap{
			"version": func() string { return version },
		},
		pages: make(map[string]*template.Template),
	}

	// Read base template
	base, err := fs.ReadFile(templateFS, "base.html")
	if err != nil {
		return nil, fmt.Errorf("reading base.html: %w", err)
	}
	h.baseHTML = string(base)

	// In production, pre-compile all page templates
	if !h.isDev {
		for _, page := range []string{
			"pages/login.html",
			"pages/setup.html",
			"pages/passkeys.html",
			"pages/dashboard.html",
			"pages/help.html",
		} {
			tmpl, err := h.compilePage(page)
			if err != nil {
				return nil, fmt.Errorf("compiling %s: %w", page, err)
			}
			h.pages[page] = tmpl
		}
	}

	return h, nil
}

// compilePage creates a fresh template combining base + the specific page.
func (h *Handlers) compilePage(page string) (*template.Template, error) {
	pageContent, err := fs.ReadFile(h.tmplFS, page)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", page, err)
	}

	tmpl := template.New("").Funcs(h.tmplFuncs)
	if _, err := tmpl.New("base.html").Parse(h.baseHTML); err != nil {
		return nil, fmt.Errorf("parsing base: %w", err)
	}
	if _, err := tmpl.New(page).Parse(string(pageContent)); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", page, err)
	}

	return tmpl, nil
}

// Render renders a page template inside the base layout.
// The page parameter is the template path, e.g. "pages/login.html".
func (h *Handlers) Render(w http.ResponseWriter, page string, data *PageData) {
	if data == nil {
		data = &PageData{}
	}
	data.Version = h.version

	var tmpl *template.Template
	var err error

	if h.isDev {
		// In dev mode, re-read templates from disk on every request
		base, readErr := fs.ReadFile(h.tmplFS, "base.html")
		if readErr != nil {
			slog.Error("template read failed", "error", readErr)
			http.Error(w, "Internal server error", 500)
			return
		}
		h.baseHTML = string(base)
		tmpl, err = h.compilePage(page)
	} else {
		tmpl = h.pages[page]
		if tmpl == nil {
			err = fmt.Errorf("unknown page template: %s", page)
		}
	}

	if err != nil {
		slog.Error("template compile failed", "page", page, "error", err)
		http.Error(w, "Internal server error", 500)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		slog.Error("template exec failed", "page", page, "error", err)
		http.Error(w, "Internal server error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// RenderPartial renders a named template block without the base layout.
func (h *Handlers) RenderPartial(w http.ResponseWriter, page, block string, data any) {
	var tmpl *template.Template
	var err error

	if h.isDev {
		base, readErr := fs.ReadFile(h.tmplFS, "base.html")
		if readErr != nil {
			slog.Error("template read failed", "error", readErr)
			http.Error(w, "Internal server error", 500)
			return
		}
		h.baseHTML = string(base)
		tmpl, err = h.compilePage(page)
	} else {
		tmpl = h.pages[page]
		if tmpl == nil {
			err = fmt.Errorf("unknown page template: %s", page)
		}
	}

	if err != nil {
		slog.Error("template compile failed", "page", page, "error", err)
		http.Error(w, "Internal server error", 500)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, block, data); err != nil {
		slog.Error("partial exec failed", "page", page, "block", block, "error", err)
		http.Error(w, "Internal server error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}
