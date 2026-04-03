package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{2684354560, "2.5 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.input)
			if result != tt.expected {
				t.Fatalf("formatBytes(%d) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTunnelView_ByteFormatting(t *testing.T) {
	tv := TunnelView{
		BytesIn:  1048576,
		BytesOut: 2097152,
	}
	if tv.BytesInFmt() != "1.0 MB" {
		t.Fatalf("BytesInFmt: %s", tv.BytesInFmt())
	}
	if tv.BytesOutFmt() != "2.0 MB" {
		t.Fatalf("BytesOutFmt: %s", tv.BytesOutFmt())
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		ago      time.Duration
		expected string
	}{
		{"seconds", 30 * time.Second, "30s"},
		{"one_minute", 1 * time.Minute, "1m"},
		{"minutes", 45 * time.Minute, "45m"},
		{"one_hour", 1 * time.Hour, "1h"},
		{"hours_minutes", 2*time.Hour + 30*time.Minute, "2h 30m"},
		{"exact_hours", 5 * time.Hour, "5h"},
		{"one_day", 24 * time.Hour, "1d"},
		{"days_hours", 3*24*time.Hour + 12*time.Hour, "3d 12h"},
		{"exact_days", 7 * 24 * time.Hour, "7d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			since := time.Now().Add(-tt.ago)
			result := FormatUptime(since)
			if result != tt.expected {
				t.Fatalf("FormatUptime(%v ago) = %q, want %q", tt.ago, result, tt.expected)
			}
		})
	}
}

func TestTunnelView_HostnamesCSV(t *testing.T) {
	tv := TunnelView{Hostnames: []string{"app.example.com", "www.example.com"}}
	if tv.HostnamesCSV() != "app.example.com, www.example.com" {
		t.Fatalf("HostnamesCSV: %s", tv.HostnamesCSV())
	}

	tv2 := TunnelView{Hostnames: []string{"single.com"}}
	if tv2.HostnamesCSV() != "single.com" {
		t.Fatalf("HostnamesCSV single: %s", tv2.HostnamesCSV())
	}

	tv3 := TunnelView{}
	if tv3.HostnamesCSV() != "" {
		t.Fatalf("HostnamesCSV empty: %s", tv3.HostnamesCSV())
	}
}

func TestTunnelView_ClientSummary(t *testing.T) {
	tv := TunnelView{
		Clients: []ClientView{
			{Addr: "192.168.1.1:5000", Uptime: "2h 30m"},
			{Addr: "10.0.0.1:6000", Uptime: "45m"},
		},
	}

	expected := "10.0.0.1:6000 (45m)\n192.168.1.1:5000 (2h 30m)"
	if tv.ClientSummary() != expected {
		t.Fatalf("ClientSummary = %q, want %q", tv.ClientSummary(), expected)
	}

	// Empty
	tv2 := TunnelView{}
	if tv2.ClientSummary() != "" {
		t.Fatalf("ClientSummary empty = %q", tv2.ClientSummary())
	}
}

func TestNewHandlers_Production(t *testing.T) {
	tmplFS := fstest.MapFS{
		"base.html":                 {Data: []byte(`{{define "base"}}base:{{template "content" .}}{{end}}`)},
		"pages/login.html":          {Data: []byte(`{{define "content"}}login{{end}}`)},
		"pages/setup.html":          {Data: []byte(`{{define "content"}}setup{{end}}`)},
		"pages/passkeys.html":       {Data: []byte(`{{define "content"}}passkeys{{end}}`)},
		"pages/dashboard.html":      {Data: []byte(`{{define "content"}}dashboard{{end}}`)},
		"pages/help.html":           {Data: []byte(`{{define "content"}}help{{end}}`)},
		"pages/auditlog.html":       {Data: []byte(`{{define "content"}}auditlog{{end}}`)},
	}

	h, err := NewHandlers("1.0.0", 6*time.Hour, tmplFS)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	if h.version != "1.0.0" {
		t.Fatalf("version = %q", h.version)
	}
	if h.isDev {
		t.Fatal("should not be dev mode for version 1.0.0")
	}
	// Production mode pre-compiles all pages
	if len(h.pages) != 6 {
		t.Fatalf("expected 6 pre-compiled pages, got %d", len(h.pages))
	}
}

func TestNewHandlers_DevMode(t *testing.T) {
	tmplFS := fstest.MapFS{
		"base.html": {Data: []byte(`{{define "base"}}{{template "content" .}}{{end}}`)},
	}

	h, err := NewHandlers("dev", time.Hour, tmplFS)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	if !h.isDev {
		t.Fatal("should be dev mode")
	}
	if len(h.pages) != 0 {
		t.Fatalf("expected 0 pre-compiled pages in dev, got %d", len(h.pages))
	}
}

func TestRender(t *testing.T) {
	tmplFS := fstest.MapFS{
		"base.html":        {Data: []byte(`{{define "base"}}base:{{template "content" .}}{{end}}`)},
		"pages/login.html": {Data: []byte(`{{define "content"}}login-page{{end}}`)},
		"pages/setup.html": {Data: []byte(`{{define "content"}}setup-page{{end}}`)},
		"pages/passkeys.html":  {Data: []byte(`{{define "content"}}passkeys{{end}}`)},
		"pages/dashboard.html": {Data: []byte(`{{define "content"}}dashboard{{end}}`)},
		"pages/help.html":           {Data: []byte(`{{define "content"}}help{{end}}`)},
		"pages/auditlog.html":       {Data: []byte(`{{define "content"}}auditlog{{end}}`)},
	}

	h, err := NewHandlers("1.0.0", time.Hour, tmplFS)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	w := httptest.NewRecorder()
	h.Render(w, "pages/login.html", &PageData{Title: "Login"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if body != "base:login-page" {
		t.Fatalf("body = %q", body)
	}

	// Check security headers
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options header")
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("missing HSTS header")
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP header")
	}
}

func TestRender_NilData(t *testing.T) {
	tmplFS := fstest.MapFS{
		"base.html":        {Data: []byte(`{{define "base"}}ok{{end}}`)},
		"pages/login.html": {Data: []byte(`{{define "content"}}login{{end}}`)},
		"pages/setup.html": {Data: []byte(`{{define "content"}}setup{{end}}`)},
		"pages/passkeys.html":  {Data: []byte(`{{define "content"}}passkeys{{end}}`)},
		"pages/dashboard.html": {Data: []byte(`{{define "content"}}dashboard{{end}}`)},
		"pages/help.html":           {Data: []byte(`{{define "content"}}help{{end}}`)},
		"pages/auditlog.html":       {Data: []byte(`{{define "content"}}auditlog{{end}}`)},
	}

	h, _ := NewHandlers("1.0.0", time.Hour, tmplFS)
	w := httptest.NewRecorder()
	h.Render(w, "pages/login.html", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with nil data, got %d", w.Code)
	}
}

func TestRender_UnknownPage(t *testing.T) {
	tmplFS := fstest.MapFS{
		"base.html":        {Data: []byte(`{{define "base"}}ok{{end}}`)},
		"pages/login.html": {Data: []byte(`{{define "content"}}login{{end}}`)},
		"pages/setup.html": {Data: []byte(`{{define "content"}}setup{{end}}`)},
		"pages/passkeys.html":  {Data: []byte(`{{define "content"}}passkeys{{end}}`)},
		"pages/dashboard.html": {Data: []byte(`{{define "content"}}dashboard{{end}}`)},
		"pages/help.html":           {Data: []byte(`{{define "content"}}help{{end}}`)},
		"pages/auditlog.html":       {Data: []byte(`{{define "content"}}auditlog{{end}}`)},
	}

	h, _ := NewHandlers("1.0.0", time.Hour, tmplFS)
	w := httptest.NewRecorder()
	h.Render(w, "pages/nonexistent.html", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for unknown page, got %d", w.Code)
	}
}

func TestRenderPartial(t *testing.T) {
	tmplFS := fstest.MapFS{
		"base.html":        {Data: []byte(`{{define "base"}}base{{end}}`)},
		"pages/login.html": {Data: []byte(`{{define "content"}}login{{end}}{{define "partial"}}partial-content{{end}}`)},
		"pages/setup.html": {Data: []byte(`{{define "content"}}setup{{end}}`)},
		"pages/passkeys.html":  {Data: []byte(`{{define "content"}}passkeys{{end}}`)},
		"pages/dashboard.html": {Data: []byte(`{{define "content"}}dashboard{{end}}`)},
		"pages/help.html":           {Data: []byte(`{{define "content"}}help{{end}}`)},
		"pages/auditlog.html":       {Data: []byte(`{{define "content"}}auditlog{{end}}`)},
	}

	h, _ := NewHandlers("1.0.0", time.Hour, tmplFS)
	w := httptest.NewRecorder()
	h.RenderPartial(w, "pages/login.html", "partial", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "partial-content" {
		t.Fatalf("body = %q", w.Body.String())
	}
}

func TestPageData_Fields(t *testing.T) {
	pd := &PageData{
		Title:           "Dashboard",
		Active:          "dashboard",
		Version:         "1.0.0",
		CheckIntervalMS: 6000,
		CSRFToken:       "abc123",
		Flash:           &Flash{Type: "success", Message: "Done"},
	}
	if pd.Title != "Dashboard" {
		t.Fatalf("Title = %q", pd.Title)
	}
	if pd.Flash.Type != "success" {
		t.Fatalf("Flash.Type = %q", pd.Flash.Type)
	}
}

func TestPasskeyView(t *testing.T) {
	pv := PasskeyView{
		Name:       "My Passkey",
		CreatedAt:  "Jan 1, 2026",
		LastUsedAt: "Mar 15, 2026",
		IDB64:      "dGVzdA",
	}
	if pv.Name != "My Passkey" {
		t.Fatalf("Name = %q", pv.Name)
	}
	if pv.IDB64 != "dGVzdA" {
		t.Fatalf("IDB64 = %q", pv.IDB64)
	}
}

func TestHostCert(t *testing.T) {
	hc := HostCert{
		Hostname: "example.com",
		Valid:    true,
		Expiry:   "May 15, 2026",
	}
	if !hc.Valid {
		t.Fatal("expected valid cert")
	}
	if hc.Error != "" {
		t.Fatalf("unexpected error: %q", hc.Error)
	}

	hc2 := HostCert{
		Hostname: "bad.com",
		Valid:    false,
		Error:    "not provisioned",
	}
	if hc2.Valid {
		t.Fatal("expected invalid cert")
	}
}
