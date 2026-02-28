package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jclement/gatecrash/internal/config"
)

func TestStripPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"example.com:8080", "example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:8080", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := stripPort(tt.input)
			if result != tt.expected {
				t.Fatalf("stripPort(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"app.example.com", false},
		{"localhost", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isIPAddress(tt.input)
			if result != tt.expected {
				t.Fatalf("isIPAddress(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestVhostRedirect(t *testing.T) {
	cfg := &config.Config{
		Redirect: []config.Redirect{
			{From: "www.example.com", To: "example.com", PreservePath: true},
			{From: "old.example.com", To: "new.example.com/legacy", PreservePath: false},
		},
	}
	srv := &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		adminMux: http.NewServeMux(),
	}

	// Test redirect with preserve_path
	req := httptest.NewRequest("GET", "/foo?bar=1", nil)
	req.Host = "www.example.com"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://example.com/foo?bar=1" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}

	// Test redirect without preserve_path
	req = httptest.NewRequest("GET", "/anything", nil)
	req.Host = "old.example.com"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301, got %d", w.Code)
	}
	loc = w.Header().Get("Location")
	if loc != "https://new.example.com/legacy" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}

func TestVhostNoTunnelErrorPage(t *testing.T) {
	cfg := &config.Config{}
	srv := &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		adminMux: http.NewServeMux(),
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "unknown.example.com"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("expected HTML content type, got %s", ct)
	}
}

func TestVhostAdminHost(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			AdminHost: "admin.example.com",
		},
	}
	srv := &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		adminMux: http.NewServeMux(),
	}
	srv.adminMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin"))
	})

	// Admin host should serve admin panel
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "admin.example.com"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "admin" {
		t.Fatalf("expected admin response, got %q", w.Body.String())
	}

	// Non-admin host should not serve admin
	req = httptest.NewRequest("GET", "/", nil)
	req.Host = "other.example.com"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-admin host, got %d", w.Code)
	}
}

func TestRegistryReload(t *testing.T) {
	r := NewRegistry()

	// Initial state
	r.Register(&TunnelState{ID: "a", Type: "http", Hostnames: []string{"a.com"}})
	r.Register(&TunnelState{ID: "b", Type: "tcp", ListenPort: 3306})

	// Simulate connection on tunnel "a"
	r.FindByID("a").AddClient(fakeConn(99), "1.2.3.4:5678")

	// Reload: keep "a", remove "b", add "c"
	r.Reload([]struct {
		ID             string
		Type           string
		Hostnames      []string
		ListenPort     int
		PreserveHost   bool
		TLSPassthrough bool
	}{
		{ID: "a", Type: "http", Hostnames: []string{"a.com", "a2.com"}},
		{ID: "c", Type: "http", Hostnames: []string{"c.com"}},
	})

	// "a" should still be connected
	a := r.FindByID("a")
	if a == nil {
		t.Fatal("tunnel a should exist")
	}
	if !a.IsConnected() {
		t.Fatal("tunnel a should still be connected")
	}
	// "a" should have new hostnames
	if r.FindByHostname("a2.com") == nil {
		t.Fatal("should find by new hostname a2.com")
	}

	// "b" should be gone
	if r.FindByID("b") != nil {
		t.Fatal("tunnel b should be removed")
	}
	if r.FindByPort(3306) != nil {
		t.Fatal("port 3306 should be removed")
	}

	// "c" should be new
	c := r.FindByID("c")
	if c == nil {
		t.Fatal("tunnel c should exist")
	}
	if c.IsConnected() {
		t.Fatal("tunnel c should not be connected")
	}

	// Total should be 2
	if len(r.AllTunnels()) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(r.AllTunnels()))
	}
}

func TestVhostIPAddressRequest(t *testing.T) {
	cfg := &config.Config{}
	srv := &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		adminMux: http.NewServeMux(),
	}

	// Request with IP address in Host header — no tunnel will match,
	// so vhost.go returns a 404 "No Tunnel Configured" error page.
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "192.168.1.1:8080"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for IP address host, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("expected HTML content type, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "No Tunnel Configured") {
		t.Fatalf("expected 'No Tunnel Configured' in body, got: %s", body)
	}
}

func TestVhostTunnelOffline(t *testing.T) {
	cfg := &config.Config{}
	registry := NewRegistry()
	// Register a tunnel but do NOT connect any client
	registry.Register(&TunnelState{
		ID:        "offline-app",
		Type:      "http",
		Hostnames: []string{"offline.example.com"},
	})

	srv := &Server{
		cfg:      cfg,
		registry: registry,
		adminMux: http.NewServeMux(),
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "offline.example.com"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for offline tunnel, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Service Offline") {
		t.Fatalf("expected 'Service Offline' in body, got: %s", body)
	}
	if !strings.Contains(body, "offline-app") {
		t.Fatalf("expected tunnel ID 'offline-app' in body, got: %s", body)
	}
}

func TestVhostStripPortVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"port only", ":443", ""},
		{"just colon", ":", ""},
		{"host with empty port", "example.com:", "example.com"},
		{"ipv6 no port", "::1", "::1"},
		{"ipv6 brackets no port", "[::1]", "[::1]"},
		{"ipv6 brackets with port", "[::1]:443", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripPort(tt.input)
			if result != tt.expected {
				t.Fatalf("stripPort(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
