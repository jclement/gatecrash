package server

import (
	"net/http"
	"net/http/httptest"
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

func TestVhostWellKnownAdmin(t *testing.T) {
	cfg := &config.Config{}
	srv := &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		adminMux: http.NewServeMux(),
	}
	srv.adminMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin"))
	})

	req := httptest.NewRequest("GET", "/.well-known/gatecrash/", nil)
	req.Host = "anything.example.com"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "admin" {
		t.Fatalf("expected admin response, got %q", w.Body.String())
	}
}

func TestRegistryReload(t *testing.T) {
	r := NewRegistry()

	// Initial state
	r.Register(&TunnelState{ID: "a", Type: "http", Hostnames: []string{"a.com"}})
	r.Register(&TunnelState{ID: "b", Type: "tcp", ListenPort: 3306})

	// Simulate connection on tunnel "a"
	r.FindByID("a").SetConnected(nil, "1.2.3.4:5678")

	// Reload: keep "a", remove "b", add "c"
	r.Reload([]struct {
		ID           string
		Type         string
		Hostnames    []string
		ListenPort   int
		PreserveHost bool
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
