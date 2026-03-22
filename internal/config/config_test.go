package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_CreatesDefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gatecrash.toml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should have auto-generated values
	if cfg.Server.Secret == "" {
		t.Fatal("secret should be generated")
	}
	if cfg.Server.SSHPort < 49152 || cfg.Server.SSHPort > 65535 {
		t.Fatalf("SSH port %d out of range", cfg.Server.SSHPort)
	}
	if cfg.Server.BindAddr != "0.0.0.0" {
		t.Fatalf("unexpected bind addr: %s", cfg.Server.BindAddr)
	}

	// File should exist on disk
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("config file should be created")
	}
}

func TestLoad_ReloadsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gatecrash.toml")

	// Create first
	cfg1, _ := Load(path)

	// Reload
	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	// Values should match
	if cfg1.Server.Secret != cfg2.Server.Secret {
		t.Fatal("secret should persist")
	}
	if cfg1.Server.SSHPort != cfg2.Server.SSHPort {
		t.Fatal("SSH port should persist")
	}
}

func TestLoad_ParsesTunnels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gatecrash.toml")

	content := `
[server]
secret = "test-secret"
ssh_port = 50000
bind_addr = "0.0.0.0"

[tls]
acme_email = "admin@example.com"
cert_dir = "./certs"

[update]
enabled = true
check_interval = "6h"
github_repo = "jclement/gatecrash"

[[tunnel]]
id = "web"
type = "http"
hostnames = ["app.example.com", "www.example.com"]

[[tunnel]]
id = "db"
type = "tcp"
listen_port = 13306
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Tunnel) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(cfg.Tunnel))
	}

	if cfg.Tunnel[0].ID != "web" {
		t.Fatalf("first tunnel ID: %s", cfg.Tunnel[0].ID)
	}
	if cfg.Tunnel[0].Type != "http" {
		t.Fatalf("first tunnel type: %s", cfg.Tunnel[0].Type)
	}
	if len(cfg.Tunnel[0].Hostnames) != 2 {
		t.Fatalf("first tunnel hostnames: %v", cfg.Tunnel[0].Hostnames)
	}

	if cfg.Tunnel[1].ID != "db" {
		t.Fatalf("second tunnel ID: %s", cfg.Tunnel[1].ID)
	}
	if cfg.Tunnel[1].ListenPort != 13306 {
		t.Fatalf("second tunnel listen port: %d", cfg.Tunnel[1].ListenPort)
	}
}

func TestLoad_GeneratesMissingSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gatecrash.toml")

	// Config with empty secret
	content := `
[server]
secret = ""
ssh_port = 50000
bind_addr = "0.0.0.0"
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Secret == "" {
		t.Fatal("should have generated secret")
	}
}

func TestLoad_GeneratesMissingSSHPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gatecrash.toml")

	content := `
[server]
secret = "test-secret"
ssh_port = 0
bind_addr = "0.0.0.0"
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.SSHPort == 0 {
		t.Fatal("should have generated SSH port")
	}
}

func TestCheckIntervalDuration(t *testing.T) {
	cfg := &Config{Update: UpdateConfig{CheckInterval: "12h"}}
	d := cfg.CheckIntervalDuration()
	if d.Hours() != 12 {
		t.Fatalf("expected 12h, got %v", d)
	}

	// Invalid duration should default to 6h
	cfg.Update.CheckInterval = "invalid"
	d = cfg.CheckIntervalDuration()
	if d.Hours() != 6 {
		t.Fatalf("expected 6h default, got %v", d)
	}
}

func TestGenerateSecret(t *testing.T) {
	s1, err := generateSecret(32)
	if err != nil {
		t.Fatalf("generateSecret: %v", err)
	}
	s2, _ := generateSecret(32)

	if s1 == "" {
		t.Fatal("secret should not be empty")
	}
	if s1 == s2 {
		t.Fatal("secrets should be unique")
	}
}

func TestRandomPort(t *testing.T) {
	for i := 0; i < 100; i++ {
		port, err := randomPort()
		if err != nil {
			t.Fatalf("randomPort: %v", err)
		}
		if port < 49152 || port > 65535 {
			t.Fatalf("port %d out of range [49152, 65535]", port)
		}
	}
}

func TestLookupSecretHash_Found(t *testing.T) {
	cfg := &Config{
		Tunnel: []Tunnel{
			{ID: "web", SecretHash: "$2a$10$abcdef"},
			{ID: "api", SecretHash: "$2a$10$ghijkl"},
		},
	}

	hash := cfg.LookupSecretHash("api")
	if hash != "$2a$10$ghijkl" {
		t.Fatalf("expected $2a$10$ghijkl, got %q", hash)
	}

	hash = cfg.LookupSecretHash("web")
	if hash != "$2a$10$abcdef" {
		t.Fatalf("expected $2a$10$abcdef, got %q", hash)
	}
}

func TestLookupSecretHash_NotFound(t *testing.T) {
	cfg := &Config{
		Tunnel: []Tunnel{
			{ID: "web", SecretHash: "$2a$10$abcdef"},
		},
	}

	hash := cfg.LookupSecretHash("nonexistent")
	if hash != "" {
		t.Fatalf("expected empty string for unknown tunnel ID, got %q", hash)
	}
}

func TestAllHostnames(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			AdminHost: "admin.example.com",
		},
		Tunnel: []Tunnel{
			{ID: "web", Hostnames: []string{"app.example.com", "www.example.com"}},
			{ID: "api", Hostnames: []string{"api.example.com", "app.example.com"}}, // duplicate
		},
		Redirect: []Redirect{
			{From: "old.example.com", To: "https://new.example.com"},
			{From: "admin.example.com", To: "https://other.example.com"}, // duplicate of admin host
		},
	}

	hosts := cfg.AllHostnames()

	expected := map[string]bool{
		"admin.example.com": false,
		"app.example.com":   false,
		"www.example.com":   false,
		"api.example.com":   false,
		"old.example.com":   false,
	}

	if len(hosts) != len(expected) {
		t.Fatalf("expected %d unique hostnames, got %d: %v", len(expected), len(hosts), hosts)
	}

	for _, h := range hosts {
		if _, ok := expected[h]; !ok {
			t.Fatalf("unexpected hostname %q in result", h)
		}
		expected[h] = true
	}

	for h, found := range expected {
		if !found {
			t.Fatalf("expected hostname %q not found in result", h)
		}
	}
}

func TestAllHostnames_Empty(t *testing.T) {
	cfg := &Config{}

	hosts := cfg.AllHostnames()
	if len(hosts) != 0 {
		t.Fatalf("expected empty slice, got %v", hosts)
	}
}

func TestAllHostnames_ExcludesTLSPassthrough(t *testing.T) {
	cfg := &Config{
		Tunnel: []Tunnel{
			{ID: "web", Hostnames: []string{"app.example.com"}, TLSPassthrough: false},
			{ID: "passthru", Hostnames: []string{"passthru.example.com"}, TLSPassthrough: true},
		},
	}

	hosts := cfg.AllHostnames()

	if len(hosts) != 1 {
		t.Fatalf("expected 1 hostname, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "app.example.com" {
		t.Fatalf("expected app.example.com, got %q", hosts[0])
	}
}

func TestConfigSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-save.toml")

	original := &Config{
		Server: ServerConfig{
			Secret:    "my-secret",
			SSHPort:   55000,
			HTTPSPort: 443,
			HTTPPort:  80,
			AdminHost: "admin.example.com",
			BindAddr:  "0.0.0.0",
		},
		TLS: TLSConfig{
			ACMEEmail: "admin@example.com",
			CertDir:   "/tmp/certs",
		},
		Update: UpdateConfig{
			Enabled:       true,
			CheckInterval: "6h",
			GitHubRepo:    "jclement/gatecrash",
		},
		Tunnel: []Tunnel{
			{ID: "web", Type: "http", Hostnames: []string{"app.example.com"}, SecretHash: "$2a$10$abc"},
			{ID: "db", Type: "tcp", ListenPort: 13306, SecretHash: "$2a$10$def"},
		},
		Redirect: []Redirect{
			{From: "old.example.com", To: "https://new.example.com", PreservePath: true},
		},
	}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}

	if reloaded.Server.Secret != original.Server.Secret {
		t.Fatalf("secret mismatch: %q vs %q", reloaded.Server.Secret, original.Server.Secret)
	}
	if reloaded.Server.SSHPort != original.Server.SSHPort {
		t.Fatalf("ssh_port mismatch: %d vs %d", reloaded.Server.SSHPort, original.Server.SSHPort)
	}
	if reloaded.Server.AdminHost != original.Server.AdminHost {
		t.Fatalf("admin_host mismatch: %q vs %q", reloaded.Server.AdminHost, original.Server.AdminHost)
	}
	if len(reloaded.Tunnel) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(reloaded.Tunnel))
	}
	if reloaded.Tunnel[0].ID != "web" || reloaded.Tunnel[1].ID != "db" {
		t.Fatalf("tunnel IDs mismatch: %q, %q", reloaded.Tunnel[0].ID, reloaded.Tunnel[1].ID)
	}
	if reloaded.Tunnel[1].ListenPort != 13306 {
		t.Fatalf("tunnel listen_port mismatch: %d", reloaded.Tunnel[1].ListenPort)
	}
	if len(reloaded.Redirect) != 1 {
		t.Fatalf("expected 1 redirect, got %d", len(reloaded.Redirect))
	}
	if reloaded.Redirect[0].From != "old.example.com" {
		t.Fatalf("redirect from mismatch: %q", reloaded.Redirect[0].From)
	}
}

func TestCheckIntervalDuration_Empty(t *testing.T) {
	cfg := &Config{Update: UpdateConfig{CheckInterval: ""}}
	d := cfg.CheckIntervalDuration()
	if d != 6*60*60*1000000000 { // 6 hours in nanoseconds
		t.Fatalf("expected 6h default for empty string, got %v", d)
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.toml")

	content := `[server
this is not valid toml }{{{
`
	os.WriteFile(path, []byte(content), 0o644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
}

func TestLoad_MissingSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-secret.toml")

	content := `
[server]
ssh_port = 55000
bind_addr = "0.0.0.0"
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Secret == "" {
		t.Fatal("expected Load to generate a secret when missing")
	}
}

func TestLoad_MissingSSHPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-sshport.toml")

	content := `
[server]
secret = "test-secret"
bind_addr = "0.0.0.0"
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.SSHPort == 0 {
		t.Fatal("expected Load to generate an SSH port when missing")
	}
	if cfg.Server.SSHPort < 49152 || cfg.Server.SSHPort > 65535 {
		t.Fatalf("generated SSH port %d out of expected range [49152, 65535]", cfg.Server.SSHPort)
	}
}
