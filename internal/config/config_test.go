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
