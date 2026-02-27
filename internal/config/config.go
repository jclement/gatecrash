package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server   ServerConfig `toml:"server"`
	TLS      TLSConfig    `toml:"tls"`
	Update   UpdateConfig `toml:"update"`
	Tunnel   []Tunnel     `toml:"tunnel"`
	Redirect []Redirect   `toml:"redirect"`
}

type ServerConfig struct {
	Secret    string `toml:"secret"`
	SSHPort   int    `toml:"ssh_port"`
	HTTPSPort int    `toml:"https_port"`
	HTTPPort  int    `toml:"http_port"`
	AdminHost string `toml:"admin_host"`
	BindAddr  string `toml:"bind_addr"`
}

type TLSConfig struct {
	ACMEEmail string `toml:"acme_email"`
	CertDir   string `toml:"cert_dir"`
	Staging   bool   `toml:"staging"`
}

type UpdateConfig struct {
	Enabled       bool   `toml:"enabled"`
	CheckInterval string `toml:"check_interval"`
	GitHubRepo    string `toml:"github_repo"`
}

type Tunnel struct {
	ID           string   `toml:"id"`
	Type         string   `toml:"type"`
	Hostnames    []string `toml:"hostnames,omitempty"`
	ListenPort   int      `toml:"listen_port,omitempty"`
	SecretHash   string   `toml:"secret_hash,omitempty"`
	PreserveHost bool     `toml:"preserve_host,omitempty"`
}

type Redirect struct {
	From         string `toml:"from"`
	To           string `toml:"to"`
	PreservePath bool   `toml:"preserve_path"`
}

func (c *Config) CheckIntervalDuration() time.Duration {
	d, err := time.ParseDuration(c.Update.CheckInterval)
	if err != nil {
		return 6 * time.Hour
	}
	return d
}

// LookupSecretHash returns the bcrypt hash for a tunnel ID, or "" if not found.
func (c *Config) LookupSecretHash(tunnelID string) string {
	for _, t := range c.Tunnel {
		if t.ID == tunnelID {
			return t.SecretHash
		}
	}
	return ""
}

// AllHostnames returns all hostnames that need TLS certificates,
// including tunnel hostnames, admin host, and redirect source hostnames.
func (c *Config) AllHostnames() []string {
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}

	add(c.Server.AdminHost)
	for _, t := range c.Tunnel {
		for _, h := range t.Hostnames {
			add(h)
		}
	}
	for _, r := range c.Redirect {
		add(r.From)
	}
	return hosts
}

// Load reads config from the given path. If the file doesn't exist, it creates
// a default config with auto-generated values.
func Load(path string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			BindAddr:  "0.0.0.0",
			HTTPSPort: 443,
			HTTPPort:  80,
		},
		TLS: TLSConfig{
			CertDir: "./certs",
		},
		Update: UpdateConfig{
			Enabled:       true,
			CheckInterval: "6h",
			GitHubRepo:    "jclement/gatecrash",
		},
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		slog.Info("no config file found, creating default", "path", path)
		if err := cfg.generateDefaults(); err != nil {
			return nil, fmt.Errorf("generating defaults: %w", err)
		}
		// Resolve relative cert_dir to be relative to config file directory
		if !filepath.IsAbs(cfg.TLS.CertDir) {
			cfg.TLS.CertDir = filepath.Join(filepath.Dir(path), cfg.TLS.CertDir)
		}
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("saving default config: %w", err)
		}
		return cfg, nil
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	// Resolve relative cert_dir to be relative to config file directory
	if !filepath.IsAbs(cfg.TLS.CertDir) {
		cfg.TLS.CertDir = filepath.Join(filepath.Dir(path), cfg.TLS.CertDir)
	}

	changed := false

	if cfg.Server.Secret == "" {
		secret, err := generateSecret(32)
		if err != nil {
			return nil, fmt.Errorf("generating secret: %w", err)
		}
		cfg.Server.Secret = secret
		changed = true
	}

	if cfg.Server.SSHPort == 0 {
		port, err := randomPort()
		if err != nil {
			return nil, fmt.Errorf("generating SSH port: %w", err)
		}
		cfg.Server.SSHPort = port
		changed = true
	}

	if cfg.Server.BindAddr == "" {
		cfg.Server.BindAddr = "0.0.0.0"
		changed = true
	}

	if changed {
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("saving updated config: %w", err)
		}
	}

	return cfg, nil
}

// Save writes the config to disk as self-documenting TOML with comments.
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating config file: %w", err)
	}
	defer f.Close()

	var b strings.Builder

	b.WriteString("# Gatecrash Configuration\n")
	b.WriteString("# https://github.com/jclement/gatecrash\n\n")

	// [server]
	b.WriteString("[server]\n")
	b.WriteString("# Session signing secret (auto-generated, do not share)\n")
	fmt.Fprintf(&b, "secret = %q\n\n", c.Server.Secret)

	b.WriteString("# SSH port for tunnel clients\n")
	fmt.Fprintf(&b, "ssh_port = %d\n\n", c.Server.SSHPort)

	b.WriteString("# HTTPS port (default: 443)\n")
	fmt.Fprintf(&b, "https_port = %d\n\n", c.Server.HTTPSPort)

	b.WriteString("# HTTP port for HTTPS redirect (default: 80, set to 0 to disable)\n")
	fmt.Fprintf(&b, "http_port = %d\n\n", c.Server.HTTPPort)

	b.WriteString("# Bind address for listeners\n")
	fmt.Fprintf(&b, "bind_addr = %q\n\n", c.Server.BindAddr)

	b.WriteString("# Admin panel hostname (required to enable the web admin panel)\n")
	b.WriteString("# When set, the admin panel with passkey auth is served at this hostname.\n")
	b.WriteString("# When not set, the admin panel is completely disabled.\n")
	if c.Server.AdminHost != "" {
		fmt.Fprintf(&b, "admin_host = %q\n\n", c.Server.AdminHost)
	} else {
		b.WriteString("# admin_host = \"admin.example.com\"\n\n")
	}

	// [tls]
	b.WriteString("[tls]\n")
	b.WriteString("# ACME/Let's Encrypt email (optional but recommended for expiration notices)\n")
	b.WriteString("# TLS is enabled automatically when hostnames are configured.\n")
	b.WriteString("# Certificates are obtained on-demand via Let's Encrypt as hostnames arrive.\n")
	if c.TLS.ACMEEmail != "" {
		fmt.Fprintf(&b, "acme_email = %q\n\n", c.TLS.ACMEEmail)
	} else {
		b.WriteString("# acme_email = \"you@example.com\"\n\n")
	}

	b.WriteString("# Certificate storage directory\n")
	fmt.Fprintf(&b, "cert_dir = %q\n\n", c.TLS.CertDir)

	b.WriteString("# Use Let's Encrypt staging CA (for testing)\n")
	if c.TLS.Staging {
		b.WriteString("staging = true\n\n")
	} else {
		b.WriteString("# staging = false\n\n")
	}

	// [update]
	b.WriteString("[update]\n")
	b.WriteString("# Check for new releases on startup\n")
	fmt.Fprintf(&b, "enabled = %v\n", c.Update.Enabled)
	fmt.Fprintf(&b, "check_interval = %q\n", c.Update.CheckInterval)
	fmt.Fprintf(&b, "github_repo = %q\n\n", c.Update.GitHubRepo)

	// Tunnel documentation
	b.WriteString("# ─── Tunnels ────────────────────────────────────────────────────────\n")
	b.WriteString("#\n")
	b.WriteString("# Each tunnel needs a unique ID and a bcrypt secret_hash for authentication.\n")
	b.WriteString("# The client connects with a token in the format: tunnel_id:plaintext_secret\n")
	b.WriteString("#\n")
	b.WriteString("# Generate a bcrypt hash:\n")
	b.WriteString("#   htpasswd -nbBC 10 \"\" \"your-secret\" | cut -d: -f2\n")
	b.WriteString("#   python3 -c \"import bcrypt; print(bcrypt.hashpw(b'your-secret', bcrypt.gensalt()).decode())\"\n")
	b.WriteString("#\n")
	b.WriteString("# Or use the admin panel to generate secrets with one click.\n")
	b.WriteString("#\n")
	b.WriteString("# Example:\n")
	b.WriteString("#   gatecrash client --server host:port --token \"myapp:your-secret\" --target 127.0.0.1:8000\n")

	if len(c.Tunnel) == 0 {
		b.WriteString("#\n")
		b.WriteString("# [[tunnel]]\n")
		b.WriteString("# id = \"example\"\n")
		b.WriteString("# type = \"http\"                    # \"http\" or \"tcp\"\n")
		b.WriteString("# hostnames = [\"app.example.com\"]   # for HTTP tunnels\n")
		b.WriteString("# secret_hash = \"$2a$10$...\"        # bcrypt hash\n")
		b.WriteString("# # preserve_host = false           # pass original Host header to backend\n")
		b.WriteString("#\n")
		b.WriteString("# [[tunnel]]\n")
		b.WriteString("# id = \"example-tcp\"\n")
		b.WriteString("# type = \"tcp\"\n")
		b.WriteString("# listen_port = 9000               # for TCP tunnels\n")
		b.WriteString("# secret_hash = \"$2a$10$...\"\n")
		b.WriteString("\n")
	} else {
		b.WriteString("\n\n")
		for _, t := range c.Tunnel {
			b.WriteString("[[tunnel]]\n")
			fmt.Fprintf(&b, "id = %q\n", t.ID)
			fmt.Fprintf(&b, "type = %q\n", t.Type)
			if len(t.Hostnames) > 0 {
				fmt.Fprintf(&b, "hostnames = [%s]\n", formatStringSlice(t.Hostnames))
			}
			if t.ListenPort > 0 {
				fmt.Fprintf(&b, "listen_port = %d\n", t.ListenPort)
			}
			if t.SecretHash != "" {
				fmt.Fprintf(&b, "secret_hash = %q\n", t.SecretHash)
			}
			if t.PreserveHost {
				b.WriteString("preserve_host = true\n")
			}
			b.WriteString("\n")
		}
	}

	// Redirect documentation
	b.WriteString("# ─── Redirects ──────────────────────────────────────────────────────\n")
	b.WriteString("#\n")
	b.WriteString("# Redirect hostnames to other destinations (301 Moved Permanently).\n")
	b.WriteString("# Redirect hostnames automatically get TLS certificates via ACME.\n")

	if len(c.Redirect) == 0 {
		b.WriteString("#\n")
		b.WriteString("# [[redirect]]\n")
		b.WriteString("# from = \"www.example.com\"\n")
		b.WriteString("# to = \"example.com\"\n")
		b.WriteString("# preserve_path = true\n")
		b.WriteString("\n")
	} else {
		b.WriteString("\n\n")
		for _, r := range c.Redirect {
			b.WriteString("[[redirect]]\n")
			fmt.Fprintf(&b, "from = %q\n", r.From)
			fmt.Fprintf(&b, "to = %q\n", r.To)
			fmt.Fprintf(&b, "preserve_path = %v\n\n", r.PreservePath)
		}
	}

	_, err = f.WriteString(b.String())
	return err
}

func formatStringSlice(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

// GenerateNew creates a new Config with auto-generated defaults
// (random secret, random SSH port, default bind address and cert dir).
func GenerateNew() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			BindAddr:  "0.0.0.0",
			HTTPSPort: 443,
			HTTPPort:  80,
		},
		TLS: TLSConfig{
			CertDir: "./certs",
		},
		Update: UpdateConfig{
			Enabled:       true,
			CheckInterval: "6h",
			GitHubRepo:    "jclement/gatecrash",
		},
	}
	if err := cfg.generateDefaults(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) generateDefaults() error {
	secret, err := generateSecret(32)
	if err != nil {
		return err
	}
	c.Server.Secret = secret

	port, err := randomPort()
	if err != nil {
		return err
	}
	c.Server.SSHPort = port

	return nil
}

func generateSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomPort() (int, error) {
	// Range: 49152-65535 (dynamic/private ports)
	n, err := rand.Int(rand.Reader, big.NewInt(65535-49152+1))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 49152, nil
}
