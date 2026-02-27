package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
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
			BindAddr: "0.0.0.0",
		},
		TLS: TLSConfig{
			CertDir: "./certs",
			Staging: false,
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
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("saving default config: %w", err)
		}
		return cfg, nil
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
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

	// Default preserve_path for redirects
	for i := range cfg.Redirect {
		// preserve_path defaults handled by TOML zero value (false)
		_ = i
	}

	if changed {
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("saving updated config: %w", err)
		}
	}

	return cfg, nil
}

// Save writes the config to disk in TOML format.
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating config file: %w", err)
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	return nil
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
