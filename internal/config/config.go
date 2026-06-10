package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server     ServerConfig `toml:"server"`
	TLS        TLSConfig    `toml:"tls"`
	Update     UpdateConfig `toml:"update"`
	Tunnel     []Tunnel     `toml:"tunnel"`
	Redirect   []Redirect   `toml:"redirect"`
	IPPolicy   []IPPolicy   `toml:"ip_policy"`
	AuthPolicy []AuthPolicy `toml:"auth_policy"`
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
	ID             string   `toml:"id"`
	Type           string   `toml:"type"`
	Hostnames      []string `toml:"hostnames,omitempty"`
	ListenPort     int      `toml:"listen_port,omitempty"`
	SecretHash     string   `toml:"secret_hash,omitempty"`
	PreserveHost   bool     `toml:"preserve_host,omitempty"`
	TLSPassthrough bool     `toml:"tls_passthrough,omitempty"`
	// IPPolicy / AuthPolicy reference reusable access policies by ID. They are
	// independent gates: when both are set a request must pass both (AND). Auth
	// policies apply to HTTP tunnels only.
	IPPolicy   string `toml:"ip_policy,omitempty"`
	AuthPolicy string `toml:"auth_policy,omitempty"`
}

// IPRange is one entry in an IP policy: a CIDR or single IP with an optional
// human comment for documentation.
type IPRange struct {
	CIDR    string `toml:"cidr" json:"cidr"`
	Comment string `toml:"comment,omitempty" json:"comment,omitempty"`
}

// IPPolicy is a reusable source-IP allowlist that tunnels can share. Access is
// granted to any client in Ranges (permanent) or holding a live self-service
// grant. EnrollToken, when set, exposes a shareable self-enrollment link.
type IPPolicy struct {
	ID          string    `toml:"id"`
	Ranges      []IPRange `toml:"range,omitempty"`
	EnrollToken string    `toml:"enroll_token,omitempty"`
}

// AuthPolicy is a reusable authentication requirement that tunnels can share.
// A request authenticates if it is a logged-in user in Users, OR (optionally) it
// presents the machine-generated service secret via HTTP Basic.
type AuthPolicy struct {
	ID    string   `toml:"id"`
	Users []string `toml:"users,omitempty"` // allowed user IDs (passkey login)
	// Header overrides the identity header name (default x-Gatecrash-User).
	Header string `toml:"header,omitempty"`
	// SecretHash is the bcrypt hash of a machine-generated service secret for
	// non-interactive clients (CI, scripts, webhooks). It is generated server-side
	// and shown once. Clients send it as the HTTP Basic password — by convention
	// with the username "service" (the username is not checked). A service secret
	// grants access INDEPENDENT of the Users list, so it is for trusted automation.
	SecretHash string `toml:"secret_hash,omitempty"`
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
		if t.TLSPassthrough {
			continue // passthrough tunnels handle their own TLS
		}
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

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks cross-field tunnel invariants that the TOML schema can't
// express — in particular access-control combinations that would silently not
// be enforced, which would be a security footgun if accepted.
func (c *Config) Validate() error {
	ipIDs := map[string]bool{}
	for _, p := range c.IPPolicy {
		if p.ID == "" {
			return fmt.Errorf("ip_policy: id is required")
		}
		if ipIDs[p.ID] {
			return fmt.Errorf("duplicate ip_policy id %q", p.ID)
		}
		ipIDs[p.ID] = true
		for _, r := range p.Ranges {
			if _, _, err := net.ParseCIDR(r.CIDR); err != nil && net.ParseIP(r.CIDR) == nil {
				return fmt.Errorf("ip_policy %q: invalid range %q (want IP or CIDR)", p.ID, r.CIDR)
			}
		}
	}

	authIDs := map[string]bool{}
	for _, p := range c.AuthPolicy {
		if p.ID == "" {
			return fmt.Errorf("auth_policy: id is required")
		}
		if authIDs[p.ID] {
			return fmt.Errorf("duplicate auth_policy id %q", p.ID)
		}
		authIDs[p.ID] = true
		if len(p.Users) == 0 && p.SecretHash == "" {
			return fmt.Errorf("auth_policy %q: must allow at least one user or have a service secret", p.ID)
		}
		// User login is established via the admin host's cross-host handoff.
		if len(p.Users) > 0 && c.Server.AdminHost == "" {
			return fmt.Errorf("auth_policy %q: user login requires server.admin_host", p.ID)
		}
	}

	for _, t := range c.Tunnel {
		if t.IPPolicy != "" && !ipIDs[t.IPPolicy] {
			return fmt.Errorf("tunnel %q: unknown ip_policy %q", t.ID, t.IPPolicy)
		}
		if t.AuthPolicy != "" {
			if !authIDs[t.AuthPolicy] {
				return fmt.Errorf("tunnel %q: unknown auth_policy %q", t.ID, t.AuthPolicy)
			}
			// Auth gates need the HTTP layer; passthrough/TCP never reach it.
			if t.TLSPassthrough {
				return fmt.Errorf("tunnel %q: auth_policy cannot be used with tls_passthrough (traffic never reaches the HTTP auth layer; use an ip_policy)", t.ID)
			}
			if t.Type == "tcp" {
				return fmt.Errorf("tunnel %q: auth_policy is not supported on TCP tunnels (use an ip_policy)", t.ID)
			}
		}
	}
	return nil
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
	b.WriteString("# Each tunnel needs a unique ID and a secret_hash for authentication.\n")
	b.WriteString("# The secret_hash is the bcrypt hash of the secret portion of the tunnel token.\n")
	b.WriteString("# The client connects with a tunnel token in the format: tunnel_id:secret\n")
	b.WriteString("#\n")
	b.WriteString("# Use the admin panel to create tunnels and generate tokens automatically,\n")
	b.WriteString("# or generate a bcrypt hash manually:\n")
	b.WriteString("#   htpasswd -nbBC 10 \"\" \"your-secret\" | cut -d: -f2\n")
	b.WriteString("#\n")
	b.WriteString("# Example:\n")
	b.WriteString("#   gatecrash --server host:port --token \"myapp:your-secret\" --target 127.0.0.1:8000\n")

	if len(c.Tunnel) == 0 {
		b.WriteString("#\n")
		b.WriteString("# [[tunnel]]\n")
		b.WriteString("# id = \"example\"\n")
		b.WriteString("# type = \"http\"                    # \"http\" or \"tcp\"\n")
		b.WriteString("# hostnames = [\"app.example.com\"]   # for HTTP tunnels\n")
		b.WriteString("# secret_hash = \"$2a$10$...\"        # bcrypt hash of the token secret\n")
		b.WriteString("# # preserve_host = false           # pass original Host header to backend\n")
		b.WriteString("#\n")
		b.WriteString("# # Access-policy-protected tunnel (define [[ip_policy]]/[[auth_policy]] below):\n")
		b.WriteString("# [[tunnel]]\n")
		b.WriteString("# id = \"internal-app\"\n")
		b.WriteString("# type = \"http\"\n")
		b.WriteString("# hostnames = [\"internal.example.com\"]\n")
		b.WriteString("# secret_hash = \"$2a$10$...\"\n")
		b.WriteString("# ip_policy = \"internal\"            # restrict by source IP (see [[ip_policy]])\n")
		b.WriteString("# auth_policy = \"staff\"             # require authentication (see [[auth_policy]])\n")
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
			if t.TLSPassthrough {
				b.WriteString("tls_passthrough = true\n")
			}
			if t.IPPolicy != "" {
				fmt.Fprintf(&b, "ip_policy = %q\n", t.IPPolicy)
			}
			if t.AuthPolicy != "" {
				fmt.Fprintf(&b, "auth_policy = %q\n", t.AuthPolicy)
			}
			b.WriteString("\n")
		}
	}

	// Access policy documentation + entries
	b.WriteString("# ─── Access Policies ────────────────────────────────────────────────\n")
	b.WriteString("#\n")
	b.WriteString("# Reusable IP allowlists and auth requirements, referenced by tunnels via\n")
	b.WriteString("# ip_policy / auth_policy. Both are independent gates (AND when both set).\n")
	if len(c.IPPolicy) == 0 && len(c.AuthPolicy) == 0 {
		b.WriteString("#\n")
		b.WriteString("# [[ip_policy]]\n")
		b.WriteString("# id = \"internal\"\n")
		b.WriteString("# [[ip_policy.range]]\n")
		b.WriteString("# cidr = \"10.0.0.0/8\"\n")
		b.WriteString("# comment = \"office LAN\"\n")
		b.WriteString("#\n")
		b.WriteString("# [[auth_policy]]   # define users in the admin UI; reference by id here\n")
		b.WriteString("# id = \"staff\"\n")
		b.WriteString("# users = [\"alice\"]              # user IDs allowed to access\n")
		b.WriteString("\n")
	} else {
		b.WriteString("\n\n")
		for _, p := range c.IPPolicy {
			b.WriteString("[[ip_policy]]\n")
			fmt.Fprintf(&b, "id = %q\n", p.ID)
			if p.EnrollToken != "" {
				fmt.Fprintf(&b, "enroll_token = %q\n", p.EnrollToken)
			}
			for _, r := range p.Ranges {
				b.WriteString("[[ip_policy.range]]\n")
				fmt.Fprintf(&b, "cidr = %q\n", r.CIDR)
				if r.Comment != "" {
					fmt.Fprintf(&b, "comment = %q\n", r.Comment)
				}
			}
			b.WriteString("\n")
		}
		for _, p := range c.AuthPolicy {
			b.WriteString("[[auth_policy]]\n")
			fmt.Fprintf(&b, "id = %q\n", p.ID)
			if len(p.Users) > 0 {
				fmt.Fprintf(&b, "users = [%s]\n", formatStringSlice(p.Users))
			}
			if p.Header != "" {
				fmt.Fprintf(&b, "header = %q\n", p.Header)
			}
			if p.SecretHash != "" {
				fmt.Fprintf(&b, "secret_hash = %q\n", p.SecretHash)
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
