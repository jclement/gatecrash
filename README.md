<p align="center">
  <img src="web/static/logo.png" alt="Gatecrash" width="200">
</p>

<h1 align="center">Gatecrash</h1>

<p align="center">
  Self-hosted tunnel server. Expose local services through a public server with automatic TLS.
  <br>
  A self-hosted alternative to Cloudflare Tunnels, ngrok, and similar services.
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#oidc-authentication">OIDC</a> &bull;
  <a href="#docker">Docker</a>
</p>

> [!NOTE]
> This project is **vibe coded** with [Claude Code](https://claude.ai/claude-code). The entire codebase — server, client, admin panel, CI/CD, and this README — was built collaboratively with AI. Use at your own risk, but it actually works pretty well.

---

## Installation

Gatecrash ships as two separate binaries:

| Binary | Purpose | Size |
|--------|---------|------|
| `gatecrash-server` | Tunnel server with admin panel, TLS, OIDC | ~15 MB |
| `gatecrash` | Lightweight tunnel client | ~7 MB |

### Linux Server (Quick Install)

Installs `gatecrash-server`, creates a systemd service, and starts it:

```bash
curl -fsSL https://raw.githubusercontent.com/jclement/gatecrash/main/deploy/install.sh | sh
```

### Homebrew (macOS/Linux)

```bash
# Server
brew install jclement/tap/gatecrash-server

# Client
brew install jclement/tap/gatecrash
```

### Go

```bash
# Server
go install github.com/jclement/gatecrash/cmd/gatecrash-server@latest

# Client
go install github.com/jclement/gatecrash/cmd/gatecrash@latest
```

### Docker

```bash
# Server
docker pull ghcr.io/jclement/gatecrash-server:latest

# Client (lightweight)
docker pull ghcr.io/jclement/gatecrash:latest
```

### Binary Releases

Download pre-built binaries for Linux, macOS, and Windows from [GitHub Releases](https://github.com/jclement/gatecrash/releases).

---

## Quick Start

1. **Provision a server** with a public IP (any Linux VPS will do)

2. **Point a hostname** at your server's IP via DNS (e.g. `admin.example.com`)

3. **Run the installer** — it downloads the binary, generates a config, creates a systemd service, and starts Gatecrash. It will ask for your admin hostname during setup.

   ```bash
   curl -fsSL https://raw.githubusercontent.com/jclement/gatecrash/main/deploy/install.sh | sh
   ```

   Or download from [GitHub Releases](https://github.com/jclement/gatecrash/releases) for manual installation.

4. **Open the admin panel** at `https://admin.example.com`, register your passkey, and click **Add Tunnel** to create your first tunnel

5. **Connect a client** using the command shown in the admin panel (the SSH port and host key are displayed when you create a tunnel):

   ```bash
   gatecrash \
     --server tunnel.example.com:51234 \
     --host-key "SHA256:..." \
     --token "web-app:YOUR_SECRET" \
     --target 127.0.0.1:8000
   ```

   > The SSH port is randomly assigned on first run (check `ssh_port` in `gatecrash.toml`). The exact connection command is shown in the admin panel when you create a tunnel or regenerate a secret.

That's it. Requests to your configured hostname now reach your local service on port 8000.

---

## How It Works

Gatecrash uses SSH as the transport layer for tunnel connections. The server accepts SSH connections from clients, then reverse-opens channels back to the client for each incoming HTTP request or TCP connection.

```mermaid
sequenceDiagram
    participant User as Browser
    participant Server as Gatecrash Server
    participant Client as Gatecrash Client
    participant App as Local App

    Client->>Server: SSH connect (authenticate with token)
    Server-->>Client: Connection established

    User->>Server: HTTPS request to app.example.com
    Server->>Server: SNI routing -> find tunnel for hostname
    Server->>Client: Open HTTP channel (reverse)
    Client->>App: Forward request to 127.0.0.1:8000
    App-->>Client: Response
    Client-->>Server: Response via SSH channel
    Server-->>User: HTTPS response
```

### HTTP Tunnels

HTTP tunnels route traffic based on the `Host` header. Multiple hostnames can map to a single tunnel. TLS certificates are automatically provisioned via Let's Encrypt.

### TCP Tunnels

TCP tunnels forward raw TCP connections on a dedicated port. Useful for databases, game servers, or any non-HTTP protocol.

### Config Live Reload

The server watches `gatecrash.toml` for changes. Valid changes are applied immediately without dropping existing connections. Invalid changes are rejected and the error is shown in the admin panel.

### HTTP Redirects

Redirect hostnames without needing a tunnel:

```toml
[[redirect]]
from = "www.example.com"
to = "example.com"
preserve_path = true
```

---

## Configuration

### Server Configuration (`gatecrash.toml`)

The config file is auto-generated on first run with sensible defaults and inline documentation.

#### Server Settings

| Field | Default | Description |
|-------|---------|-------------|
| `server.secret` | auto-generated | Session signing secret (do not share) |
| `server.ssh_port` | random high port | SSH listen port for tunnel connections |
| `server.https_port` | `443` | HTTPS listen port |
| `server.http_port` | `80` | HTTP->HTTPS redirect port (0 to disable) |
| `server.bind_addr` | `0.0.0.0` | Bind address |
| `server.admin_host` | _(disabled)_ | Hostname for admin panel (required to enable it) |

#### TLS Settings

| Field | Default | Description |
|-------|---------|-------------|
| `tls.acme_email` | | Email for Let's Encrypt expiration notices |
| `tls.cert_dir` | `./certs` | Certificate storage directory |
| `tls.staging` | `false` | Use Let's Encrypt staging CA |

#### Update Settings

| Field | Default | Description |
|-------|---------|-------------|
| `update.enabled` | `true` | Check for updates on startup |
| `update.check_interval` | `6h` | How often to check for updates |
| `update.github_repo` | `jclement/gatecrash` | GitHub repo for update checks |

#### Tunnel Options

| Option | Default | Description |
|--------|---------|-------------|
| `preserve_host` | `false` | Pass the original `Host` header to the backend |
| `tls_passthrough` | `false` | Forward raw TLS without terminating (backend handles TLS) |
| `require_auth` | `false` | Require OIDC authentication to access this tunnel |
| `auth_rule` | | OIDC rule name that must match for access |
| `auth_header` | `x-Gatecrash-User` | Header name for authenticated user identity |
| `auth_header_claim` | _(email claim)_ | Which OIDC claim value to put in the auth header |

Example:

```toml
[[tunnel]]
id = "backend-api"
type = "http"
hostnames = ["api.example.com"]
secret_hash = "$2a$12$..."
preserve_host = true
require_auth = true
auth_rule = "Employees"
auth_header = "x-Gatecrash-User"
auth_header_claim = "email"
```

#### Forwarding Headers

For HTTP tunnels (when `tls_passthrough = false`), the following headers are injected:

| Header | Value |
|--------|-------|
| `X-Forwarded-For` | Original client IP |
| `X-Forwarded-Proto` | `https` or `http` |
| `X-Forwarded-Host` | Original Host header |
| `X-Real-IP` | Original client IP |
| `X-Request-Id` | Unique request ID |

When `require_auth = true`, the configured `auth_header` is also injected with the authenticated user's claim value.

---

## OIDC Authentication

By default, Gatecrash uses passkey authentication (single admin user). When OIDC is enabled, it **replaces** passkeys entirely -- all admin and tunnel authentication goes through your OIDC provider.

### Configuring OIDC

Add the `[oidc]` section to `gatecrash.toml`:

```toml
[oidc]
enabled = true
provider_name = "Keycloak"            # Display name on login button
client_id = "gatecrash"
client_secret = "your-client-secret"
auth_url = "https://idp.example.com/auth/realms/main/protocol/openid-connect/auth"
token_url = "https://idp.example.com/auth/realms/main/protocol/openid-connect/token"
cert_url = "https://idp.example.com/auth/realms/main/protocol/openid-connect/certs"
use_pkce = false
name_claim = "name"                   # Claim containing user's display name
email_claim = "email"                 # Claim containing user's email

# Optional: restrict admin access to users matching a specific claim.
# When empty, any authenticated OIDC user is an admin.
admin_claim_name = "role"
admin_claim_value = "admin"
```

> **Note:** OIDC is configured in `gatecrash.toml` only. Environment variables are not supported for OIDC settings.

When OIDC is enabled:
- The login page auto-redirects to your OIDC provider
- Passkey authentication is disabled (the Passkeys tab is hidden)
- Audit log entries show the OIDC user's name and email

### Protecting Tunnels

HTTP tunnels can require authentication via the **Require Authentication** checkbox in the tunnel edit dialog.

**In passkey mode:** the admin must be logged in with their passkey to access the tunnel (single-user).

**In OIDC mode:** users are redirected to the OIDC provider. You can optionally restrict access by claim:

```toml
[[tunnel]]
id = "internal-app"
type = "http"
hostnames = ["internal.example.com"]
secret_hash = "$2a$12$..."
require_auth = true                   # Users must authenticate
auth_claim_name = "department"        # Optional: restrict by claim
auth_claim_value = "engineering"      # Only users with this claim value get access
auth_header = "x-Gatecrash-User"     # Header injected into proxied requests
auth_header_claim = "email"          # Claim value to put in the header
```

When `auth_claim_name` is empty, any authenticated OIDC user can access the tunnel. The `auth_header` is injected into all proxied requests with the authenticated user's claim value.

Claim filters support string and array claims (e.g. if `groups` is `["engineering", "ops"]`, filtering on `engineering` will match).

### Callback URLs

Register these callback URLs with your OIDC provider:

- **Admin login:** `https://<admin_host>/oidc/callback`
- **Tunnel auth:** `https://<tunnel_hostname>/.gatecrash/oidc/callback` (one per protected tunnel hostname)

---

## Audit Log

All admin panel changes are recorded in an audit log, viewable from the **Audit Log** tab.

Logged events include:
- Tunnel create, edit, delete, and secret regeneration
- Redirect create, edit, delete
- Admin logins (passkey or OIDC)

Each entry records the timestamp, actor identity (`Admin (passkey)` or `Name <email>` for OIDC users), action, and detail. The log is stored at `<config_dir>/audit.json` and retains the most recent 1,000 entries.

---

## CLI Reference

### Server (`gatecrash-server`)

```
gatecrash-server              Start the tunnel server (default)
gatecrash-server make-config  Generate a config file
gatecrash-server update       Self-update to latest release
gatecrash-server version      Print version
gatecrash-server help         Show help
```

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--config` | `GATECRASH_CONFIG` | `/etc/gatecrash/gatecrash.toml` | Config file path |
| `--debug` | | `false` | Enable debug logging |

### Client (`gatecrash`)

The client runs directly without subcommands:

```
gatecrash [flags]       Connect a tunnel to the server
gatecrash update        Self-update to latest release
gatecrash version       Print version
gatecrash help          Show help
```

| Flag | Env Var | Required | Default | Description |
|------|---------|----------|---------|-------------|
| `--server` | `GATECRASH_SERVER` | **Yes** | | Server SSH address (`host:port`) |
| `--token` | `GATECRASH_TOKEN` | **Yes** | | Tunnel token (`tunnel_id:secret`) |
| `--target` | `GATECRASH_TARGET` | **Yes** | | Target service address (`[scheme://]host:port`) |
| `--host-key` | `GATECRASH_HOST_KEY` | **Yes** | | Server SSH fingerprint (`SHA256:...`) |
| `--count` | `GATECRASH_COUNT` | No | `1` | Parallel tunnel connections (1-10) |
| `--debug` | | No | `false` | Enable debug logging |

#### Target Schemes

| Target | Behavior |
|--------|----------|
| `localhost:8080` | Plain HTTP (default) |
| `https://localhost:8443` | TLS with certificate verification |
| `https+insecure://localhost:8443` | TLS without certificate verification |

---

## Docker

### Server

```bash
# Replace 51234 with the ssh_port from your gatecrash.toml
docker run -d \
  -p 443:443 -p 80:80 -p 51234:51234 \
  -v gatecrash-config:/etc/gatecrash \
  ghcr.io/jclement/gatecrash-server:latest
```

The SSH port is randomly generated on first run. Check `ssh_port` in your `gatecrash.toml` to find the assigned port.

### Client

```bash
docker run -d \
  -e GATECRASH_SERVER=tunnel.example.com:51234 \
  -e GATECRASH_HOST_KEY=SHA256:your_host_key_fingerprint \
  -e GATECRASH_TOKEN=web-app:YOUR_SECRET \
  -e GATECRASH_TARGET=app:8000 \
  --network=app-network \
  ghcr.io/jclement/gatecrash:latest
```

The client image is minimal -- just the tunnel client binary with ca-certificates.

### Docker Compose -- Client with Service

A typical deployment pairs the `gatecrash` client with your application:

```yaml
services:
  # Your application
  whoami:
    image: traefik/whoami
    expose:
      - "80"

  # Gatecrash tunnel client
  tunnel:
    image: ghcr.io/jclement/gatecrash:latest
    environment:
      GATECRASH_SERVER: tunnel.example.com:51234
      GATECRASH_HOST_KEY: "SHA256:your_host_key_fingerprint"
      GATECRASH_TOKEN: "web-app:YOUR_SECRET"
      GATECRASH_TARGET: whoami:80
    depends_on:
      - whoami
    restart: unless-stopped
```

### Docker Compose -- Server

```yaml
services:
  server:
    image: ghcr.io/jclement/gatecrash-server:latest
    ports:
      - "80:80"
      - "443:443"
      - "51234:51234"    # Match ssh_port in your gatecrash.toml
    volumes:
      - config:/etc/gatecrash
    restart: unless-stopped

volumes:
  config:
```

OIDC and other settings are configured in `gatecrash.toml` inside the config volume, or via the admin panel.

---

## Development

```bash
# Install tools
mise install

# Download frontend assets
mise run setup

# Run server with hot-reload
mise run dev

# Run tests
mise run test

# Build both binaries
mise run build

# Test release
mise run release-snapshot
```

---

## Architecture

```
gatecrash/
├── cmd/
│   ├── gatecrash/           # Client binary
│   └── gatecrash-server/    # Server binary
├── internal/
│   ├── config/              # TOML config + file watcher
│   ├── server/              # SSH server, HTTP proxy, TCP forward, vhost routing, TLS
│   ├── client/              # SSH client, HTTP/TCP handlers, reconnect logic
│   ├── admin/               # Web admin panel (passkeys, OIDC, sessions, audit log)
│   ├── protocol/            # SSH channel types and control messages (shared)
│   ├── token/               # bcrypt-based tunnel authentication
│   └── update/              # Self-update via GitHub releases (shared)
├── web/                     # HTML templates + static assets (server only)
├── deploy/                  # Install script, docker-compose examples
└── .github/                 # CI/CD, dependabot
```

## License

MIT

---

<p align="center">
  <em>Vibe coded with <a href="https://claude.ai/claude-code">Claude Code</a></em>
</p>
