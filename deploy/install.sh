#!/bin/sh
# Gatecrash installer / upgrader
# Usage: curl -fsSL https://raw.githubusercontent.com/jclement/gatecrash/main/deploy/install.sh | sh
set -e

REPO="jclement/gatecrash"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/gatecrash"
SERVICE_USER="gatecrash"
SERVICE_NAME="gatecrash"

# ── Colors ──────────────────────────────────────────────────────────

if [ -t 1 ]; then
    BOLD="\033[1m"
    DIM="\033[2m"
    GREEN="\033[32m"
    CYAN="\033[36m"
    YELLOW="\033[33m"
    RED="\033[31m"
    RESET="\033[0m"
else
    BOLD="" DIM="" GREEN="" CYAN="" YELLOW="" RED="" RESET=""
fi

info()  { printf "${CYAN}==>${RESET} ${BOLD}%s${RESET}\n" "$1"; }
ok()    { printf "${GREEN}==>${RESET} ${BOLD}%s${RESET}\n" "$1"; }
warn()  { printf "${YELLOW}==>${RESET} %s\n" "$1"; }
err()   { printf "${RED}==>${RESET} %s\n" "$1"; }
dim()   { printf "${DIM}    %s${RESET}\n" "$1"; }

# ── Platform detection ──────────────────────────────────────────────

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    err "This installer is for Linux only."
    dim "For macOS/Windows, download from: https://github.com/${REPO}/releases"
    exit 1
fi

printf "\n"
printf "${BOLD}  Gatecrash Installer${RESET}\n"
printf "${DIM}  ─────────────────────────────────────${RESET}\n"
printf "\n"

# ── Check for existing install ──────────────────────────────────────

CURRENT_VERSION=""
if command -v gatecrash >/dev/null 2>&1; then
    CURRENT_VERSION=$(gatecrash version 2>/dev/null | sed 's/gatecrash //' || true)
    if [ -n "$CURRENT_VERSION" ]; then
        info "Existing installation found: ${CURRENT_VERSION}"
    fi
fi

# ── Get latest release ──────────────────────────────────────────────

info "Fetching latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    err "Failed to determine latest version"
    exit 1
fi

if [ "$CURRENT_VERSION" = "v${LATEST}" ] || [ "$CURRENT_VERSION" = "${LATEST}" ]; then
    ok "Already up to date (v${LATEST})"
    exit 0
fi

if [ -n "$CURRENT_VERSION" ]; then
    info "Upgrading: ${CURRENT_VERSION} -> v${LATEST}"
else
    info "Installing: v${LATEST}"
fi
dim "Platform: ${OS}/${ARCH}"

# ── Download binary ─────────────────────────────────────────────────

URL="https://github.com/${REPO}/releases/download/v${LATEST}/gatecrash_${OS}_${ARCH}"
info "Downloading binary..."
dim "${URL}"
curl -fsSL -o /tmp/gatecrash "$URL"
chmod +x /tmp/gatecrash

# ── Install binary ──────────────────────────────────────────────────

UPGRADING=false
if [ -f "${INSTALL_DIR}/gatecrash" ]; then
    UPGRADING=true
fi

info "Installing to ${INSTALL_DIR}/gatecrash"
sudo mv /tmp/gatecrash "${INSTALL_DIR}/gatecrash"

if [ "$UPGRADING" = "true" ]; then
    ok "Binary upgraded to v${LATEST}"
    # Restart service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Restarting ${SERVICE_NAME} service..."
        sudo systemctl restart "$SERVICE_NAME"
        ok "Service restarted"
    fi
    printf "\n"
    ok "Upgrade complete!"
    printf "\n"
    exit 0
fi

# ── Fresh install setup ────────────────────────────────────────────

# Create config directory
info "Creating config directory: ${CONFIG_DIR}"
sudo mkdir -p "$CONFIG_DIR"

# Create service user
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    info "Creating service user: ${SERVICE_USER}"
    sudo useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
fi
sudo chown -R "${SERVICE_USER}:${SERVICE_USER}" "$CONFIG_DIR"

# Create systemd service
info "Creating systemd service"
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Gatecrash Tunnel Server
After=network.target
Documentation=https://github.com/${REPO}

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/gatecrash server --config ${CONFIG_DIR}/gatecrash.toml
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}
PrivateTmp=true

# Allow binding to privileged ports (80, 443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"

# Start the service
info "Starting ${SERVICE_NAME}..."
sudo systemctl start "$SERVICE_NAME"

# Wait briefly for config generation
sleep 2

# ── Print summary ──────────────────────────────────────────────────

printf "\n"
ok "Gatecrash v${LATEST} installed and running!"
printf "\n"
dim "Config:  ${CONFIG_DIR}/gatecrash.toml"
dim "Logs:    sudo journalctl -u ${SERVICE_NAME} -f"
dim "Status:  sudo systemctl status ${SERVICE_NAME}"
dim "Admin:   http://<your-ip>:8080/"
printf "\n"
dim "A config file has been generated with a random SSH port."
dim "Edit ${CONFIG_DIR}/gatecrash.toml to add tunnels and set up TLS."
printf "\n"
