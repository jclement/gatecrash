#!/bin/sh
# Gatecrash installer
# Usage: curl -fsSL https://raw.githubusercontent.com/jclement/gatecrash/main/deploy/install.sh | sh
set -e

REPO="jclement/gatecrash"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/gatecrash"
SERVICE_USER="gatecrash"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    echo "This installer is for Linux only. For macOS/Windows, download from GitHub Releases."
    exit 1
fi

echo "==> Gatecrash Installer"
echo "    OS: $OS, Arch: $ARCH"

# Get latest release version
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    echo "Failed to determine latest version"
    exit 1
fi
echo "    Version: v${LATEST}"

# Download binary
URL="https://github.com/${REPO}/releases/download/v${LATEST}/gatecrash_${OS}_${ARCH}"
echo "==> Downloading ${URL}"
curl -fsSL -o /tmp/gatecrash "$URL"
chmod +x /tmp/gatecrash

# Install
echo "==> Installing to ${INSTALL_DIR}/gatecrash"
sudo mv /tmp/gatecrash "${INSTALL_DIR}/gatecrash"

# Create config directory
sudo mkdir -p "$CONFIG_DIR"

# Create service user if it doesn't exist
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "==> Creating service user: ${SERVICE_USER}"
    sudo useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
fi
sudo chown -R "${SERVICE_USER}:${SERVICE_USER}" "$CONFIG_DIR"

# Create systemd service
echo "==> Creating systemd service"
sudo tee /etc/systemd/system/gatecrash.service > /dev/null <<EOF
[Unit]
Description=Gatecrash Tunnel Server
After=network.target

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

# Allow binding to privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable gatecrash

echo ""
echo "==> Gatecrash installed successfully!"
echo ""
echo "    Config: ${CONFIG_DIR}/gatecrash.toml"
echo "    Start:  sudo systemctl start gatecrash"
echo "    Logs:   sudo journalctl -u gatecrash -f"
echo ""
echo "    On first start, a config file will be generated with a random SSH port."
echo "    Edit ${CONFIG_DIR}/gatecrash.toml to configure tunnels, then restart."
