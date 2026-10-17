#!/usr/bin/env bash
# ==============================================================================
# OpenSOC Forge - 1-Click Native Suricata NIDS Auto-Setup & Interface Binder
# Target OS: RHEL 9/10, Rocky, Alma, Fedora, Kali, Ubuntu, Debian
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    log_err "This script must be run as root (use sudo ./scripts/setup_suricata.sh)."
    exit 1
fi

echo -e "${CYAN}"
echo "================================================================================"
echo "    OpenSOC Forge - Suricata NIDS Live Telemetry Setup"
echo "================================================================================"
echo -e "${NC}"

# 1. Detect Host OS Family
OS_FAMILY=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID_LIKE:-$ID}" in
        *rhel*|*fedora*|*centos*) OS_FAMILY="rhel" ;;
        *debian*|*ubuntu*)        OS_FAMILY="debian" ;;
        *)                        OS_FAMILY="unknown" ;;
    esac
fi
log_info "Detected OS: ${PRETTY_NAME:-$ID} (Family: ${OS_FAMILY})"

# 2. Detect Active Physical/Default Network Interface
ACTIVE_NIC=""
if command -v ip >/dev/null 2>&1; then
    # Default route interface
    ACTIVE_NIC=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')
    if [ -z "${ACTIVE_NIC}" ]; then
        ACTIVE_NIC=$(ip -o link show up | awk -F': ' '$2 != "lo" && $2 !~ /^(docker|veth|br-|virbr)/ {print $2; exit}')
    fi
fi

if [ -z "${ACTIVE_NIC}" ]; then
    ACTIVE_NIC="eno1"
fi
log_ok "Monitored Network Interface detected: ${CYAN}${ACTIVE_NIC}${NC}"

# 3. Install Suricata NIDS Engine
log_info "Verifying Suricata installation..."
if ! command -v suricata >/dev/null 2>&1; then
    log_info "Installing Suricata via package manager..."
    if [ "${OS_FAMILY}" = "rhel" ]; then
        dnf install -y epel-release 2>/dev/null || true
        # Enable CRB / CodeReady Linux Builder if present (RHEL 9 / 10)
        dnf config-manager --set-enabled crb 2>/dev/null || true
        dnf --enablerepo=crb install -y suricata 2>/dev/null || dnf install -y suricata
    elif [ "${OS_FAMILY}" = "debian" ]; then
        apt-get update -y
        apt-get install -y suricata
    else
        log_err "Unsupported OS family: ${OS_FAMILY}. Please install Suricata manually."
        exit 1
    fi
fi

if command -v suricata >/dev/null 2>&1; then
    SURI_VER=$(suricata --build-info 2>/dev/null | head -n 1 || echo "installed")
    log_ok "Suricata binary verified: ${SURI_VER}"
else
    log_err "Failed to install Suricata."
    exit 1
fi

# 4. Prepare Directories and Permissions
mkdir -p /var/log/suricata
mkdir -p /etc/suricata
mkdir -p /var/lib/suricata/rules

# 5. Configure Suricata (AF_PACKET on ACTIVE_NIC & EVE JSON Output)
SURI_CONF="/etc/suricata/suricata.yaml"
if [ ! -f "${SURI_CONF}" ]; then
    if [ -f "/opt/opensoc-forge/configs/suricata/suricata.yaml" ]; then
        cp /opt/opensoc-forge/configs/suricata/suricata.yaml "${SURI_CONF}"
    fi
fi

if [ -f "${SURI_CONF}" ]; then
    log_info "Configuring ${SURI_CONF} for interface: ${ACTIVE_NIC}..."
    # Replace default interface with ACTIVE_NIC
    sed -i -E "s/interface:\s*[a-zA-Z0-9_\-]+/interface: ${ACTIVE_NIC}/g" "${SURI_CONF}"
    
    # Ensure eve-log is enabled
    sed -i "s/enabled:\s*no/enabled: yes/g" "${SURI_CONF}" 2>/dev/null || true
fi

# RHEL Sysconfig override
if [ -d /etc/sysconfig ]; then
    echo "OPTIONS=\"-i ${ACTIVE_NIC} --user suricata\"" > /etc/sysconfig/suricata
fi

# Ensure systemd service configuration runs AF_PACKET on ACTIVE_NIC
mkdir -p /etc/systemd/system/suricata.service.d
cat <<EOF > /etc/systemd/system/suricata.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/sbin/suricata -c /etc/suricata/suricata.yaml --af-packet=${ACTIVE_NIC}
Restart=always
RestartSec=3s
EOF

# Ensure rule files exist
if [ ! -f /etc/suricata/suricata.rules ] && [ -f /opt/opensoc-forge/configs/suricata/suricata.rules ]; then
    cp /opt/opensoc-forge/configs/suricata/suricata.rules /etc/suricata/suricata.rules
fi

# 6. Start / Restart Suricata Service
log_info "Reloading systemd and starting Suricata service..."
systemctl daemon-reload
systemctl enable suricata
systemctl restart suricata

sleep 2

if systemctl is-active --quiet suricata; then
    log_ok "Suricata NIDS service is RUNNING on interface: ${ACTIVE_NIC}"
else
    log_warn "Suricata service status check:"
    systemctl status suricata --no-pager || true
fi

# 7. Update OpenSOC Forge Environment
BASE_DIR="/opt/opensoc-forge"
if [ -d "${BASE_DIR}" ]; then
    if [ -f "${BASE_DIR}/.env" ]; then
        sed -i "s/^MONITORED_INTERFACE=.*/MONITORED_INTERFACE=${ACTIVE_NIC}/" "${BASE_DIR}/.env" 2>/dev/null || echo "MONITORED_INTERFACE=${ACTIVE_NIC}" >> "${BASE_DIR}/.env"
        sed -i "s|^SURICATA_EVE_PATH=.*|SURICATA_EVE_PATH=/var/log/suricata/eve.json|" "${BASE_DIR}/.env" 2>/dev/null || echo "SURICATA_EVE_PATH=/var/log/suricata/eve.json" >> "${BASE_DIR}/.env"
    fi

    # Update systemd service environment
    if [ -f /etc/systemd/system/opensoc-forge.service ]; then
        if ! grep -q "MONITORED_INTERFACE" /etc/systemd/system/opensoc-forge.service; then
            sed -i "/\[Service\]/a Environment=\"MONITORED_INTERFACE=${ACTIVE_NIC}\"" /etc/systemd/system/opensoc-forge.service
        else
            sed -i "s/Environment=\"MONITORED_INTERFACE=.*\"/Environment=\"MONITORED_INTERFACE=${ACTIVE_NIC}\"/" /etc/systemd/system/opensoc-forge.service
        fi
        systemctl daemon-reload
        systemctl restart opensoc-forge
        log_ok "OpenSOC Forge UI restarted with active interface: ${ACTIVE_NIC}"
    fi
fi

# 8. Generate Benign Network Test Packets to verify live ingestion
log_info "Generating live network test traffic on ${ACTIVE_NIC}..."
ping -c 2 8.8.8.8 >/dev/null 2>&1 || true
nslookup google.com >/dev/null 2>&1 || true
curl -s --max-time 3 https://cloudflare.com/cdn-cgi/trace >/dev/null 2>&1 || true

sleep 2

if [ -f /var/log/suricata/eve.json ]; then
    FLOW_COUNT=$(wc -l < /var/log/suricata/eve.json || echo "0")
    log_ok "Suricata EVE JSON live log verified (/var/log/suricata/eve.json): ${FLOW_COUNT} events indexed."
else
    log_warn "EVE JSON file not yet created at /var/log/suricata/eve.json. Check 'journalctl -u suricata -n 20'."
fi

echo -e "${GREEN}"
echo "================================================================================"
echo " [SUCCESS] Suricata NIDS Live Telemetry Setup Complete!"
echo " Interface  : ${ACTIVE_NIC} (Promiscuous Packet Capture)"
echo " EVE Stream : /var/log/suricata/eve.json"
echo " Dashboard  : Open 'Network Telemetry' in http://<HOST_IP>:8000/console/"
echo "================================================================================"
echo -e "${NC}"
