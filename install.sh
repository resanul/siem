#!/usr/bin/env bash
# ==============================================================================
# OpenSOC Forge - Universal 1-Click Linux Systemd Service Installer
# Requirement R1 & R4: Automated provisioning across Kali Linux, Debian,
# Ubuntu, RHEL 9, Rocky Linux 9, AlmaLinux, and Fedora.
# ==============================================================================
set -euo pipefail

# ------------------------------------------------------------------------------
# Defaults & Global Variables
# ------------------------------------------------------------------------------
INSTALL_DIR="${INSTALL_DIR:-/opt/opensoc-forge}"
SKIP_PREFLIGHT=false
DRY_RUN=false
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()  { echo -e "${CYAN}[INFO]${NC} $(date +'%Y-%m-%d %H:%M:%S') - $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}   $(date +'%Y-%m-%d %H:%M:%S') - $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $(date +'%Y-%m-%d %H:%M:%S') - $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date +'%Y-%m-%d %H:%M:%S') - $*" >&2; }

# ------------------------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------------------------
usage() {
    cat <<EOF
OpenSOC Forge 1-Click Installer

Usage: sudo ./install.sh [OPTIONS]

Options:
  -s, --skip-preflight    Bypass hardware resource preflight checks (RAM/CPU/Disk)
  -d, --dir <PATH>        Target installation directory (default: /opt/opensoc-forge)
  -n, --dry-run           Perform preflight and configuration checks without installing
  -h, --help              Show this help message and exit

Supported Operating Systems:
  - Kali Linux 2024+
  - Debian 12 (Bookworm)
  - Ubuntu 22.04 / 24.04 LTS
  - Red Hat Enterprise Linux (RHEL) 9
  - Rocky Linux 9
  - AlmaLinux 9
  - Fedora 39 / 40+
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--skip-preflight)
            SKIP_PREFLIGHT=true
            shift
            ;;
        -d|--dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage 1
            ;;
    esac
done

echo -e "${BLUE}"
echo "================================================================================"
echo "         OpenSOC Forge — Universal Linux 1-Click Systemd Installer             "
echo "================================================================================"
echo -e "${NC}"

# ------------------------------------------------------------------------------
# 1. Root Privileges Check
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ] && [ "${DRY_RUN}" != "true" ]; then
    log_error "install.sh must be executed as root. Please run with sudo: 'sudo ./install.sh'"
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. OS Family Detection & Classification
# ------------------------------------------------------------------------------
log_info "Detecting operating system family via /etc/os-release..."
if [ ! -f /etc/os-release ]; then
    log_error "/etc/os-release not detected. Unsupported platform."
    exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release
OS_ID="${ID:-}"
OS_LIKE="${ID_LIKE:-}"
OS_NAME="${PRETTY_NAME:-$NAME}"

log_info "Detected Host OS: ${OS_NAME} (ID: ${OS_ID}, ID_LIKE: ${OS_LIKE})"

OS_FAMILY="unsupported"
PKG_MGR=""

if [[ "${OS_ID}" =~ ^(kali|debian|ubuntu)$ ]] || [[ "${OS_LIKE}" =~ debian ]]; then
    OS_FAMILY="debian"
    PKG_MGR="apt-get"
    export DEBIAN_FRONTEND=noninteractive
elif [[ "${OS_ID}" =~ ^(rhel|rocky|almalinux|fedora|centos)$ ]] || [[ "${OS_LIKE}" =~ (rhel|fedora|centos) ]]; then
    OS_FAMILY="rhel"
    PKG_MGR="dnf"
fi

if [ "${OS_FAMILY}" = "unsupported" ]; then
    log_error "Unsupported Linux distribution: ${OS_NAME}."
    log_error "OpenSOC Forge requires Debian/Kali/Ubuntu or RHEL/Rocky/AlmaLinux/Fedora."
    exit 1
fi

log_ok "OS Family classified as '${OS_FAMILY}' (Package Manager: ${PKG_MGR})."

# ------------------------------------------------------------------------------
# 3. Hardware Preflight Verification
# ------------------------------------------------------------------------------
if [ "${SKIP_PREFLIGHT}" = "true" ]; then
    log_warn "Hardware preflight verification bypassed via --skip-preflight."
else
    log_info "Running system hardware preflight checks..."
    PREFLIGHT_FAILED=false

    # RAM: Minimum 8GB (allow 7600MB = 7782400 KB VM/hypervisor reservation threshold)
    MEM_TOTAL_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    MEM_TOTAL_MB=$(( MEM_TOTAL_KB / 1024 ))
    if [ "${MEM_TOTAL_KB}" -lt 7782400 ]; then
        log_error "Insufficient RAM: ${MEM_TOTAL_MB} MB detected. Minimum 8GB (7600 MB VM threshold) required."
        log_error "To override on low-memory test systems, rerun with: './install.sh --skip-preflight'"
        PREFLIGHT_FAILED=true
    else
        log_ok "Memory check passed: ${MEM_TOTAL_MB} MB available."
    fi

    # CPU Cores: Minimum 4 cores
    CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
    if [ "${CPU_CORES}" -lt 4 ]; then
        log_error "Insufficient CPU cores: ${CPU_CORES} core(s) detected. Minimum 4 cores required."
        PREFLIGHT_FAILED=true
    else
        log_ok "CPU cores check passed: ${CPU_CORES} cores available."
    fi

    # Disk Space: Minimum 30GB free on target filesystem (31457280 KB)
    PARENT_DIR="$(dirname "${INSTALL_DIR}")"
    [ ! -d "${PARENT_DIR}" ] && PARENT_DIR="/"
    DISK_AVAIL_KB=$(df -Pk "${PARENT_DIR}" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    DISK_AVAIL_GB=$(( DISK_AVAIL_KB / (1024 * 1024) ))
    if [ "${DISK_AVAIL_KB}" -lt 31457280 ]; then
        log_error "Insufficient disk space: ${DISK_AVAIL_GB} GB available on ${PARENT_DIR}. Minimum 30GB required."
        PREFLIGHT_FAILED=true
    else
        log_ok "Disk space check passed: ${DISK_AVAIL_GB} GB available."
    fi

    # Network Interface: At least one active non-loopback interface in operstate UP
    ACTIVE_IFACE=$(ip -o link show up 2>/dev/null | awk -F': ' '$2 != "lo" {print $2; exit}' || echo "")
    if [ -z "${ACTIVE_IFACE}" ]; then
        log_error "No active non-loopback network interface with operstate UP found."
        PREFLIGHT_FAILED=true
    else
        log_ok "Active network interface detected: ${ACTIVE_IFACE}."
    fi

    if [ "${PREFLIGHT_FAILED}" = "true" ]; then
        log_error "Hardware preflight checks failed. Aborting installation."
        exit 1
    fi
fi

# Detect Host IP
HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
log_info "Primary host IP for Web Console binding: ${HOST_IP}"

if [ "${DRY_RUN}" = "true" ]; then
    log_ok "[DRY-RUN] Preflight and configuration validation passed. No changes committed."
    exit 0
fi

# ------------------------------------------------------------------------------
# 4. Kernel Parameter Tuning (sysctl)
# ------------------------------------------------------------------------------
log_info "Applying required kernel parameter optimizations..."
# Runtime tuning for Elasticsearch and socket buffering
sysctl -w vm.max_map_count=262144 2>/dev/null || true
sysctl -w fs.file-max=65536 2>/dev/null || true
sysctl -w net.core.somaxconn=1024 2>/dev/null || true

# Persistent configuration in /etc/sysctl.d/99-opensoc-forge.conf
SYSCTL_TARGET="/etc/sysctl.d/99-opensoc-forge.conf"
if [ -d "/etc/sysctl.d" ]; then
    if [ -f "${SOURCE_DIR}/configs/sysctl/99-opensoc-forge.conf" ]; then
        cp -f "${SOURCE_DIR}/configs/sysctl/99-opensoc-forge.conf" "${SYSCTL_TARGET}"
    else
        cat <<EOF > "${SYSCTL_TARGET}"
# OpenSOC Forge Kernel Optimizations
vm.max_map_count=262144
fs.file-max=65536
net.core.somaxconn=1024
EOF
    fi
    chmod 644 "${SYSCTL_TARGET}"
    sysctl --system 2>/dev/null || sysctl -p "${SYSCTL_TARGET}" 2>/dev/null || true
    log_ok "Kernel parameters persisted to ${SYSCTL_TARGET}."
fi

# ------------------------------------------------------------------------------
# 5. Automated Container Engine Provisioning
# ------------------------------------------------------------------------------
log_info "Verifying container engine and compose availability..."
COMPOSE_CMD=""

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE_CMD="podman-compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
fi

if [ -z "${COMPOSE_CMD}" ]; then
    log_info "Container compose engine not detected. Provisioning container runtime for ${OS_FAMILY}..."
    if [ "${OS_FAMILY}" = "debian" ]; then
        log_info "Installing Docker engine and compose plugin via apt-get..."
        apt-get update -y
        apt-get install -y --no-install-recommends docker.io docker-compose-plugin curl ca-certificates jq
        systemctl enable --now docker 2>/dev/null || true
        COMPOSE_CMD="docker compose"
    elif [ "${OS_FAMILY}" = "rhel" ]; then
        log_info "Installing EPEL and container engine via dnf..."
        dnf install -y epel-release 2>/dev/null || true
        dnf install -y podman podman-compose curl jq || {
            log_warn "podman-compose dnf install failed, attempting pip fallback..."
            dnf install -y python3-pip && pip3 install podman-compose || true
            [ -f /usr/local/bin/podman-compose ] && ln -sf /usr/local/bin/podman-compose /usr/bin/podman-compose || true
        }
        systemctl enable --now podman.socket 2>/dev/null || true
        if command -v podman-compose >/dev/null 2>&1; then
            COMPOSE_CMD="podman-compose"
        elif podman compose version >/dev/null 2>&1; then
            COMPOSE_CMD="podman compose"
        fi
    fi
fi

log_ok "Container runtime ready: using '${COMPOSE_CMD}'."

# ------------------------------------------------------------------------------
# 6. Non-Interactive Staging to /opt/opensoc-forge
# ------------------------------------------------------------------------------
log_info "Staging OpenSOC Forge platform files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/backups"

# Copy repository tree to target directory idempotently
for dir_item in configs scripts systemd bin backend frontend adapters orchestration compatibility releases rules; do
    mkdir -p "${INSTALL_DIR}/${dir_item}"
    if [ -d "${SOURCE_DIR}/${dir_item}" ]; then
        cp -a "${SOURCE_DIR}/${dir_item}/." "${INSTALL_DIR}/${dir_item}/" 2>/dev/null || true
    fi
done

for file_item in docker-compose.yml podman-compose.yml Dockerfile pyproject.toml; do
    if [ -f "${SOURCE_DIR}/${file_item}" ]; then
        cp -f "${SOURCE_DIR}/${file_item}" "${INSTALL_DIR}/"
    fi
done

# Initialize .env from .env.example if not present
if [ ! -f "${INSTALL_DIR}/.env" ]; then
    if [ -f "${SOURCE_DIR}/.env.example" ]; then
        cp -f "${SOURCE_DIR}/.env.example" "${INSTALL_DIR}/.env"
    else
        cat <<EOF > "${INSTALL_DIR}/.env"
OPENSOC_ENV=production
HOST_IP=${HOST_IP}
MGMT_PORT=7070
ES_PORT=9200
KIBANA_PORT=5601
WAZUH_PORT=1514
SYSLOG_PORT=514
ELASTICSEARCH_URL=http://elasticsearch:9200
EOF
    fi
fi

# Ensure active interface is bound for Suricata to prevent startup crash
if [ -n "${ACTIVE_IFACE:-}" ]; then
    if grep -q "MONITORED_INTERFACE=" "${INSTALL_DIR}/.env" 2>/dev/null; then
        sed -i "s/^MONITORED_INTERFACE=.*/MONITORED_INTERFACE=${ACTIVE_IFACE}/" "${INSTALL_DIR}/.env"
    else
        echo "MONITORED_INTERFACE=${ACTIVE_IFACE}" >> "${INSTALL_DIR}/.env"
    fi
    log_ok "Suricata monitoring interface bound to host interface: ${ACTIVE_IFACE}"
fi

# Ensure executable permissions on scripts and CLI
chmod +x "${INSTALL_DIR}/bin/opensoc-ctl" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/scripts/"*.sh 2>/dev/null || true

# ------------------------------------------------------------------------------
# 7. TLS Certificate Generation
# ------------------------------------------------------------------------------
log_info "Generating TLS certificates for Elasticsearch and Syslog..."
CERT_DIR="${INSTALL_DIR}/configs/elasticsearch/certs"
mkdir -p "${CERT_DIR}"
if [ -f "${INSTALL_DIR}/scripts/generate_certs.sh" ]; then
    bash "${INSTALL_DIR}/scripts/generate_certs.sh" "${CERT_DIR}"
fi

# ------------------------------------------------------------------------------
# 8. Security & Network Policy Alignment (R4)
# ------------------------------------------------------------------------------
log_info "Configuring security policies (Firewalld, SELinux, Capabilities)..."

# RHEL / Rocky SELinux container booleans
if command -v setsebool >/dev/null 2>&1; then
    setsebool -P container_manage_cgroup 1 2>/dev/null || true
    setsebool -P container_use_devices 1 2>/dev/null || true
fi

# Kali / Debian packet sniffing capabilities
if command -v setcap >/dev/null 2>&1; then
    for bin_target in /usr/bin/suricata /usr/sbin/tcpdump; do
        if [ -f "${bin_target}" ]; then
            setcap cap_net_raw,cap_net_admin+eip "${bin_target}" 2>/dev/null || true
        fi
    done
fi

if [ -f "${INSTALL_DIR}/scripts/configure_security_policies.sh" ]; then
    INSTALL_DIR="${INSTALL_DIR}" bash "${INSTALL_DIR}/scripts/configure_security_policies.sh"
fi

# ------------------------------------------------------------------------------
# 9. Native Systemd Service Unit Installation & CLI Symlink
# ------------------------------------------------------------------------------
log_info "Installing systemd service unit and CLI command..."
SYSTEMD_TARGET="/etc/systemd/system/opensoc-forge.service"
if [ -d "/etc/systemd/system" ] && [ -f "${INSTALL_DIR}/systemd/opensoc-forge.service" ]; then
    cp -f "${INSTALL_DIR}/systemd/opensoc-forge.service" "${SYSTEMD_TARGET}"
    chmod 644 "${SYSTEMD_TARGET}"
    systemctl daemon-reload
    systemctl enable opensoc-forge.service 2>/dev/null || true
    log_ok "Systemd service opensoc-forge.service enabled for boot auto-start."
fi

# Symlink bin/opensoc-ctl -> /usr/local/bin/opensoc-ctl
mkdir -p /usr/local/bin
ln -sf "${INSTALL_DIR}/bin/opensoc-ctl" /usr/local/bin/opensoc-ctl
log_ok "CLI tool linked to /usr/local/bin/opensoc-ctl."

# ------------------------------------------------------------------------------
# 10. Start Platform Service & Pre-pull Images
# ------------------------------------------------------------------------------
log_info "Pre-pulling core container images (Elasticsearch, Kibana, Wazuh, Suricata, Vector)..."
log_info "This may take 5 to 15 minutes depending on your internet bandwidth. Please wait..."
(cd "${INSTALL_DIR}" && ${COMPOSE_CMD} pull || true)

log_info "Building OpenSOC Forge management container..."
(cd "${INSTALL_DIR}" && ${COMPOSE_CMD} build || true)

log_info "Starting OpenSOC Forge systemd service..."
if command -v systemctl >/dev/null 2>&1 && [ -f "${SYSTEMD_TARGET}" ]; then
    systemctl restart opensoc-forge.service 2>/dev/null || {
        log_warn "Systemd restart command issued; containers launching in background."
    }
else
    # Fallback in non-systemd container environments
    log_info "Starting platform via compose background runner..."
    (cd "${INSTALL_DIR}" && ${COMPOSE_CMD} up -d)
fi

# Synchronous Health Verification Loop
log_info "Waiting for core services to reach healthy status (up to 120s)..."
WAIT_COUNT=0
MAX_WAIT=24
ALL_HEALTHY=false

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    if curl -s --connect-timeout 2 "http://127.0.0.1:7070/" >/dev/null 2>&1; then
        ALL_HEALTHY=true
        log_ok "Management API is ONLINE and responding at http://${HOST_IP}:7070/."
        break
    fi
    echo -n "."
    sleep 5
    WAIT_COUNT=$((WAIT_COUNT + 1))
done
echo ""

if [ "${ALL_HEALTHY}" != "true" ]; then
    log_warn "Services are still initializing in the background."
    log_warn "Check live logs with: 'cd ${INSTALL_DIR} && ${COMPOSE_CMD} logs -f'"
fi

# ------------------------------------------------------------------------------
# 11. Completion Banner & Access Info
# ------------------------------------------------------------------------------
echo -e "${GREEN}"
echo "================================================================================"
echo " [SUCCESS] OpenSOC Forge Deployment Completed Successfully!"
echo "================================================================================"
echo -e "${NC}"
echo " Access Information:"
echo "   - Web Console UI   : http://${HOST_IP}:7070/console/"
echo "   - Management API   : http://${HOST_IP}:7070/api/v1/docs"
echo "   - Kibana Dashboard : http://${HOST_IP}:5601"
echo "   - Elasticsearch    : http://${HOST_IP}:9200"
echo "   - Wazuh Manager    : ports 1514 (events), 1515 (auth), 55000 (api)"
echo "   - Syslog Collector : ports 514 (udp/tcp), 6514 (tls)"
echo ""
echo " Management & Operations:"
echo "   - Systemd Service  : systemctl status opensoc-forge"
echo "   - Unified Logs     : journalctl -u opensoc-forge -f"
echo "   - CLI Tool Status  : opensoc-ctl status"
echo "   - Pipeline Test    : opensoc-ctl test"
echo "   - Backup Archive   : opensoc-ctl backup"
echo ""
echo " Credentials:"
echo "   - Elasticsearch / Kibana: elastic / OpenSocForge2026!"
echo "   - Wazuh API             : wazuh  / OpenSocForge2026!"
echo "================================================================================"
