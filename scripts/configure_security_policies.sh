#!/usr/bin/env bash
# OpenSOC Forge - Cross-Distribution Security & Network Policy Alignment
# Requirement R4: SELinux, Firewalld, UFW, Network Capabilities, and Promiscuous Mode
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/opensoc-forge}"

log_info() { echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $*"; }
log_warn() { echo "[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $*" >&2; }

# 1. Detect Distribution Family
OS_FAMILY="unsupported"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"

    if [[ "${OS_ID}" =~ ^(kali|debian|ubuntu)$ ]] || [[ "${OS_LIKE}" =~ debian ]]; then
        OS_FAMILY="debian"
    elif [[ "${OS_ID}" =~ ^(rhel|rocky|almalinux|fedora|centos)$ ]] || [[ "${OS_LIKE}" =~ (rhel|fedora|centos) ]]; then
        OS_FAMILY="rhel"
    fi
fi

log_info "Detected OS Family for policy alignment: ${OS_FAMILY}"

# 2. Configure RHEL / Rocky / AlmaLinux / Fedora Security Policies
if [ "${OS_FAMILY}" = "rhel" ]; then
    log_info "Configuring RHEL/Rocky Security Policies (SELinux & Firewalld)..."

    # SELinux Booleans and Container Contexts
    if command -v getenforce >/dev/null 2>&1; then
        SELINUX_MODE=$(getenforce 2>/dev/null || echo "Disabled")
        if [ "${SELINUX_MODE}" != "Disabled" ]; then
            log_info "Applying SELinux container booleans (container_manage_cgroup, container_use_devices)..."
            setsebool -P container_manage_cgroup 1 2>/dev/null || true
            setsebool -P container_use_devices 1 2>/dev/null || true

            # Apply container storage contexts to mounted volumes
            for vol_dir in "${INSTALL_DIR}/configs" "${INSTALL_DIR}/data" "${INSTALL_DIR}/certs"; do
                if [ -d "${vol_dir}" ]; then
                    chcon -Rt container_file_t "${vol_dir}" 2>/dev/null || true
                fi
            done
        else
            log_info "SELinux is Disabled. Skipping boolean configuration."
        fi
    fi

    # Firewalld Configuration
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        log_info "Configuring Firewalld ports and service definition..."
        FIREWALLD_SVC_DIR="/etc/firewalld/services"
        if [ -d "${FIREWALLD_SVC_DIR}" ] && [ -f "${REPO_ROOT}/configs/firewalld/opensoc-forge.xml" ]; then
            cp -f "${REPO_ROOT}/configs/firewalld/opensoc-forge.xml" "${FIREWALLD_SVC_DIR}/opensoc-forge.xml"
            chmod 644 "${FIREWALLD_SVC_DIR}/opensoc-forge.xml"
            firewall-cmd --permanent --add-service=opensoc-forge 2>/dev/null || true
        fi

        # Ensure explicit port fallback
        firewall-cmd --permanent --add-port=8000/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=7070/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=5601/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=9200/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=1514/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=1514/udp 2>/dev/null || true
        firewall-cmd --permanent --add-port=1515/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=55000/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=514/udp 2>/dev/null || true
        firewall-cmd --permanent --add-port=514/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=6514/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_info "Firewalld policies reloaded successfully."
    fi
fi

# 3. Configure Debian / Kali / Ubuntu Security Policies
if [ "${OS_FAMILY}" = "debian" ]; then
    log_info "Configuring Debian/Kali Security Policies (Capabilities & UFW)..."

    # Packet Capture Capabilities
    if command -v setcap >/dev/null 2>&1; then
        log_info "Configuring packet capture capabilities (cap_net_raw,cap_net_admin+eip)..."
        # If native suricata or sniffing binaries exist on host, apply capabilities
        for bin_target in /usr/bin/suricata /usr/sbin/tcpdump; do
            if [ -f "${bin_target}" ]; then
                setcap cap_net_raw,cap_net_admin+eip "${bin_target}" 2>/dev/null || true
            fi
        done
    fi

    # UFW Port Configuration
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw "active"; then
        log_info "Configuring UFW allowed ports for OpenSOC Forge..."
        ufw allow 8000/tcp comment "OpenSOC Forge Web Console & API" 2>/dev/null || true
        ufw allow 7070/tcp comment "OpenSOC Forge Web Console & API" 2>/dev/null || true
        ufw allow 5601/tcp comment "OpenSOC Forge Kibana" 2>/dev/null || true
        ufw allow 9200/tcp comment "OpenSOC Forge Elasticsearch" 2>/dev/null || true
        ufw allow 1514/tcp comment "OpenSOC Forge Wazuh Events TCP" 2>/dev/null || true
        ufw allow 1514/udp comment "OpenSOC Forge Wazuh Events UDP" 2>/dev/null || true
        ufw allow 1515/tcp comment "OpenSOC Forge Wazuh Registration" 2>/dev/null || true
        ufw allow 55000/tcp comment "OpenSOC Forge Wazuh API" 2>/dev/null || true
        ufw allow 514/udp comment "OpenSOC Forge Syslog UDP" 2>/dev/null || true
        ufw allow 514/tcp comment "OpenSOC Forge Syslog TCP" 2>/dev/null || true
        ufw allow 6514/tcp comment "OpenSOC Forge Syslog TLS" 2>/dev/null || true
        log_info "UFW rules applied successfully."
    fi
fi

# 4. Network Sniffing & Promiscuous Mode Alignment
ACTIVE_IFACE=$(ip -o link show up 2>/dev/null | awk -F': ' '$2 != "lo" {print $2; exit}' || echo "")
if [ -n "${ACTIVE_IFACE}" ]; then
    log_info "Enabling promiscuous mode on active network interface: ${ACTIVE_IFACE}"
    ip link set dev "${ACTIVE_IFACE}" promisc on 2>/dev/null || true
fi

log_info "Security and network policies configured successfully."
