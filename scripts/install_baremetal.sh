#!/usr/bin/env bash
# ==============================================================================
# OpenSOC Forge - 1-Click Native Bare-Metal Installer (No Docker Required)
# Supported platforms: RHEL 9 / 10, Rocky Linux 9, AlmaLinux 9, Debian / Ubuntu
# Provisions Elasticsearch, Wazuh Manager, Kibana, Rsyslog, and OpenSOC Forge API
# directly on the Host OS managed by native systemd.
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $(date +'%Y-%m-%d %H:%M:%S') - $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}   $(date +'%Y-%m-%d %H:%M:%S') - $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $(date +'%Y-%m-%d %H:%M:%S') - $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date +'%Y-%m-%d %H:%M:%S') - $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be executed as root. Please run with: sudo $0"
    exit 1
fi

INSTALL_DIR="${INSTALL_DIR:-/opt/opensoc-forge}"
HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo -e "${BLUE}"
echo "================================================================================"
echo "    OpenSOC Forge — Native Bare-Metal (Non-Docker) Systemd Provisioner          "
echo "================================================================================"
echo -e "${NC}"

# 1. OS Classification
log_info "Detecting operating system family..."
. /etc/os-release
OS_ID="${ID:-}"
OS_LIKE="${ID_LIKE:-}"

OS_FAMILY="unsupported"
if [[ "${OS_ID}" =~ ^(kali|debian|ubuntu)$ ]] || [[ "${OS_LIKE}" =~ debian ]]; then
    OS_FAMILY="debian"
elif [[ "${OS_ID}" =~ ^(rhel|rocky|almalinux|fedora|centos)$ ]] || [[ "${OS_LIKE}" =~ (rhel|fedora|centos) ]]; then
    OS_FAMILY="rhel"
fi

if [ "${OS_FAMILY}" = "unsupported" ]; then
    log_error "Unsupported OS: ${PRETTY_NAME:-$NAME}."
    exit 1
fi
log_ok "OS Classified: ${OS_FAMILY} (${PRETTY_NAME:-$NAME})"

# 2. Kernel Tuning
log_info "Configuring kernel sysctl parameters..."
tee /etc/sysctl.d/99-opensoc-forge.conf >/dev/null <<EOF
vm.max_map_count=262144
fs.file-max=65536
net.core.somaxconn=1024
EOF
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-opensoc-forge.conf >/dev/null 2>&1 || true
log_ok "Kernel parameters applied (vm.max_map_count=262144)."

# 3. Firewalld / Port Configuration
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    log_info "Configuring Firewalld port policies..."
    for p in 8000/tcp 5601/tcp 9200/tcp 1514/tcp 1514/udp 1515/tcp 55000/tcp 514/udp 514/tcp 6514/tcp; do
        firewall-cmd --permanent --add-port="${p}" >/dev/null 2>&1 || true
    done
    firewall-cmd --reload >/dev/null 2>&1 || true
    log_ok "Firewalld ports authorized."
fi

# 4. Elasticsearch Installation (7.17.x Native)
log_info "Installing Elasticsearch on Host OS..."
if [ "${OS_FAMILY}" = "rhel" ]; then
    rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch 2>/dev/null || true
    tee /etc/yum.repos.d/elasticsearch.repo >/dev/null <<EOF
[elasticsearch]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
    dnf install -y elasticsearch-7.17.24 || dnf install -y elasticsearch
elif [ "${OS_FAMILY}" = "debian" ]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg --yes 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list >/dev/null
    apt-get update -y
    apt-get install -y elasticsearch=7.17.24 || apt-get install -y elasticsearch
fi

# Configure Elasticsearch
tee /etc/elasticsearch/elasticsearch.yml >/dev/null <<EOF
cluster.name: opensoc-cluster
node.name: opensoc-node-01
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
EOF

mkdir -p /etc/elasticsearch/jvm.options.d
tee /etc/elasticsearch/jvm.options.d/heap.options >/dev/null <<EOF
-Xms2g
-Xmx2g
EOF

systemctl daemon-reload
systemctl enable --now elasticsearch
log_ok "Elasticsearch installed and active on port 9200."

# 5. Wazuh Manager Installation
log_info "Installing Wazuh Manager..."
if [ "${OS_FAMILY}" = "rhel" ]; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 2>/dev/null || true
    tee /etc/yum.repos.d/wazuh.repo >/dev/null <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    dnf install -y wazuh-manager
elif [ "${OS_FAMILY}" = "debian" ]; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null || true
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list >/dev/null
    apt-get update -y
    apt-get install -y wazuh-manager
fi

systemctl daemon-reload
systemctl enable --now wazuh-manager
log_ok "Wazuh Manager installed and active (ports 1514, 1515, 55000)."

# 6. Kibana Installation
log_info "Installing Kibana Analytics UI..."
if [ "${OS_FAMILY}" = "rhel" ]; then
    dnf install -y kibana-7.17.24 || dnf install -y kibana
elif [ "${OS_FAMILY}" = "debian" ]; then
    apt-get install -y kibana=7.17.24 || apt-get install -y kibana
fi

tee /etc/kibana/kibana.yml >/dev/null <<EOF
server.port: 5601
server.host: "0.0.0.0"
server.name: "opensoc-kibana"
elasticsearch.hosts: ["http://127.0.0.1:9200"]
EOF

systemctl daemon-reload
systemctl enable --now kibana
log_ok "Kibana installed and active on port 5601."

# 7. Native Rsyslog for Cisco FMC and Network Log Ingestion (Port 514)
log_info "Configuring Native Rsyslog on Port 514 (UDP & TCP)..."
if [ "${OS_FAMILY}" = "rhel" ]; then
    dnf install -y rsyslog
elif [ "${OS_FAMILY}" = "debian" ]; then
    apt-get install -y rsyslog
fi

mkdir -p /var/log/remote
tee /etc/rsyslog.d/10-opensoc-syslog.conf >/dev/null <<EOF
module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")

\$template RemoteLogs,"/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log"
*.* ?RemoteLogs
EOF

systemctl daemon-reload
systemctl enable --now rsyslog
log_ok "Rsyslog active on port 514 (UDP and TCP)."

# 8. OpenSOC Forge Management Console & API (Python Service)
log_info "Provisioning OpenSOC Forge Management Plane..."
if [ "${OS_FAMILY}" = "rhel" ]; then
    dnf install -y python3 python3-pip
elif [ "${OS_FAMILY}" = "debian" ]; then
    apt-get install -y python3 python3-pip
fi

pip3 install --upgrade pip fastapi uvicorn pyyaml jsonschema httpx cryptography >/dev/null 2>&1 || true

tee /etc/systemd/system/opensoc-forge.service >/dev/null <<EOF
[Unit]
Description=OpenSOC Forge Central Management Plane & UI
After=network.target elasticsearch.service wazuh-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PORT=8000"
Environment="ELASTICSEARCH_URL=http://127.0.0.1:9200"
ExecStart=/usr/local/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now opensoc-forge.service
log_ok "OpenSOC Forge Management UI active on http://${HOST_IP}:8000/console/."

echo -e "${GREEN}"
echo "================================================================================"
echo " [SUCCESS] OpenSOC Forge Native Bare-Metal Deployment Succeeded!"
echo "================================================================================"
echo -e "${NC}"
echo " Access Information:"
echo "   - Web Console UI   : http://${HOST_IP}:8000/console/"
echo "   - Kibana Dashboard : http://${HOST_IP}:5601"
echo "   - Elasticsearch    : http://${HOST_IP}:9200"
echo "   - Wazuh Manager    : ports 1514 (events), 1515 (enrollment), 55000 (api)"
echo "   - Syslog Collector : ports 514 (UDP & TCP native rsyslog)"
echo "================================================================================"
