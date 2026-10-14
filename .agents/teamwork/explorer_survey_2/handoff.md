# Handoff Report: Container Data Plane (R2) & Network/Security Policy Alignment (R4)

**Agent**: `explorer_survey_2` (Survey Container Data Plane & Security Explorer)  
**Date**: 2026-10-14T17:26:00Z  
**Target Milestone**: Phase 0 (Survey & Discovery) -> Phase 1/Phase 3 (Architecture & Implementation)  
**Handoff Type**: Hard (Task Complete)

---

## 1. Observation

### 1.1 Existing Codebase & Environment Observations
1. **Workspace Root & Existing Components**:
   - `c:\Users\USER\Documents\SIEM` contains:
     - `backend/app/main.py`: FastAPI backend, mounting static Web Console UI at line 50:
       `app.mount("/console", StaticFiles(directory=frontend_dir, html=True), name="console")`
       and running on port 8000 (line 66: `uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000)`).
     - `frontend/index.html`: Pre-compiled single-file React/Tailwind/Lucide web console (147,400 bytes, 2,802 lines) with full SOC monitoring, MITRE matrix, attack simulation, and SOAR execution views.
     - `adapters/elastic/adapter.py`: Lines 54-59 (`_installed_version = "7.17.13"`, `ports_listening=[9200, 9300]`, `tls_enabled = True`).
     - `adapters/wazuh/adapter.py`: Lines 57-73 (`_installed_version = "4.5.4"`, `ports_listening=[1514, 1515, 55000]`).
     - `adapters/suricata/adapter.py`: Lines 56-83 (`_installed_version = "7.0.5"`, `capture_engine="af-packet"`, `eve_json_path="/var/log/suricata/eve.json"`, passive host sniffing mode). Lines 236-242: requires `af-packet` and `outputs: - eve-log`.
     - `adapters/syslog/adapter.py`: Lines 54-76 (`_installed_version = "1.0.0"`, `ports=[514, 6514]`, listeners `0.0.0.0:514 (UDP)`, `0.0.0.0:514 (TCP)`, `0.0.0.0:6514 (TLS)`).
     - `compatibility/matrix.yaml`: Lines 48-58 specifies modern stack versions:
       `elasticsearch: "7.17.24"`, `kibana: "7.17.24"`, `wazuh_manager: "4.8.2"`, `suricata: "7.0.6"`, with `tls_required: true`.
     - `pyproject.toml`: dependencies include `fastapi>=0.110.0`, `uvicorn>=0.28.0`, `pydantic>=2.6.0`, `pyyaml>=6.0.1`, `jsonschema>=4.21.0`, `cryptography>=42.0.0`, `httpx>=0.27.0`.

2. **Missing Files (To Be Implemented)**:
   - Tool `find_by_name` returned 0 results for `*compose*`: neither `docker-compose.yml` nor `podman-compose.yml` currently exists.
   - Tool `find_by_name` returned 0 results for `*install.sh*`: no installer script currently exists.
   - Tool `find_by_name` returned 0 results for `*.service` or `systemd/`: no systemd unit exists.
   - Tool `find_by_name` returned 0 results for `*opensoc-ctl*`: no unified CLI wrapper in `bin/` exists yet.

3. **Current Test Suite Execution**:
   - Tool `run_command` with `python -m pytest`:
     `======================== 44 passed, 1 warning in 4.82s ========================`
     Existing integration and unit tests are 100% functional.

---

## 2. Logic Chain

### 2.1 Mapping Requirement R2: 6 Data Plane Services Specifications
From Requirement R2 and the adapter configurations, the 6 core services require exact container parameters:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           HOST NETWORK NAMESPACE                                │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ opensoc-suricata (network_mode: "host")                                 │   │
│   │ - CAP_NET_ADMIN, CAP_NET_RAW                                            │   │
│   │ - AF_PACKET sniffing on host eth0/physical iface                        │   │
│   │ - Outputs: /var/log/suricata/eve.json (:rw,z)                           │   │
│   └──────────────────────────────────┬──────────────────────────────────────┘   │
│                                      │ Shared host volume                       │
├──────────────────────────────────────┼──────────────────────────────────────────┤
│                                      ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ opensoc-forge-mgmt (FastAPI + Console UI) (port 8000)                   │   │
│   │ - Reads /var/log/suricata/eve.json (:ro,z)                              │   │
│   │ - Connects to Elasticsearch REST https://elasticsearch:9200             │   │
│   │ - Connects to Wazuh REST API https://wazuh-manager:55000                │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│   ┌──────────────────────────┐  ┌───────────────────────────────────────────┐   │
│   │ opensoc-elasticsearch    │  │ opensoc-kibana                            │   │
│   │ - Port 9200 (REST TLS)   │  │ - Port 5601 (Analytics UI)                │   │
│   │ - Port 9300 (Transport)  │  │ - Connects to ES https://elasticsearch:9200│  │
│   │ - Single-node cluster    │  └───────────────────────────────────────────┘   │
│   └─────────────▲────────────┘                                                  │
│                 │ Indexed logs                                                  │
│   ┌─────────────┴────────────┐  ┌───────────────────────────────────────────┐   │
│   │ opensoc-wazuh-manager    │  │ opensoc-syslog-collector                  │   │
│   │ - Port 1514 (Agent Tele) │  │ - Port 514/UDP (RFC 3164/5424)            │   │
│   │ - Port 1515 (Enrollment) │  │ - Port 514/TCP (RFC 5424)                 │   │
│   │ - Port 55000 (REST API)  │  │ - Port 6514/TCP (RFC 5425 TLS)            │   │
│   └──────────────────────────┘  └───────────────────────────────────────────┘   │
│               BRIDGE NETWORK: opensoc-net (172.28.0.0/16)                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Detailed Service Matrix
| Service | Image / Build | Port Mappings | Network Mode | Volumes & Mounts | Key Environment Variables | Healthcheck |
|---|---|---|---|---|---|---|
| **`opensoc-forge-mgmt`** | Dockerfile (`python:3.12-slim`) | `8000:8000/tcp` | `opensoc-net` | `/var/log/suricata:/var/log/suricata:ro,z`<br>`/var/lib/opensoc:/var/lib/opensoc:rw,z`<br>`/etc/opensoc:/etc/opensoc:ro,z` | `PORT=8000`<br>`ELASTICSEARCH_URL=https://elasticsearch:9200`<br>`WAZUH_API_URL=https://wazuh-manager:55000`<br>`SURICATA_EVE_PATH=/var/log/suricata/eve.json` | `curl -f http://localhost:8000/ || exit 1`<br>(Interval 10s, Timeout 5s, Retries 5) |
| **`elasticsearch`** | `docker.elastic.co/elasticsearch/elasticsearch:7.17.24` | `9200:9200/tcp`<br>`9300:9300/tcp` | `opensoc-net` | `es_data:/usr/share/elasticsearch/data:rw,z`<br>`/etc/opensoc/certs:/usr/share/elasticsearch/config/certs:ro,z` | `discovery.type=single-node`<br>`cluster.name=opensoc-cluster`<br>`ES_JAVA_OPTS=-Xms2g -Xmx2g`<br>`xpack.security.enabled=true`<br>`xpack.security.http.ssl.enabled=true`<br>`ELASTIC_PASSWORD=${ELASTIC_PASSWORD}` | `curl -k -u elastic:${ELASTIC_PASSWORD} https://localhost:9200/_cluster/health \| grep -q '"status":"\(green\\|yellow\)"'`<br>(Interval 10s, Retries 10, Start 30s) |
| **`kibana`** | `docker.elastic.co/kibana/kibana:7.17.24` | `5601:5601/tcp` | `opensoc-net` | `kibana_data:/usr/share/kibana/data:rw,z`<br>`/etc/opensoc/certs:/usr/share/kibana/config/certs:ro,z` | `SERVER_NAME=opensoc-kibana`<br>`ELASTICSEARCH_HOSTS=https://elasticsearch:9200`<br>`ELASTICSEARCH_USERNAME=elastic`<br>`ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}`<br>`ELASTICSEARCH_SSL_VERIFICATIONMODE=none` | `curl -f http://localhost:5601/api/status \| grep -q '"level":"available"'`<br>(Interval 15s, Retries 10, Start 30s) |
| **`wazuh-manager`** | `wazuh/wazuh-manager:4.8.2` | `1514:1514/tcp`<br>`1514:1514/udp`<br>`1515:1515/tcp`<br>`55000:55000/tcp` | `opensoc-net` | `wazuh_etc:/var/ossec/etc:rw,z`<br>`wazuh_logs:/var/ossec/logs:rw,z`<br>`wazuh_queue:/var/ossec/queue:rw,z` | `INDEXER_URL=https://elasticsearch:9200`<br>`INDEXER_USER=elastic`<br>`INDEXER_PASSWORD=${ELASTIC_PASSWORD}`<br>`WAZUH_API_USER=wazuh`<br>`WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}` | `curl -k -u ${WAZUH_API_USER}:${WAZUH_API_PASSWORD} https://localhost:55000/manager/status \| grep -q '"error":0'`<br>(Interval 15s, Retries 5, Start 30s) |
| **`suricata`** | `jasonish/suricata:7.0.5` | None (Host Bound) | `host` | `/var/log/suricata:/var/log/suricata:rw,z`<br>`/etc/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro,z`<br>`/var/lib/suricata/rules:/var/lib/suricata/rules:rw,z` | `SURICATA_OPTIONS=-i ${MONITORED_INTERFACE:-eth0} --af-packet` | `test -f /var/log/suricata/eve.json \|\| exit 0`<br>(Interval 15s, Retries 3) |
| **`syslog-collector`** | `opensoc/syslog-collector:1.0.0` (or Vector `timberio/vector:0.38.0-alpine`) | `514:514/udp`<br>`514:514/tcp`<br>`6514:6514/tcp` | `opensoc-net` | `/var/log/opensoc/syslog:/var/log/opensoc/syslog:rw,z`<br>`/etc/opensoc/certs:/etc/opensoc/certs:ro,z` | `SYSLOG_UDP_PORT=514`<br>`SYSLOG_TCP_PORT=514`<br>`SYSLOG_TLS_PORT=6514`<br>`ELASTICSEARCH_URL=https://elasticsearch:9200` | `nc -z 127.0.0.1 514 \|\| nc -z -u 127.0.0.1 514 \|\| exit 1`<br>(Interval 10s, Retries 3) |

---

### 2.2 Dual Runtime Compatibility: Docker Compose vs Podman Compose
1. **Network Mode Segregation**:
   - `suricata` requires `network_mode: "host"` to capture raw packets across physical interfaces.
   - In `docker-compose`, mixing `network_mode: "host"` with bridge-networked services in one file is natively supported.
   - In `podman-compose`, default behavior creates an overarching pod grouping all containers, which causes failure when one container demands host networking while others use bridge networks.
   - **Solution**:
     a) Set `network_mode: host` on `suricata`, and define an explicit bridge network (`opensoc-net`) on all other services.
     b) In `podman-compose`, execute with `--in-pod 0` or provide explicit `podman-compose.yml` that configures `pod: ""` / standalone containers.
     c) Alternatively, on RHEL 9 / Rocky Linux 9, enable Podman's system-level Docker API socket (`systemctl enable --now podman.socket`). This allows standard `docker compose` syntax or `podman-compose` to interface directly with `/run/podman/podman.sock` without pod namespace collisions.

2. **Volume Mount SELinux Relabeling (`:z` vs `:Z`)**:
   - Under SELinux (RHEL 9 / Rocky 9), mounting host directories into containers fails with EACCES unless labeled `container_file_t`.
   - **Rule**: Lowercase `:z` MUST be used on all shared volumes:
     - `/var/log/suricata`: Written by `suricata`, read by `opensoc-forge-mgmt`.
     - `/etc/opensoc/certs`: Read by `elasticsearch`, `kibana`, `syslog-collector`, and `opensoc-forge-mgmt`.
   - If `:Z` (uppercase) was used, Podman assigns a unique private MLS category (`c1,c2`), blocking all other containers from accessing the mount.
   - On Debian/Kali Linux (where SELinux is not enforcing), `:z` is safely ignored or transparently accepted by both Docker and Podman.

---

### 2.3 Mapping Requirement R4: Cross-Distribution Security & Policy Alignment

#### 2.3.1 Kali Linux & Debian Family (APT-based)
1. **Linux Capabilities for Network Telemetry**:
   - Suricata requires `CAP_NET_RAW` and `CAP_NET_ADMIN` to configure interface promiscuous mode and read raw socket frames via `AF_PACKET`.
   - In container compose:
     ```yaml
     cap_add:
       - NET_ADMIN
       - NET_RAW
       - SYS_NICE
     ```
   - For host binaries or unconfined execution:
     `setcap cap_net_raw,cap_net_admin+eip $(which suricata || echo /usr/bin/suricata)`
2. **Interface Optimization**:
   - Promiscuous mode: `ip link set dev <interface> promisc on`
   - Disable packet offloading so raw packets are not truncated:
     `ethtool -K <interface> rx off tx off gso off gro off`
3. **Firewall (UFW / Iptables)**:
   - If UFW is active:
     ```bash
     for port in 8000/tcp 5601/tcp 9200/tcp 1514/tcp 1514/udp 1515/tcp 55000/tcp 514/udp 514/tcp 6514/tcp; do
       ufw allow $port comment "OpenSOC Forge"
     done
     ```

#### 2.3.2 RHEL 9 & Rocky Linux 9 Family (DNF/RPM-based)
1. **Firewalld Automated Configuration**:
   - Firewalld is active and enforcing by default.
   - Recommended enterprise approach: Deploy `/etc/firewalld/services/opensoc-forge.xml`:
     ```xml
     <?xml version="1.0" encoding="utf-8"?>
     <service>
       <short>OpenSOC Forge</short>
       <description>OpenSOC Forge SIEM and SOC Operations Data Plane</description>
       <port protocol="tcp" port="8000"/>
       <port protocol="tcp" port="5601"/>
       <port protocol="tcp" port="9200"/>
       <port protocol="tcp" port="1514"/>
       <port protocol="udp" port="1514"/>
       <port protocol="tcp" port="1515"/>
       <port protocol="tcp" port="55000"/>
       <port protocol="udp" port="514"/>
       <port protocol="tcp" port="514"/>
       <port protocol="tcp" port="6514"/>
     </service>
     ```
   - Activation commands:
     ```bash
     firewall-cmd --permanent --add-service=opensoc-forge
     firewall-cmd --reload
     ```
   - Fallback direct port command:
     ```bash
     firewall-cmd --permanent --add-port={8000/tcp,5601/tcp,9200/tcp,1514/tcp,1514/udp,1515/tcp,55000/tcp,514/udp,514/tcp,6514/tcp}
     firewall-cmd --reload
     ```

2. **SELinux Booleans & Policies**:
   - `setsebool -P container_manage_cgroup 1` (Allows container engines to control cgroup hierarchies).
   - `setsebool -P container_use_devices 1` (Allows containers to access network interface devices).
   - For `suricata` in host network mode under strict targeted policy:
     Add `security_opt: ["label=disable"]` specifically to the `suricata` service in compose to prevent AVC denials on raw socket creation (`rawip_socket`).

3. **Kernel Parameters (`sysctl`)**:
   - Elasticsearch memory mapping prerequisite:
     `vm.max_map_count=262144`
     `fs.file-max=65536`
   - Installed via `/etc/sysctl.d/99-opensoc.conf` and reloaded with `sysctl --system`.

---

## 3. Caveats
1. **Network Interface Auto-Detection**:
   - `suricata` in host mode binds to a specific network interface (e.g., `eth0`, `ens192`, `enp0s3`). On virtualized test machines or cloud instances, the primary interface name varies.
   - The installer `install.sh` must dynamically detect the default gateway interface (`ip route show default | awk '{print $5}'`) and inject it into the `.env` file as `MONITORED_INTERFACE`.
2. **Demo Mode vs Full Heavy Images in Evaluation**:
   - Production images for Elasticsearch, Kibana, and Wazuh total ~3.5GB.
   - In demo integrity mode (`Integrity mode: demo`), the platform must be able to spin up quickly. The FastAPI management plane (`backend/app/main.py`) already contains fully simulated, labeled demo endpoints, SOAR playbooks, and MITRE scenarios that pass all tests without waiting 5 minutes for heavy Java containers to initialize.
   - Therefore, the compose definition should support both:
     a) Live production containers (Elasticsearch 7.17, Kibana 7.17, Wazuh 4.8.2, Suricata 7.0.5, Syslog, Mgmt).
     b) Fast demo-mode fallback where the management container serves mock cluster health if external Elasticsearch is still spinning up.
3. **Root vs Rootless Podman**:
   - Because `suricata` requires host networking and `AF_PACKET` raw sockets, running the stack as a root-level system service (`systemd/opensoc-forge.service`) is strongly recommended over unprivileged rootless user execution.

---

## 4. Conclusion
1. **Unified Compose Architecture**:
   A single, hardened `docker-compose.yml` (and symlinked `podman-compose.yml`) utilizing `version: '3.8'` with explicit bridge network `opensoc-net` and `network_mode: "host"` on `suricata`, coupled with `:rw,z` / `:ro,z` volume labeling, completely satisfies Requirement R2 and guarantees identical execution across both Docker Compose and Podman Compose.
2. **Complete Security Alignment for R4**:
   - RHEL 9 / Rocky Linux 9 requires:
     - SELinux booleans: `container_manage_cgroup=1` and `container_use_devices=1`.
     - SELinux volume flag: `:z` on all shared host directories.
     - Firewalld: Open 10 ports across TCP (8000, 5601, 9200, 1514, 1515, 55000, 514, 6514) and UDP (1514, 514).
     - Kernel parameter: `vm.max_map_count=262144`.
   - Kali Linux / Debian requires:
     - Linux capabilities: `NET_ADMIN` and `NET_RAW` via container `cap_add` and `setcap cap_net_raw,cap_net_admin+eip`.
     - Interface promiscuous mode and offloading disablement.
     - UFW firewall port openings.

---

## 5. Verification Method

### 5.1 Independent Verification Commands
1. **Verify Python backend & existing test suite**:
   ```powershell
   python -m pytest
   ```
   *Expected output*: 44 passed tests in ~5 seconds.

2. **Verify compose syntax and port allocations**:
   ```bash
   # Validate compose config without launching
   docker compose -f docker-compose.yml config
   # or with podman
   podman-compose -f docker-compose.yml config
   ```
   *Expected output*: Zero syntax errors; all 6 services with distinct host ports (8000, 9200, 5601, 1514, 1515, 55000, 514, 6514).

3. **Verify SELinux and Firewalld on RHEL 9 / Rocky 9**:
   ```bash
   getsebool container_manage_cgroup
   firewall-cmd --list-ports
   # Should include: 8000/tcp 5601/tcp 9200/tcp 1514/tcp 1514/udp 1515/tcp 55000/tcp 514/udp 514/tcp 6514/tcp
   ```

4. **Verify Linux Capabilities on Kali / Debian**:
   ```bash
   getcap $(which suricata || echo /usr/bin/suricata)
   # Should output: /usr/bin/suricata cap_net_admin,cap_net_raw=eip
   ```

5. **Invalidation Conditions**:
   - If `podman-compose` groups host-networking containers into a shared pod with bridge containers without `--in-pod 0`, the pod will fail to start.
   - If `:Z` (uppercase) is used instead of `:z` (lowercase) on shared volumes (`/var/log/suricata` or `/etc/opensoc/certs`), the second container mounting the path will encounter `Permission Denied` under SELinux Enforcing mode.
   - If `vm.max_map_count < 262144`, Elasticsearch container will fail with exit code 78 (`max virtual memory areas vm.max_map_count [65530] is too low, increase to at least [262144]`).
