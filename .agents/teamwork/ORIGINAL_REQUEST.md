# Original User Request

## 2026-10-14T17:16:28Z

Build OpenSOC Forge 1-Click Universal Linux Systemd Service Package: an all-in-one containerized SIEM/SOC platform (OpenSOC Forge Web Console & API, Elasticsearch, Kibana, Wazuh Manager, Suricata NIDS) that installs with a single command (`./install.sh`) and runs as an automated `systemd` system service across Kali Linux and Red Hat Enterprise Linux 9 / Rocky Linux.

Working directory: `c:\Users\USER\Documents\SIEM`
Integrity mode: demo

## Requirements

### R1. Universal 1-Click Linux Installer Script (`install.sh`)
Create an idempotent, automated installation and provisioning script (`install.sh`) that:
- Inspects `/etc/os-release` to detect OS family (Kali Linux, Debian, Ubuntu, RHEL 9, Rocky Linux 9, AlmaLinux, Fedora).
- Validates system hardware preflight checks (RAM >= 8GB, CPU >= 4 cores, Disk >= 30GB, network interface state).
- Configures necessary kernel parameters (e.g. `sysctl -w vm.max_map_count=262144` for Elasticsearch).
- Automatically installs or verifies container engine availability (Podman / Docker + Compose plugin) across both APT and DNF/RPM package managers.
- Deploys all services without interactive prompts or manual intervention.

### R2. All-in-One Containerized Multi-Service Data Plane
Package the full security operations topology into a production-hardened compose definition (`docker-compose.yml` / `podman-compose.yml`) containing:
1. `opensoc-forge-mgmt`: FastAPI Management API and pre-compiled Web Console UI (port 8000).
2. `elasticsearch`: Single-node search & telemetry datastore with TLS enabled (port 9200).
3. `kibana`: Visual data analytics frontend (port 5601).
4. `wazuh-manager`: Endpoint detection, file integrity monitoring (FIM), and SCA engine (ports 1514, 1515, 55000).
5. `suricata`: Network intrusion detection engine running in host networking mode with AF_PACKET packet capture.
6. `syslog-collector`: RFC 5424/3164 log receiver (ports 514/udp, 6514/tcp TLS).

### R3. Automated Native Systemd Service Integration
Create systemd unit file templates (`systemd/opensoc-forge.service`) enabling full system service management:
- Enable on boot: `systemctl enable opensoc-forge.service`.
- Unified lifecycle controls: `systemctl start|stop|restart|status opensoc-forge`.
- Automated recovery (`Restart=on-failure`, `TimeoutStartSec=300`).
- Unified operational log viewing: `journalctl -u opensoc-forge -f`.

### R4. Cross-Distribution Network & Security Policy Alignment
- On Kali Linux / Debian: ensure packet capture permissions (`setcap cap_net_raw,cap_net_admin+eip`) for network telemetry.
- On Red Hat 9 / Rocky Linux 9: automatically configure `firewalld` ports (8000, 5601, 9200, 1514, 514) and SELinux booleans (e.g., `container_manage_cgroup`).

### R5. Self-Contained CLI Wrapper Tool (`opensoc-ctl`)
Provide a unified management CLI (`bin/opensoc-ctl`):
- `opensoc-ctl status`: Displays health of all containers, ports, and data pipelines.
- `opensoc-ctl logs [service]`: Tail logs of individual components.
- `opensoc-ctl backup`: Exports Elasticsearch snapshots, Wazuh configurations, and platform metadata.
- `opensoc-ctl test`: Injects synthetic events to verify end-to-end detection pipeline.

## Acceptance Criteria

### Automated Cross-Platform Installation
- [ ] Executing `sudo ./install.sh` on clean Kali Linux 2024+ installs prerequisites and starts the entire platform without manual prompts.
- [ ] Executing `sudo ./install.sh` on clean Red Hat Enterprise Linux 9 / Rocky Linux 9 installs prerequisites and starts the entire platform without manual prompts.
- [ ] `systemctl is-active opensoc-forge` returns `active`.

### Service & Pipeline Health
- [ ] Navigating to `http://<HOST_IP>:8000/console/` displays the OpenSOC Forge Web Console with all operational screens and Enterprise Simulation tabs.
- [ ] `curl -k https://localhost:9200/_cluster/health` returns status `green` or `yellow`.
- [ ] Wazuh manager API (`https://localhost:55000`) and Suricata EVE log stream are active and indexed.
- [ ] `opensoc-ctl test` generates a synthetic alert that successfully renders in the Web Console within 5 seconds.
