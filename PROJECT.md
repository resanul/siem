# Project: OpenSOC Forge 1-Click Universal Linux Systemd Service Package

## Architecture
- **Platform Scope**: All-in-one containerized SIEM & SOC operations data plane deployed via a universal 1-click Linux installer (`install.sh`) and managed natively under `systemd` across Kali Linux / Debian and RHEL 9 / Rocky Linux 9.
- **Service Topology**:
  1. `opensoc-forge-mgmt`: FastAPI management API and standalone React 18 Web Console (port 8000).
  2. `elasticsearch`: Single-node search and telemetry datastore with TLS enabled (port 9200, 9300).
  3. `kibana`: Visual data analytics frontend (port 5601).
  4. `wazuh-manager`: Endpoint detection, FIM, and SCA engine (ports 1514, 1515, 55000).
  5. `suricata`: Network intrusion detection engine in host networking mode with AF_PACKET packet capture and EVE JSON logging.
  6. `syslog-collector`: RFC 5424/3164 log receiver (ports 514/udp, 514/tcp, 6514/tcp TLS).
- **Control Plane**:
  - `systemd/opensoc-forge.service`: Native system unit running `Type=simple` foreground container manager, providing auto-recovery (`Restart=on-failure`), boot auto-enable, and unified `journalctl` stream.
  - `bin/opensoc-ctl`: Unified management CLI (`status`, `logs [service]`, `backup`, `test`, `start-foreground`, `stop`, `restart`).
  - `install.sh`: Idempotent cross-distribution installer handling OS classification, hardware preflights, sysctl tuning, container engine provisioning, and security policy alignment.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | OS Family Detection | Parse `/etc/os-release` to support Kali, Debian, Ubuntu, RHEL 9, Rocky 9, AlmaLinux, Fedora | M2 | ORIGINAL_REQUEST §R1 |
| 2 | Hardware Preflight Checks | Validate RAM (>=8GB with 7600MB VM threshold), CPU (>=4 cores), Disk (>=30GB), network interface state | M2 | ORIGINAL_REQUEST §R1 |
| 3 | Kernel Parameter Tuning | Set `sysctl vm.max_map_count=262144` and persist in `/etc/sysctl.d/99-opensoc-forge.conf` | M2 | ORIGINAL_REQUEST §R1 |
| 4 | Container Engine Provisioning | Detect or install Docker Compose (APT) or Podman Compose (DNF) non-interactively | M2 | ORIGINAL_REQUEST §R1 |
| 5 | Non-Interactive Deployment | End-to-end hands-off installation to `/opt/opensoc-forge` without manual prompts | M2 | ORIGINAL_REQUEST §R1 |
| 6 | Management API & Console Container | Containerize FastAPI mgmt app and static Web Console on port 8000 | M1 | ORIGINAL_REQUEST §R2 |
| 7 | Elasticsearch Container | Single-node search datastore with TLS on port 9200/9300 | M1 | ORIGINAL_REQUEST §R2 |
| 8 | Kibana Container | Analytics frontend on port 5601 connecting to Elasticsearch over TLS | M1 | ORIGINAL_REQUEST §R2 |
| 9 | Wazuh Manager Container | Host intrusion & endpoint agent manager on ports 1514, 1515, 55000 | M1 | ORIGINAL_REQUEST §R2 |
| 10 | Suricata NIDS Container | Network intrusion detection in host networking mode with AF_PACKET packet capture | M1 | ORIGINAL_REQUEST §R2 |
| 11 | Syslog Collector Container | RFC 5424/3164 receiver on ports 514/udp, 514/tcp, 6514/tcp TLS | M1 | ORIGINAL_REQUEST §R2 |
| 12 | Hardened Compose Definition | Compose file with bridge network `opensoc-net`, volume mounts with `:z` SELinux labels | M1 | ORIGINAL_REQUEST §R2 |
| 13 | TLS Certificate Generation | TLS certificate setup for Elasticsearch and syslog in `scripts/generate_certs.sh` | M1 | ORIGINAL_REQUEST §R2 |
| 14 | Native Systemd Unit | Create `systemd/opensoc-forge.service` with `Type=simple` and `Restart=on-failure` | M3 | ORIGINAL_REQUEST §R3 |
| 15 | Systemd Lifecycle Controls | Enable unified `systemctl start\|stop\|restart\|status opensoc-forge` | M3 | ORIGINAL_REQUEST §R3 |
| 16 | Systemd Boot Auto-start | Enable service at system startup via `WantedBy=multi-user.target` | M3 | ORIGINAL_REQUEST §R3 |
| 17 | Unified Journalctl Logging | Direct container stdout/stderr to `journalctl -u opensoc-forge -f` | M3 | ORIGINAL_REQUEST §R3 |
| 18 | Kali/Debian Packet Capture Permissions | Configure `setcap cap_net_raw,cap_net_admin+eip` and container `cap_add` | M3 | ORIGINAL_REQUEST §R4 |
| 19 | RHEL 9 / Rocky 9 Firewalld Alignment | Configure firewalld ports (8000, 5601, 9200, 1514, 1515, 55000, 514, 6514) | M3 | ORIGINAL_REQUEST §R4 |
| 20 | RHEL 9 / Rocky 9 SELinux Alignment | Configure `setsebool -P container_manage_cgroup 1` and shared volume `:z` labels | M3 | ORIGINAL_REQUEST §R4 |
| 21 | Unified CLI Wrapper Entrypoint | Deploy executable `bin/opensoc-ctl` and symlink to `/usr/local/bin/opensoc-ctl` | M4 | ORIGINAL_REQUEST §R5 |
| 22 | CLI Status Command | `opensoc-ctl status` showing systemd, container, port, pipeline, and ES cluster health | M4 | ORIGINAL_REQUEST §R5 |
| 23 | CLI Logs Command | `opensoc-ctl logs [service]` tailing container logs or full service journal | M4 | ORIGINAL_REQUEST §R5 |
| 24 | CLI Backup Command | `opensoc-ctl backup` exporting snapshots, configs, and state with SHA-256 verification | M4 | ORIGINAL_REQUEST §R5 |
| 25 | CLI Test Command | `opensoc-ctl test` injecting synthetic event and verifying pipeline in < 5 seconds | M4 | ORIGINAL_REQUEST §R5 |
| 26 | Backend Synthetic Alert Injection | Update `POST /api/v1/synthetic-event` to inject `AlertItem` into `DEMO_ALERTS` | M4 | Survey Gap 1 |
| 27 | Frontend Web Console Live Polling | Update `frontend/index.html` React state with 2s polling on `/api/v1/alerts` | M4 | Survey Gap 2 |
| 28 | Cross-Platform Installer E2E Test | Validate installer script execution and preflight simulation | M-Final | Acceptance Criteria |
| 29 | Systemd Service State E2E Test | Validate `systemctl is-active opensoc-forge` returns `active` | M-Final | Acceptance Criteria |
| 30 | Web Console Display E2E Test | Validate `http://<HOST_IP>:8000/console/` renders all screens and simulation tabs | M-Final | Acceptance Criteria |
| 31 | Elasticsearch Cluster Health E2E Test | Validate `/_cluster/health` returns status `green` or `yellow` | M-Final | Acceptance Criteria |
| 32 | Wazuh & Suricata Health E2E Test | Validate Wazuh API port 55000 and Suricata EVE log indexing | M-Final | Acceptance Criteria |
| 33 | Synthetic Alert E2E Verification | Validate `opensoc-ctl test` renders synthetic alert in Web Console in <= 5s | M-Final | Acceptance Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Multi-Service Container Data Plane | Dockerfile, docker-compose.yml, container configs, healthchecks, TLS cert generator | None | DONE |
| M2 | Universal 1-Click Installer | install.sh, OS detection, hardware preflights, sysctl tuning, container engine setup | M1 | DONE |
| M3 | Native Systemd Service & Policy Alignment | systemd/opensoc-forge.service, firewalld XML/ports, SELinux booleans, setcap | M1, M2 | DONE |
| M4 | Management CLI Wrapper & Pipeline Integration | bin/opensoc-ctl, backend synthetic alert injection, frontend live alert polling | M1, M2, M3 | DONE |
| M-Final | E2E Test Pass & Adversarial Hardening | Pass 100% E2E tests (Tiers 1-4), Tier 5 adversarial testing, Forensic Integrity Audit | M1, M2, M3, M4, Test Track | DONE |

## Interface Contracts
### `install.sh` ↔ `systemd/opensoc-forge.service`
- `install.sh` copies `systemd/opensoc-forge.service` to `/etc/systemd/system/opensoc-forge.service`.
- `install.sh` executes `systemctl daemon-reload && systemctl enable --now opensoc-forge.service`.
- Pre-requisites: Kernel parameter `vm.max_map_count=262144` applied; container engine daemon/socket running.

### `systemd/opensoc-forge.service` ↔ `bin/opensoc-ctl`
- `ExecStartPre=-/usr/local/bin/opensoc-ctl prestart`
- `ExecStart=/usr/local/bin/opensoc-ctl start-foreground`
- `ExecStop=/usr/local/bin/opensoc-ctl stop`
- `ExecReload=/usr/local/bin/opensoc-ctl restart`
- Exit Code: 0 on clean exit, non-zero on failure triggering `Restart=on-failure`.

### `bin/opensoc-ctl` ↔ `opensoc-forge-mgmt` (FastAPI)
- `opensoc-ctl status`: queries `http://127.0.0.1:8000/` and `http://127.0.0.1:8000/api/v1/overview`.
- `opensoc-ctl test`: `POST http://127.0.0.1:8000/api/v1/synthetic-event` with payload `{"event_type": "test_alert", "target_component": "suricata"}`.
- Response payload must include `synthetic_event_id` and test stages.
- Subsequent `GET http://127.0.0.1:8000/api/v1/alerts` must return the synthetic alert in the alerts array.

### `opensoc-forge-mgmt` ↔ `frontend/index.html` (Web Console)
- Web Console UI served statically from `http://<HOST_IP>:8000/console/`.
- Frontend React component polls `GET /api/v1/alerts` every 2000ms.
- Render latency from synthetic event injection to DOM update is <= 5000ms.

## Code Layout
```
c:\Users\USER\Documents\SIEM\
├── install.sh                                # Universal 1-click Linux installer
├── Dockerfile                                # Container definition for opensoc-forge-mgmt
├── docker-compose.yml                        # Production multi-service compose file
├── podman-compose.yml                        # Symlink or compatible compose for Podman
├── .env.example                              # Template environment variables
├── systemd/
│   └── opensoc-forge.service                 # Native systemd service unit template
├── bin/
│   └── opensoc-ctl                           # Unified management CLI wrapper
├── scripts/
│   ├── generate_certs.sh                     # TLS certificate generation utility
│   ├── configure_security_policies.sh        # Firewalld, SELinux, and setcap configurator
│   └── opensoc_cli.py                        # Existing Python management operations
├── configs/
│   ├── firewalld/
│   │   └── opensoc-forge.xml                 # Enterprise firewalld service definition
│   ├── sysctl/
│   │   └── 99-opensoc-forge.conf             # Kernel optimizations configuration
│   ├── elasticsearch/                        # ES configuration and TLS setup
│   ├── suricata/                             # Suricata configuration and rules
│   └── syslog/                               # Syslog receiver configuration
├── backend/                                  # FastAPI management backend
│   └── app/
│       ├── main.py                           # Application entrypoint & static mount
│       └── api/v1/api.py                     # API endpoints (including synthetic event)
├── frontend/
│   └── index.html                            # React 18 standalone Web Console UI
├── tests/
│   ├── unit/                                 # Unit tests
│   ├── integration/                          # Integration tests
│   └── e2e/                                  # Dual-track E2E test suites (Tiers 1-5)
│       ├── test_tier1_feature_coverage.py
│       ├── test_tier2_boundary_corner.py
│       ├── test_tier3_cross_feature.py
│       ├── test_tier4_real_world.py
│       └── e2e_test_runner.py                # Standalone E2E test harness
└── .agents/teamwork/                         # Agent coordination and metadata
```
