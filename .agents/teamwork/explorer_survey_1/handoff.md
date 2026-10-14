# Handoff Report: Survey of Codebase & Assets for 1-Click Universal Linux Systemd Service Package

## 1. Observation

A systematic survey was executed across the entire repository at `c:\Users\USER\Documents\SIEM`.

### 1.1 Tool Invocations and Results
- **Directory listing & file scan (`list_dir`, `find_by_name`)**:
  - Found 48 source, configuration, and documentation files across 14 directories: `adapters/`, `backend/`, `compatibility/`, `configs/`, `docs/`, `frontend/`, `orchestration/`, `releases/`, `rules/`, `scripts/`, and `tests/`.
- **Existing Test Execution (`python -m pytest tests/`)**:
  - Command: `python -m pytest tests/`
  - Output: `44 passed, 1 warning in 4.43s` (Python 3.12.10, pytest-9.1.1, anyio-4.15.1).
  - Existing test suites:
    - `tests/integration/test_api_endpoints.py` (9 tests passed)
    - `tests/integration/test_enterprise_bas_and_hunting.py` (5 tests passed)
    - `tests/integration/test_orchestration_and_recovery.py` (4 tests passed)
    - `tests/integration/test_simulation_and_soar.py` (6 tests passed)
    - `tests/unit/test_adapters.py` (8 tests passed)
    - `tests/unit/test_manifest_and_compatibility.py` (8 tests passed)
    - `tests/unit/test_rbac_and_audit.py` (4 tests passed)

### 1.2 Implemented Artifacts Observed

1. **FastAPI Management Application (`backend/app/main.py`)**:
   - Line 11-18: Initialized `FastAPI` instance with title `OpenSOC Forge`, version `1.0.0`, OpenAPI routes at `/api/v1/openapi.json`.
   - Line 31-40: OWASP security headers middleware enforcing `nosniff`, `DENY` framing, `X-XSS-Protection`, and Content-Security-Policy.
   - Line 43: API v1 router included at `/api/v1`.
   - Line 48-50: Static frontend mount at `/console` pointing directly to `frontend/` directory.
   - Line 53-61: Root `/` health endpoint returning `{"platform": "OpenSOC Forge", "status": "ONLINE", ...}`.

2. **Core Security, RBAC & Audit Engine (`backend/app/core/`)**:
   - `security.py:20-74`: 5 user roles (`SECOPS_VIEWER`, `INCIDENT_RESPONDER`, `DETECTION_ENGINEER`, `RECOVERY_OPERATOR`, `PLATFORM_ADMIN`) and granular permission matrix.
   - `security.py:77-101`: Salted SHA-256 password hashing and HMAC-SHA256 JWT bearer token lifecycle.
   - `audit.py:15-111`: Append-only, tamper-evident audit log with cryptographic SHA-256 hash chaining stored in `configs/audit_log.jsonl`, verified via `verify_integrity()`.

3. **API Endpoints & Enterprise Simulation Services (`backend/app/api/v1/api.py` and `backend/app/services/`)**:
   - 907 lines in `api.py` implementing endpoints for:
     - Authentication (`/auth/login`)
     - Operations & Alert triage (`/overview`, `/alerts`, `/alerts/{alert_id}`, `/cases`)
     - Rule testing & Sigma compilation (`/rules`, `/rules/test-syntax`, `/rules/sigma/compile`)
     - Component lifecycle & recovery (`/inventory`, `/releases`, `/deploy/plan`, `/deploy/execute`, `/deploy/jobs`, `/backups`, `/backups/restore`, `/rollback`, `/synthetic-event`, `/diagnostics/export`, `/audit`)
     - Adversary Emulation & Cyber Range (`/simulation/scenarios`, `/simulation/run`, `/simulation/bas/tests`, `/simulation/bas/run`, `/simulation/bas/scorecard`, `/simulation/purple-team/campaigns`)
     - Threat Hunting & SOAR (`/soar/playbooks`, `/soar/execute`, `/hunting/campaigns`, `/mitre/matrix`, `/threat-intel/feeds`, `/threat-intel/hunt`, `/investigation/process-tree/{alert_id}`, `/cases/{case_id}/war-room`)

4. **Web Console UI (`frontend/index.html`)**:
   - Line 1-2802 (147 KB): Complete standalone React 18 single-page application utilizing Tailwind CSS and Lucide icons.
   - Zero-dependency runtime (loads via pre-compiled React UMD with zero runtime Babel compilation).
   - Line 812-927: Full navigation hierarchy containing all 15 operational screens and Enterprise Simulation tabs (`overview`, `alerts`, `search`, `hosts`, `network`, `cases`, `adversary_sim`, `bas_testing`, `purple_team`, `soar_playbooks`, `threat_hunting`, `mitre_heatmap`, `threat_intel`, `sigma_studio`, `rules`, `reports`, `inventory`, `jobs`, `health`, `releases`, `backup`, `audit`, `settings`).

5. **Component Adapters (`adapters/`)**:
   - `base.py:25-106`: 17-method operational interface (`discover`, `get_version`, `validate_compatibility`, `preflight`, `plan_install`, `install`, `configure`, `validate_configuration`, `start`, `stop`, `healthcheck`, `integration_test`, `upgrade`, `backup`, `restore`, `rollback`, `collect_diagnostics`, `uninstall`).
   - Implementations in `adapters/elastic/adapter.py`, `adapters/suricata/adapter.py`, `adapters/wazuh/adapter.py`, `adapters/syslog/adapter.py` supporting both host inspection and fallback simulation mode.

6. **Compatibility Engine & Release Manifests (`compatibility/`, `releases/`)**:
   - `compatibility/engine.py:59-70`: Semver parsing and compatibility solver.
   - `compatibility/matrix.yaml:1-88`: Declares supported combinations (`v1.0-lab`, `v1.1-modern`) and explicit incompatibility rules (`INCOMPAT-001` to `INCOMPAT-004`).
   - `releases/manifests/v1.0.0-lab.yaml` & `v1.1.0-candidate.yaml`: JSON schema-validated release manifests defining component ports, paths, checksums, and upgrade migration steps.

7. **Orchestration & CLI (`orchestration/engine.py`, `scripts/opensoc_cli.py`)**:
   - `orchestration/engine.py`: 14-step idempotent state machine with automated rollback on failure.
   - `scripts/opensoc_cli.py`: Argparse CLI runner with subcommands (`status`, `doctor`, `plan`, `install`, `configure`, `validate`, `test-integration`, `backup`, `backup-verify`, `upgrade`, `rollback-config`, `rollback-component`, `restore-data`, `logs`, `report`, `uninstall`).
   - `scripts/opensoc-forge.bat`: Windows batch wrapper.

### 1.3 Missing Artifacts Observed (Relative to User Request R1-R5)
- **Installer Script**: Pattern search `*install*` returned 0 results. No `install.sh` exists in repository root or subdirectories.
- **Compose Definitions**: Pattern search `*compose*` and `*docker*` returned 0 results. No `docker-compose.yml`, `podman-compose.yml`, or `Dockerfile` exists.
- **Systemd Service Integration**: Pattern search `*systemd*` returned 0 files. No `systemd/` directory or `opensoc-forge.service` unit file exists.
- **CLI Wrapper Tool**: Pattern search `*ctl*` returned 0 files. No `bin/opensoc-ctl` executable wrapper exists.
- **Security Policy Scripts**: No firewalld or SELinux automated configuration scripts exist for RHEL 9 / Rocky Linux 9, and no `setcap` packet capture configuration scripts exist for Kali Linux / Debian.
- **Data Plane Container Configurations**: No containerized Elasticsearch TLS certificate generation or config staging, no Wazuh manager container configuration, no Suricata container AF_PACKET compose definitions, and no syslog receiver container service.

---

## 2. Logic Chain

1. **Premise 1**: The user request (`ORIGINAL_REQUEST.md`) requires an OpenSOC Forge 1-Click Universal Linux Systemd Service Package that installs with `sudo ./install.sh`, runs as a native systemd service (`systemctl enable|start|stop opensoc-forge.service`), orchestrates a multi-service containerized data plane (FastAPI mgmt, Elasticsearch, Kibana, Wazuh Manager, Suricata, Syslog), aligns cross-distro security policies (Kali/Debian vs RHEL/Rocky 9), and provides a CLI wrapper `bin/opensoc-ctl`.
2. **Premise 2**: Observation 1.2 confirms that the software application layer of OpenSOC Forge is complete and verified:
   - The FastAPI management server (`backend/app/main.py`) is operational.
   - The React Web Console UI (`frontend/index.html`) is complete with all required screens and simulation tabs.
   - The component adapters (`adapters/`), compatibility engine (`compatibility/`), simulation engine (`backend/app/services/`), and orchestration state machine (`orchestration/`) are fully coded and pass all 44 unit and integration tests.
3. **Premise 3**: Observation 1.3 confirms that the containerized packaging, universal installation script, systemd service units, and host management CLI are entirely absent:
   - No `install.sh` exists to inspect `/etc/os-release`, execute hardware preflight checks, set `vm.max_map_count`, detect/install Docker/Podman, and automate deployment.
   - No `docker-compose.yml` or container definitions exist to launch `opensoc-forge-mgmt`, `elasticsearch`, `kibana`, `wazuh-manager`, `suricata`, and `syslog-collector`.
   - No `systemd/opensoc-forge.service` unit file exists to control container lifecycle under systemd.
   - No `bin/opensoc-ctl` exists to manage `status`, `logs`, `backup`, and `test`.
   - No cross-distro security scripts exist for Kali (`setcap`) or RHEL 9 (`firewalld`, SELinux `container_manage_cgroup`).
4. **Conclusion**: Implementation must focus entirely on building the operational deployment and container infrastructure layer around the existing application codebase, without breaking or replacing the existing passing FastAPI endpoints, adapters, and frontend.

---

## 3. Caveats

- **Operating System Environment**: The current workspace host is Windows (running Python 3.12.10). Direct execution of Linux-specific commands (`setcap`, `systemctl`, `firewalld`, `/etc/os-release` parsing) must be validated via mock-friendly scripts or container test harnesses on this host, while the actual bash scripts (`install.sh`, `bin/opensoc-ctl`) must be authored with strict POSIX/bash compliance (`#!/usr/bin/env bash`, `set -euo pipefail`).
- **Container Engine Parity**: Both Docker Compose (plugin `docker compose` or legacy `docker-compose`) and Podman (`podman-compose`) should be supported by `install.sh` and `opensoc-ctl` to ensure seamless execution on both Kali Linux (Debian-based APT) and RHEL 9 / Rocky Linux 9 (RPM-based DNF).
- **Existing Tests**: Any additions must not break the 44 existing passing pytest tests in `tests/`. New unit and integration tests must be added to cover `install.sh`, `docker-compose.yml`, `systemd/opensoc-forge.service`, and `bin/opensoc-ctl`.

---

## 4. Conclusion

The OpenSOC Forge repository has a mature, fully functional application and simulation layer, but lacks the deployment, containerization, systemd integration, and cross-distribution packaging demanded by `ORIGINAL_REQUEST.md`.

To satisfy all requirements R1–R5 and acceptance criteria, the following implementation plan is needed:
1. **Packaging & Containerization (R2)**:
   - Create `Dockerfile` for `opensoc-forge-mgmt` (packaging FastAPI app + static Web Console).
   - Create production-ready `docker-compose.yml` (and `podman-compose.yml` compatible) with the 6 services:
     1. `opensoc-forge-mgmt` (port 8000)
     2. `elasticsearch` (port 9200, single-node, TLS enabled)
     3. `kibana` (port 5601)
     4. `wazuh-manager` (ports 1514, 1515, 55000)
     5. `suricata` (network_mode: host, AF_PACKET packet capture, EVE JSON logging)
     6. `syslog-collector` (ports 514/udp, 6514/tcp TLS)
   - Provide configuration templates, environment files (`.env.example`), and TLS cert generation scripts (`scripts/generate_certs.sh`).
2. **Universal 1-Click Installer (`install.sh`) (R1, R4)**:
   - Author idempotent `install.sh` at repository root.
   - Add OS family detector supporting Kali Linux, Debian, Ubuntu, RHEL 9, Rocky Linux 9, AlmaLinux, Fedora.
   - Implement preflight hardware checks (RAM >= 8GB, CPU >= 4 cores, Disk >= 30GB, network interface detection).
   - Implement kernel parameter configuration (`vm.max_map_count=262144`).
   - Implement package manager container engine provisioner (APT vs DNF/RPM).
   - Implement distro-specific policy alignment: `setcap` on Kali/Debian, `firewalld` port openings and SELinux boolean configuration (`container_manage_cgroup`) on RHEL/Rocky.
3. **Automated Native Systemd Service Integration (R3)**:
   - Create `systemd/opensoc-forge.service` unit file template with `Restart=on-failure`, `TimeoutStartSec=300`, and container management hooks.
   - Configure installer to install, reload, enable, and start the service.
4. **Unified Management CLI (`bin/opensoc-ctl`) (R5)**:
   - Create executable `bin/opensoc-ctl` supporting `status`, `logs [service]`, `backup`, and `test` (synthetic alert injection).
5. **Automated Verification Harnesses**:
   - Add automated test scripts / pytest fixtures verifying compose structure, installer preflight logic, systemd unit validity, and CLI parsing.

---

## 5. Verification Method

To independently verify this survey:
1. **Inspect Repository Layout**:
   - Run `python -m pytest tests/` from repository root: confirms 44 tests pass.
   - Check file existence of missing components:
     ```powershell
     Test-Path "c:\Users\USER\Documents\SIEM\install.sh"
     Test-Path "c:\Users\USER\Documents\SIEM\docker-compose.yml"
     Test-Path "c:\Users\USER\Documents\SIEM\systemd\opensoc-forge.service"
     Test-Path "c:\Users\USER\Documents\SIEM\bin\opensoc-ctl"
     ```
     All should return `False` currently, verifying that deployment package assets are yet to be built.
2. **Inspect Existing Application Assets**:
   - Verify FastAPI endpoints in `backend/app/main.py` and `backend/app/api/v1/api.py`.
   - Verify React Web Console at `frontend/index.html`.
3. **Invalidation Conditions**:
   - If any `docker-compose.yml`, `install.sh`, or `systemd/opensoc-forge.service` already exists in a hidden or alternative directory, this finding would be invalidated (none were found in `find_by_name`).
