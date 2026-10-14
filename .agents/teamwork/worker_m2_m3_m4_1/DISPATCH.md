## 2026-10-14T17:43:57Z
You are teamwork_preview_worker (Milestones 2, 3, 4 Implementation Worker).
Your working directory is `c:\Users\USER\Documents\SIEM\.agents\teamwork\worker_m2_m3_m4_1`.
You MUST read the authoritative user request at `c:\Users\USER\Documents\SIEM\.agents\teamwork\ORIGINAL_REQUEST.md` before starting work.
You MUST also read `c:\Users\USER\Documents\SIEM\PROJECT.md`, `c:\Users\USER\Documents\SIEM\TEST_READY.md`, and `c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_3\handoff.md`.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your task:
Implement Milestones 2, 3, and 4 to complete all remaining system requirements (R1, R3, R4, R5) and acceptance criteria:

1. **Milestone 2: Universal 1-Click Installer (`install.sh`) (Requirement R1)**
   - Create idempotent `install.sh` in repository root with `#!/usr/bin/env bash` and `set -euo pipefail`.
   - OS Family detection parsing `/etc/os-release`:
     - Kali Linux, Debian, Ubuntu -> `apt-get` non-interactive mode.
     - RHEL 9, Rocky Linux 9, AlmaLinux, Fedora -> `dnf` non-interactive mode.
   - Hardware preflight checks:
     - RAM >= 8GB (allow 7600 MB threshold for hypervisor/kernel reservations, and `--skip-preflight` flag).
     - CPU >= 4 cores.
     - Disk >= 30GB free on target path.
     - Active network interface check (operstate up, non-loopback) and gateway IP detection.
   - Kernel parameter tuning:
     - Apply `sysctl -w vm.max_map_count=262144` and `fs.file-max=65536`.
     - Persist in `/etc/sysctl.d/99-opensoc-forge.conf`.
   - Automated container engine detection/provisioning:
     - Detects or installs Docker + Compose plugin (Debian/Kali) or Podman + Compose (RHEL/Rocky).
   - Automated non-interactive deployment to `/opt/opensoc-forge`:
     - Stages compose files, configs, scripts, and environment.
     - Generates TLS certificates via `scripts/generate_certs.sh`.
     - Installs systemd service unit and CLI symlink (`/usr/local/bin/opensoc-ctl`).
     - Enables and starts systemd service without interactive prompts.

2. **Milestone 3: Native Systemd Service & Policy Alignment (Requirements R3 & R4)**
   - Create `systemd/opensoc-forge.service`:
     - `Type=simple`, `Restart=on-failure`, `RestartSec=10s`, `TimeoutStartSec=300`.
     - `ExecStartPre=-/usr/local/bin/opensoc-ctl prestart`
     - `ExecStart=/usr/local/bin/opensoc-ctl start-foreground`
     - `ExecStop=/usr/local/bin/opensoc-ctl stop`
     - `ExecReload=/usr/local/bin/opensoc-ctl restart`
     - `WantedBy=multi-user.target`.
     - Pipes container stdout/stderr into journalctl for `journalctl -u opensoc-forge -f`.
   - Cross-distribution policy alignment:
     - Create `configs/firewalld/opensoc-forge.xml` defining ports (8000, 5601, 9200, 1514, 1515, 55000, 514, 6514).
     - Create `scripts/configure_security_policies.sh` automating:
       - RHEL 9 / Rocky 9: Firewalld service installation & reload; SELinux `container_manage_cgroup 1` and `container_use_devices 1` booleans; volume label handling.
       - Kali / Debian: `setcap cap_net_raw,cap_net_admin+eip` and UFW port rules.
     - Create `configs/sysctl/99-opensoc-forge.conf`.

3. **Milestone 4: Self-Contained CLI Wrapper Tool (`bin/opensoc-ctl`) & Pipeline Integration (Requirement R5)**
   - Create `bin/opensoc-ctl` with `#!/usr/bin/env bash` and `set -euo pipefail`:
     - `opensoc-ctl status`: displays systemd unit state, container statuses, open ports, API overview metrics, and Elasticsearch cluster health.
     - `opensoc-ctl logs [service]`: tails component logs or full service journal.
     - `opensoc-ctl backup`: creates tar.gz archive of configs/state, calculates SHA-256 hash, and verifies integrity.
     - `opensoc-ctl test`: triggers synthetic alert pipeline test, verifies round-trip in < 5 seconds.
     - Internal hooks: `start-foreground`, `start`, `stop`, `restart`, `prestart`.
   - Fix Survey Gap 1 in `backend/app/api/v1/api.py`:
     - In `inject_synthetic_event()` (POST `/api/v1/synthetic-event`), construct and prepend an `AlertItem` to `DEMO_ALERTS` so `GET /api/v1/alerts` contains the newly created synthetic alert.
   - Fix Survey Gap 2 in `frontend/index.html`:
     - Add auto-refresh polling (every 2 seconds) for `/api/v1/alerts` in React state so newly injected alerts render on the Web Console within 5 seconds.

4. **Testing and Verification**:
   - Write comprehensive unit tests in `tests/unit/test_milestones_2_3_4.py`.
   - Execute `python -m pytest tests/` and `python tests/e2e/e2e_test_runner.py` to ensure ALL unit, integration, and E2E tests pass 100% with zero failures.
   - Produce a detailed handoff report in `c:\Users\USER\Documents\SIEM\.agents\teamwork\worker_m2_m3_m4_1\handoff.md`.
