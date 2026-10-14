# Survey Report: Universal Installer (R1), Native Systemd Integration (R3), and Management CLI Wrapper (R5)

## Executive Summary
This survey report establishes the architectural specifications, concrete implementations, error handling rules, idempotency requirements, and edge-case mitigations for:
1. **Requirement R1**: Universal 1-Click Linux Installer Script (`install.sh`) supporting Kali Linux 2024+, Debian 12, Ubuntu 22.04+, RHEL 9, Rocky Linux 9, AlmaLinux 9, and Fedora.
2. **Requirement R3**: Automated Native Systemd Service Integration (`systemd/opensoc-forge.service`) enabling automatic recovery, boot auto-start, and unified journalctl logging.
3. **Requirement R4**: Cross-Distribution Network & Security Policy Alignment (`firewalld`, SELinux booleans, and packet capture capabilities).
4. **Requirement R5**: Self-Contained CLI Wrapper Tool (`bin/opensoc-ctl`) supporting `status`, `logs [service]`, `backup`, and `test` with end-to-end synthetic alert rendering within 5 seconds.

---

## 1. Observation

### 1.1 Existing Codebase & Assets
- **Project Structure**:
  - `backend/app/main.py`: Lines 48-50 mount the pre-compiled Web Console at `/console` on port 8000 using `StaticFiles(directory=frontend_dir, html=True)`. Root API endpoint `/` returns platform status and metadata.
  - `backend/app/api/v1/api.py`: Lines 77-159 define in-memory `DEMO_ALERTS`. Lines 270-293 provide `GET /overview`. Lines 296-311 provide `GET /alerts`. Lines 541-566 define `POST /synthetic-event` which calls `adapter.integration_test()` returning an `IntegrationTestResult` but currently **does NOT** append a new `AlertItem` to `DEMO_ALERTS`.
  - `frontend/index.html`: Lines 72-100 define static `initialAlerts`. Line 198 initializes React state `const [alerts, setAlerts] = useState(initialAlerts);`. Lines 666-680 define `triggerSyntheticTest()` which only updates local component state after 800ms; there is currently **no network fetch** polling `/api/v1/alerts`.
  - `scripts/opensoc_cli.py`: Lines 1-230 implement CLI operations with commands `status`, `doctor`, `plan`, `install`, `configure`, `validate`, `test-integration`, `backup`, `backup-verify`, `upgrade`, `rollback-config`, `rollback-component`, `restore-data`, `logs`, `report`, `uninstall`. Subcommand signatures do not match the required R5 tool interface `bin/opensoc-ctl status|logs|backup|test`.
  - `releases/manifests/v1.0.0-lab.yaml`: Lines 23-156 specify components: Elasticsearch (port 9200, 9300), Kibana (port 5601), Wazuh Manager (ports 1514, 1515, 55000), Suricata (AF_PACKET packet capture, passive mode), Filebeat (agent), Syslog (ports 514, 6514).
  - `orchestration/engine.py`: Lines 175-274 implement 14-step idempotent deployment state machine with automatic rollback upon failure.

### 1.2 Missing Components Required by User Request
- Tool `find_by_name` across `c:\Users\USER\Documents\SIEM` confirmed:
  - `install.sh`: **Not present**.
  - `systemd/opensoc-forge.service`: **Not present**.
  - `bin/opensoc-ctl`: **Not present**.
  - `docker-compose.yml` / `podman-compose.yml`: **Not present**.

### 1.3 Baseline Test Verification
- Executed `python -m pytest` on root:
  - Total tests collected: 44.
  - Results: **44 passed, 0 failures, 1 warning in 3.34s**.
  - Confirms baseline stability across API endpoints, BAS simulation, orchestration recovery, and component adapters.

---

## 2. Logic Chain

### 2.1 Universal 1-Click Linux Installer Script (`install.sh`) (R1 & R4)

#### 2.1.1 OS Identification Logic
`/etc/os-release` must be sourced to extract `ID`, `ID_LIKE`, `VERSION_ID`:
```bash
if [ -f /etc/os-release ]; then
    . /etc/os-release
else
    echo "ERROR: /etc/os-release not detected. Unsupported platform." >&2
    exit 1
fi
```
Classification Matrix:
| Target OS | `ID` / `ID_LIKE` | Package Manager | Non-Interactive Mode Flag |
|---|---|---|---|
| Kali Linux 2024+ | `ID="kali"`, `ID_LIKE="debian"` | `apt-get` | `DEBIAN_FRONTEND=noninteractive` |
| Debian 12 (Bookworm) | `ID="debian"` | `apt-get` | `DEBIAN_FRONTEND=noninteractive` |
| Ubuntu 22.04 / 24.04 | `ID="ubuntu"`, `ID_LIKE="debian"` | `apt-get` | `DEBIAN_FRONTEND=noninteractive` |
| RHEL 9 (9.0 - 9.4) | `ID="rhel"`, `ID_LIKE="fedora"` | `dnf` | `-y` |
| Rocky Linux 9 | `ID="rocky"`, `ID_LIKE="rhel centos fedora"` | `dnf` | `-y` |
| AlmaLinux 9 | `ID="almalinux"`, `ID_LIKE="rhel centos fedora"`| `dnf` | `-y` |
| Fedora (39/40+) | `ID="fedora"` | `dnf` | `-y` |

#### 2.1.2 Hardware Preflight Verification
Hardware checks must guard against out-of-memory kernel panics or disk exhaustion while tolerating virtualized hypervisor reservations:
- **RAM Check**:
  - OpenSOC Forge topology (Elasticsearch JVM 2-4GB, Wazuh Manager 2GB, Kibana 1GB, Suricata 1GB, Management API 512MB) requires at least 8 GB total RAM.
  - In VMs, an 8GB allocation often reports ~7600–7900 MB in `/proc/meminfo` due to hypervisor/kernel memory reservations.
  - Extraction: `MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)`.
  - Pass condition: `[ "$MEM_KB" -ge 7782400 ]` (7600 MB threshold). If below and `--skip-preflight` is not set, exit with fatal error and remediation advice.
- **CPU Cores Check**:
  - Extraction: `CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)`.
  - Pass condition: `[ "$CPU_CORES" -ge 4 ]`.
- **Disk Free Space Check**:
  - Target filesystem check on `/opt/opensoc-forge` (or installation parent directory):
  - Extraction: `DISK_AVAIL_KB=$(df -Pk "${INSTALL_DIR:-/opt}" | awk 'NR==2 {print $4}')`.
  - Pass condition: `[ "$DISK_AVAIL_KB" -ge 31457280 ]` (30 GB).
- **Network Interface Check**:
  - Check for at least one active non-loopback network interface with `operstate` equal to `up`:
  - `ACTIVE_IFACE=$(ip -o link show up | awk -F': ' '$2 != "lo" {print $2; exit}')`.
  - Detect primary host IP: `HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}')`.

#### 2.1.3 Kernel Parameter Tuning (`sysctl`)
Elasticsearch mandates `vm.max_map_count >= 262144`. Suricata and high-throughput syslog require socket buffer headroom:
- Immediate runtime apply:
  `sysctl -w vm.max_map_count=262144`
  `sysctl -w fs.file-max=65536`
- Persistent persistence file: `/etc/sysctl.d/99-opensoc-forge.conf`:
  ```ini
  # OpenSOC Forge Kernel Optimizations
  vm.max_map_count=262144
  fs.file-max=65536
  net.core.somaxconn=1024
  ```
- Application: `sysctl --system` (or `sysctl -p /etc/sysctl.d/99-opensoc-forge.conf`).

#### 2.1.4 Automated Container Engine Provisioning
The installer dynamically detects and installs the appropriate container runtime:
1. Engine Evaluation:
   - Check if `docker` and `docker compose` (or `docker-compose`) exist.
   - Check if `podman` and `podman-compose` exist.
2. Automated Installation if absent:
   - **Debian / Kali / Ubuntu**:
     ```bash
     apt-get update -y
     apt-get install -y --no-install-recommends docker.io docker-compose-plugin curl ca-certificates jq
     systemctl enable --now docker
     ```
   - **RHEL 9 / Rocky Linux 9 / AlmaLinux**:
     ```bash
     dnf install -y podman podman-compose curl jq
     systemctl enable --now podman.socket 2>/dev/null || true
     ```
3. Command Resolver:
   Determine `$COMPOSE_CMD`:
   - If `docker compose version` >/dev/null 2>&1 -> `COMPOSE_CMD="docker compose"`
   - Else if `podman-compose --version` >/dev/null 2>&1 -> `COMPOSE_CMD="podman-compose"`
   - Else if `docker-compose version` >/dev/null 2>&1 -> `COMPOSE_CMD="docker-compose"`

#### 2.1.5 Security & Network Policy Alignment (R4)
- **RHEL 9 / Rocky Linux 9 Policy Configuration**:
  - `firewalld`:
    ```bash
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port={8000/tcp,5601/tcp,9200/tcp,1514/tcp,1514/udp,1515/tcp,55000/tcp,514/udp,514/tcp,6514/tcp}
        firewall-cmd --reload
    fi
    ```
  - `SELinux`:
    ```bash
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
        setsebool -P container_manage_cgroup 1 2>/dev/null || true
        # Ensure mounted volumes use :z / :Z or apply container_file_t
        chcon -Rt container_file_t "$INSTALL_DIR/configs" "$INSTALL_DIR/data" 2>/dev/null || true
    fi
    ```
- **Kali Linux / Debian Policy Configuration**:
  - Network packet sniffing capabilities:
    Containers running Suricata use `network_mode: host` and `cap_add: [NET_ADMIN, NET_RAW]`. On host binaries if installed natively, apply: `setcap cap_net_raw,cap_net_admin+eip <binary>`.

#### 2.1.6 Automated Non-Interactive Deployment Flow
```
[Start install.sh]
       │
       ▼
Check root / sudo (EUID == 0)
       │
       ▼
Parse /etc/os-release -> Classify distro
       │
       ▼
Execute Hardware Preflights (RAM >= 8GB, CPU >= 4, Disk >= 30GB, Net UP)
       │
       ▼
Apply sysctl vm.max_map_count=262144 -> Persist in /etc/sysctl.d/99-opensoc-forge.conf
       │
       ▼
Detect or Install Container Engine (Docker/Compose on Debian/Kali; Podman/Compose on RHEL/Rocky)
       │
       ▼
Apply Network & Security Policies (firewalld ports, SELinux booleans, setcap)
       │
       ▼
Stage files to /opt/opensoc-forge
       │
       ▼
Install systemd/opensoc-forge.service to /etc/systemd/system/
       │
       ▼
Symlink bin/opensoc-ctl -> /usr/local/bin/opensoc-ctl
       │
       ▼
systemctl daemon-reload && systemctl enable --now opensoc-forge.service
       │
       ▼
Poll http://localhost:8000/ and health endpoints (timeout 60s)
       │
       ▼
Display Access Credentials & Banner
```

---

### 2.2 Native Systemd Service Integration (`systemd/opensoc-forge.service`) (R3)

#### 2.2.1 Service Architecture Choice: `Type=simple` vs `Type=oneshot`
- **Analysis**:
  - `Type=oneshot` (`docker compose up -d`): Systemd exits immediately after launching. It does not monitor container lifecycle, meaning `Restart=on-failure` never triggers if a container dies later, and `journalctl -u opensoc-forge -f` does not show live container logs.
  - `Type=simple` with Foreground Execution (`bin/opensoc-ctl start-foreground` -> `docker compose up` / `podman-compose up` without `-d`):
    - Systemd directly monitors the compose process.
    - All container stdout/stderr streams are piped into the systemd journal, making `journalctl -u opensoc-forge -f` immediately display full telemetry logs in real time.
    - If containers crash fatally, the process terminates and systemd triggers automatic recovery via `Restart=on-failure`.
    - Clean shutdown via `ExecStop=/usr/local/bin/opensoc-ctl stop` gracefully drains and shuts down containers (`docker compose down -t 30`).

#### 2.2.2 Systemd Unit Definition (`systemd/opensoc-forge.service`)
```ini
[Unit]
Description=OpenSOC Forge All-in-One SIEM/SOC Platform
Documentation=https://github.com/opensoc-forge/opensoc
After=network.target network-online.target docker.service podman.service firewalld.service
Wants=network-online.target
RequiresMountsFor=/opt/opensoc-forge

[Service]
Type=simple
WorkingDirectory=/opt/opensoc-forge
EnvironmentFile=-/opt/opensoc-forge/.env
ExecStartPre=-/usr/local/bin/opensoc-ctl prestart
ExecStart=/usr/local/bin/opensoc-ctl start-foreground
ExecStop=/usr/local/bin/opensoc-ctl stop
ExecReload=/usr/local/bin/opensoc-ctl restart
Restart=on-failure
RestartSec=10s
TimeoutStartSec=300
TimeoutStopSec=60
KillMode=mixed
LimitNOFILE=65536
LimitNPROC=4096
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

---

### 2.3 Management CLI Wrapper Tool (`bin/opensoc-ctl`) (R5)

#### 2.3.1 CLI Architecture & Command Mapping
`bin/opensoc-ctl` must be an executable script placed in `$PATH` (`/usr/local/bin/opensoc-ctl`) supporting the following four primary user-facing commands and internal service lifecycle hooks:

```
opensoc-ctl
├── status               # Health of all containers, ports, and data pipelines
├── logs [service]       # Tail logs of component or all services
├── backup               # Export ES snapshot, Wazuh configs, and state
├── test                 # Injects synthetic event & verifies in <= 5s
├── start-foreground     # [Internal] Foreground runner for systemd Type=simple
├── start                # [Internal] Detached background runner
├── stop                 # [Internal] Graceful container shutdown
├── restart              # [Internal] Container restart
└── prestart             # [Internal] Systemd preflight sanity checks
```

#### 2.3.2 Subcommand Specifications

1. `opensoc-ctl status`:
   - **Systemd Check**: Evaluates `systemctl is-active opensoc-forge` (returns `active` / `inactive`).
   - **Container State**: Executes `$COMPOSE_CMD ps` to extract statuses of:
     `opensoc-forge-mgmt`, `elasticsearch`, `kibana`, `wazuh-manager`, `suricata`, `syslog-collector`.
   - **Network Listeners**: Tests socket connectivity on ports:
     `8000` (Management API), `5601` (Kibana), `9200` (Elasticsearch), `1514` (Wazuh Comm), `1515` (Wazuh Reg), `55000` (Wazuh API), `514` (Syslog).
   - **Pipeline Metrics**: Queries `http://127.0.0.1:8000/api/v1/overview` to report active release, EPS (`534.6`), and pipeline latency (`14.8ms`).
   - **Cluster Health**: Queries Elasticsearch cluster health (`/_cluster/health`), confirming `status: green` or `yellow`.
   - Output format: Clean, colored terminal status dashboard.

2. `opensoc-ctl logs [service]`:
   - If `[service]` is specified (e.g. `elasticsearch`, `suricata`, `wazuh-manager`, `kibana`, `opensoc-forge-mgmt`, `syslog-collector`):
     Runs `$COMPOSE_CMD logs -f --tail=100 "$service"`.
   - If no service is specified:
     Executes `journalctl -u opensoc-forge -f` or `$COMPOSE_CMD logs -f --tail=50`.

3. `opensoc-ctl backup`:
   - Creates backup timestamp directory: `/opt/opensoc-forge/backups/backup-$(date +%Y%m%d_%H%M%S)`.
   - Exports Elasticsearch snapshots / index configurations:
     Creates index dump or snapshot of `suricata-*`, `wazuh-alerts-*`, `.kibana`.
   - Copies component configurations:
     `/opt/opensoc-forge/configs`, `/opt/opensoc-forge/docker-compose.yml`, `/opt/opensoc-forge/.env`.
   - Compresses into `.tar.gz` archive.
   - Computes SHA-256 cryptographic checksum.
   - Validates tar archive integrity (`tar -tzf <archive> >/dev/null`).
   - Displays backup summary: Backup ID, file size, SHA-256 hash.

4. `opensoc-ctl test`:
   - **Requirement**: Generates a synthetic alert that successfully renders in the Web Console within 5 seconds.
   - Flow:
     1. CLI generates a unique synthetic event token (`synth-<timestamp>`).
     2. Calls API: `POST http://127.0.0.1:8000/api/v1/synthetic-event` with payload `{"event_type": "test_alert", "target_component": "suricata"}`.
     3. Backend creates a new `AlertItem` and injects it into `DEMO_ALERTS` and active Elasticsearch index.
     4. CLI polls `GET http://127.0.0.1:8000/api/v1/alerts` to confirm the synthetic alert is present.
     5. Measures round-trip duration in milliseconds (typically < 100ms, well within the 5.0s threshold).
     6. Prints `[PASS] Pipeline Verification Succeeded (Latency: XX ms, Alert ID: ALT-XXXX)`.

---

### 2.4 Critical Integration Findings & Fixes

During the survey, two critical integration gaps between backend, frontend, and acceptance criteria were discovered:

#### Gap 1: Backend Synthetic Event does not add to `DEMO_ALERTS`
- **Current state**: `POST /api/v1/synthetic-event` in `backend/app/api/v1/api.py` (lines 541-566) calls `adapter.integration_test()`. It returns a test result object, but **never adds** an `AlertItem` to `DEMO_ALERTS`.
- **Impact**: Any consumer querying `GET /api/v1/alerts` (such as the Web Console) will never see the synthetic alert created by `opensoc-ctl test`.
- **Fix**: In Phase 3, update `inject_synthetic_event()` to construct a new `AlertItem`:
  ```python
  new_alert = AlertItem(
      id=f"ALT-{int(time.time())}",
      timestamp=datetime.utcnow().isoformat() + "Z",
      severity=AlertSeverity.HIGH,
      source="suricata",
      title=f"SYNTHETIC VERIFICATION: E2E Telemetry Ingestion Alert ({test_res.synthetic_event_id})",
      description="Automated synthetic event injected via opensoc-ctl test to verify pipeline delivery.",
      host="opensoc-sensor-01",
      src_ip="198.51.100.99",
      dest_ip="10.0.1.15",
      mitre_attack_id="T1059",
      mitre_tactic="Execution",
      status=AlertStatus.NEW,
      raw_payload={"stages": test_res.stages, "synthetic_id": test_res.synthetic_event_id},
      is_demo=True,
  )
  DEMO_ALERTS.insert(0, new_alert)
  ```

#### Gap 2: Frontend Web Console does not poll `/api/v1/alerts`
- **Current state**: `frontend/index.html` loads `initialAlerts` into React state `alerts` at initialization, but never calls `fetch("/api/v1/alerts")`.
- **Impact**: The Web Console will never reflect alerts created by `opensoc-ctl test` on the screen within 5 seconds.
- **Fix**: In Phase 3, add an auto-refresh effect in `frontend/index.html` that periodically polls `/api/v1/alerts` (e.g. every 2 seconds):
  ```javascript
  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await fetch("/api/v1/alerts");
        if (res.ok) {
          const data = await res.json();
          setAlerts(data);
        }
      } catch (err) {
        // Fallback to existing alerts in standalone mode
      }
    };
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 2000);
    return () => clearInterval(interval);
  }, []);
  ```
  With this 2-second polling interval, synthetic alerts injected by `opensoc-ctl test` will render in the Web Console within 2–3 seconds, reliably satisfying the "< 5 seconds" acceptance criterion.

---

## 3. Caveats

1. **Development Host OS (Windows vs Target Linux)**:
   - The active development workstation is Windows. The shell scripts (`install.sh`, `bin/opensoc-ctl`) and systemd unit (`systemd/opensoc-forge.service`) are POSIX Linux utilities.
   - All shell scripts must use strict POSIX/Bash syntax with LF line endings (`\n`, no `\r\n`).
   - Automated tests running in Python (`pytest`) will test script parsing, command line interface arguments, mock execution, API routing, and systemd syntax validation so that the test suite runs cross-platform on Windows and Linux.
2. **Virtualized Hypervisor RAM Reporting**:
   - As noted, an 8GB VM frequently reports ~7600–7900 MB in `/proc/meminfo`. The installer check must use `7600 MB` (7782400 kB) as the lower threshold rather than an exact 8192 MB to avoid false rejections. A `--skip-preflight` flag must also be available.
3. **Rootful Podman on RHEL 9**:
   - Binding to ports < 1024 (syslog port 514/udp and 514/tcp) and operating Suricata in host networking mode requires root privileges. Therefore, Podman on RHEL 9 must run in rootful mode via systemd (`User=root`).

---

## 4. Conclusion

1. **Requirement R1 (`install.sh`)**:
   - The installer architecture is fully defined: OS detection via `/etc/os-release`, hardware preflights (RAM >= 8GB, CPU >= 4, Disk >= 30GB, network interface UP), sysctl kernel tuning (`vm.max_map_count=262144` runtime and `/etc/sysctl.d/` persistence), dual container engine detection/installation (`apt-get` vs `dnf`), security policy alignment (`firewalld` ports and SELinux booleans), and non-interactive hands-off deployment.
2. **Requirement R3 (`systemd/opensoc-forge.service`)**:
   - Unit design is finalized as `Type=simple` running `bin/opensoc-ctl start-foreground`. This guarantees unified log aggregation in `journalctl -u opensoc-forge -f`, automated restart recovery (`Restart=on-failure`), boot auto-enable (`systemctl enable opensoc-forge`), and 300s start timeout (`TimeoutStartSec=300`).
3. **Requirement R4 (Policy Alignment)**:
   - Packet capture capabilities (`setcap cap_net_raw,cap_net_admin+eip`) for Debian/Kali.
   - `firewalld` port permissions (8000, 5601, 9200, 1514, 1515, 55000, 514, 6514) and SELinux container booleans (`container_manage_cgroup`) for RHEL 9 / Rocky 9.
4. **Requirement R5 (`bin/opensoc-ctl`)**:
   - Subcommand interfaces (`status`, `logs [service]`, `backup`, `test`) are specified.
   - The integration pipeline test flow guarantees synthetic alert generation and verification within 5 seconds.
5. **Concrete Action Plan for Phase 1 & Phase 3**:
   - Feed these findings into `PROJECT.md` and `TEST_INFRA.md` during Phase 1.
   - Implement `install.sh`, `systemd/opensoc-forge.service`, and `bin/opensoc-ctl` in Phase 3 Milestones 2, 3, and 4.

---

## 5. Verification Method

To independently verify the survey findings and baseline:

1. **Baseline Test Execution**:
   Run the pytest suite to verify zero regressions:
   ```bash
   python -m pytest
   ```
   *Expected Result*: 44 passed, 0 failures.

2. **Verify Subcommand & Script Architecture**:
   - Inspect `c:\Users\USER\Documents\SIEM\scripts\opensoc_cli.py`:
     Observe that existing subcommands are `test-integration`, `status`, `backup`. Confirm that R5 subcommands require a dedicated `bin/opensoc-ctl` wrapper.
   - Inspect `c:\Users\USER\Documents\SIEM\backend\app\api\v1\api.py`:
     Lines 541-566: Verify that `inject_synthetic_event()` does not currently mutate `DEMO_ALERTS`.
   - Inspect `c:\Users\USER\Documents\SIEM\frontend\index.html`:
     Lines 198 and 666-680: Verify that `alerts` is loaded once and not polled from backend.

3. **Invalidation Conditions**:
   - If `/proc/meminfo` checking logic uses strict 8192 MB, it will fail on standard 8GB virtual machines.
   - If `Type=oneshot` is chosen for systemd, `Restart=on-failure` will not monitor container failures, invalidating R3 auto-recovery.
   - If `inject_synthetic_event` does not update `DEMO_ALERTS` and `frontend/index.html` does not poll `/api/v1/alerts`, the acceptance criterion for `< 5s` console alert rendering will fail.
