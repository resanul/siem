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


## 2026-10-18T13:37:03Z

Implement end-to-end event querying and search functionality for the "Event Investigation & Query Console" in OpenSOC Forge, replacing the static mockup with real backend query execution against Elasticsearch, Suricata logs, Wazuh alerts, and local telemetry, paired with an interactive frontend console.

Working directory: d:/AI/siem
Integrity mode: development

## Requirements

### R1. Backend Event Search API Endpoint
Implement an endpoint `POST /api/v1/events/search` (and matching `GET /api/v1/events/search`) in `backend/app/api/v1/api.py`.
- Accept query parameters/payload: `query` (string, supporting Lucene/KQL syntax, key:value filters, or substring text), `indices` (list of index patterns such as `["suricata-*", "wazuh-alerts-*", "syslog-*"]` or `["*"]`), `time_range` (e.g., "15m", "1h", "24h", "7d", "all"), and `limit` (default 50, max 200).
- When Elasticsearch is reachable (`ELASTICSEARCH_URL`), dispatch query via `query_string` or multi-index search with authentication.
- Resilient fallback: When Elasticsearch is offline or returns no hits, parse and search across local Suricata EVE logs (`eve.json`), Wazuh alerts, syslog, in-memory `LIVE_SIMULATION_ALERTS`, persisted alerts, and threat indicators matching the query terms.
- Return structured JSON response:
  ```json
  {
    "total_hits": 12,
    "took_ms": 14,
    "indices_searched": ["suricata-*", "wazuh-alerts-*", "syslog-*"],
    "events": [
      {
        "id": "evt-...",
        "timestamp": "2026-10-18T19:20:00Z",
        "index": "suricata-eve",
        "source_type": "suricata.eve.alert",
        "host": "web-app-dmz-01",
        "severity": "CRITICAL",
        "summary": "...",
        "raw": { ... }
      }
    ]
  }
  ```

### R2. Interactive Event Investigation UI Console
Update the "Event Investigation & Query Console" in `frontend/index.html` (`currentScreen === "search"`):
- Bind the query input to state (`queryText`), enabling execution on button click or Enter key.
- Provide responsive execution status, displaying real query execution time (`Query Results: X hits in Yms`) and time range filter selector.
- Add quick filter chips/presets for common indices and syntax examples (e.g., `suricata-*`, `wazuh-alerts-*`, `event.category:network`, `host.name:*`).
- Render event results dynamically with timestamp, color-coded source badge, host name, and summary.
- Clicking on an event expands or opens a modal displaying the formatted raw JSON payload and metadata with a one-click copy button.
- Provide a clean empty state with actionable suggestions when no events match.
- Auto-load recent events upon entering the screen or mounting the view.

### R3. Automated Test Verification
Add unit and integration tests (e.g., in `tests/test_event_search.py`) verifying:
- Search API response status 200 and schema compliance.
- Query parsing and execution across live or fallback data sources.
- Resilient operation when Elasticsearch is unreachable.

## Acceptance Criteria

### API Verification
- [ ] `POST /api/v1/events/search` responds with HTTP 200 and schema containing `total_hits`, `took_ms`, `indices_searched`, and `events`.
- [ ] Wildcard `*` or empty query returns the most recent telemetry events.
- [ ] Filter queries by host or event type properly filter returned events.
- [ ] Fallback mechanism functions seamlessly when Elasticsearch is unavailable.

### UI Console Verification
- [ ] Navigating to "Event Investigation" displays live or recent events instead of hardcoded static data.
- [ ] Entering a query and clicking "Execute Query" (or pressing Enter) triggers real search and updates the result list and hit counter.
- [ ] Clicking any result item reveals detailed event JSON payload.
- [ ] Quick index filters or time range selectors update the query results accordingly.
