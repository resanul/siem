# BRIEFING — 2026-10-14T17:27:00Z

## Mission
Investigate and map complete technical specifications for R2 (All-in-One Containerized Multi-Service Data Plane) and R4 (Cross-Distribution Network & Security Policy Alignment) across Kali/Debian and RHEL 9/Rocky Linux.

## 🔒 My Identity
- Archetype: explorer
- Roles: survey container data plane & security explorer
- Working directory: c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_2
- Original parent: 8e4247d4-e296-4f7a-92db-58f802e3410e
- Milestone: Phase 0 - Survey & Discovery for R2 & R4

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Cross-distro support: Kali Linux / Debian (APT) and RHEL 9 / Rocky Linux 9 (DNF/RPM)
- Container runtime compatibility: Docker Compose and Podman Compose
- Security & policy alignment: SELinux booleans/labels, firewalld rules, Linux capabilities

## Current Parent
- Conversation ID: 8e4247d4-e296-4f7a-92db-58f802e3410e
- Updated: 2026-10-14T17:20:06Z

## Investigation State
- **Explored paths**:
  - `backend/app/main.py` (FastAPI backend + static Web Console mounting at `/console`)
  - `frontend/index.html` (147KB pre-compiled Web Console UI with React/Tailwind)
  - `adapters/elastic/adapter.py`, `adapters/wazuh/adapter.py`, `adapters/suricata/adapter.py`, `adapters/syslog/adapter.py`
  - `compatibility/matrix.yaml` (ES 7.17.24, Kibana 7.17.24, Wazuh 4.8.2, Suricata 7.0.6)
  - `orchestration/ansible/` playbooks and roles
  - Existing tests: 44/44 tests passed with `python -m pytest`
- **Key findings**:
  - Service parameters, ports, volumes, healthchecks, and environment variables mapped for all 6 data plane services.
  - Suricata requires `network_mode: "host"` with `cap_add: [NET_ADMIN, NET_RAW]`.
  - Compose compatibility across Docker Compose and Podman Compose requires explicit bridge network `opensoc-net` for non-host services and `--in-pod 0` / standalone container mode in Podman.
  - SELinux requires `:z` (lowercase) on shared mounts (`/var/log/suricata`, `/etc/opensoc/certs`), `container_manage_cgroup=1`, `container_use_devices=1`.
  - Firewalld on RHEL 9 / Rocky 9 requires opening 10 ports across TCP (8000, 5601, 9200, 1514, 1515, 55000, 514, 6514) and UDP (1514, 514), either via dedicated service XML or CLI.
  - Kali/Debian requires `setcap cap_net_raw,cap_net_admin+eip`, promiscuous mode, and offload disablement.
- **Unexplored areas**: None within R2 & R4 survey scope; ready for Phase 1 architecture synthesis.

## Key Decisions Made
- Fully documented 6-service matrix, container networking diagram, SELinux policy, and firewalld specification in `handoff.md`.
- Recommended single unified `docker-compose.yml` (and symlink `podman-compose.yml`) utilizing `:z` volume flags.

## Artifact Index
- `c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_2\DISPATCH.md` — Initial dispatch message
- `c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_2\BRIEFING.md` — Persistent briefing
- `c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_2\progress.md` — Heartbeat and status
- `c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_2\handoff.md` — Comprehensive 5-component handoff report
