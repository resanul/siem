## 2026-10-14T17:20:06Z

You are teamwork_preview_explorer (Survey Container Data Plane & Security Explorer).
Your working directory is `c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_2`.
You MUST read the authoritative user request at `c:\Users\USER\Documents\SIEM\.agents\teamwork\ORIGINAL_REQUEST.md` before starting work.

Your task:
1. Investigate Requirement R2 (All-in-One Containerized Multi-Service Data Plane) and R4 (Cross-Distribution Network & Security Policy Alignment) across Kali Linux / Debian and RHEL 9 / Rocky Linux.
2. Map out the specifications for each of the 6 data plane services:
   - `opensoc-forge-mgmt`: FastAPI Management API & pre-compiled Web Console UI (port 8000).
   - `elasticsearch`: Single-node search & telemetry datastore with TLS enabled (port 9200).
   - `kibana`: Visual data analytics frontend (port 5601).
   - `wazuh-manager`: Endpoint detection, FIM, SCA engine (ports 1514, 1515, 55000).
   - `suricata`: NIDS in host networking mode with AF_PACKET packet capture.
   - `syslog-collector`: RFC 5424/3164 log receiver (ports 514/udp, 6514/tcp TLS).
3. Investigate the security & policy requirements:
   - Capabilities (`setcap cap_net_raw,cap_net_admin+eip` or container cap_add: NET_ADMIN, NET_RAW) on Debian/Kali.
   - Firewalld service/port configuration on RHEL/Rocky (ports 8000, 5601, 9200, 1514, 514, etc.).
   - SELinux policies (`container_manage_cgroup`, container volume labels `:z` / `:Z`).
   - Compose file structure supporting both Docker Compose and Podman Compose.
4. Record your findings in `c:\Users\USER\Documents\SIEM\.agents\teamwork\explorer_survey_2\handoff.md` following the Handoff Protocol.
5. When finished, send a message to the caller with a summary and reference to your handoff report.
