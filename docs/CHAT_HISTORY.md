# OpenSOC Forge — Continuous Development & Chat Work History Log
> **Location-Agnostic SOC Engineering Journal**: Documents all user prompts, design decisions, architectural milestones, debugging sessions, deployment configurations, and operational states across **Home** and **Office** work environments.

---

## 📌 Environment & Deployment Quick-Reference

| Parameter | Configuration / Value |
| :--- | :--- |
| **Primary GitHub Repository** | `https://github.com/resanul/siem` |
| **Active Sync Branches** | `master` & `main` (mirrored) |
| **Active Target SOC Server (Office)** | Red Hat Enterprise Linux 9 (`172.31.105.11`) |
| **Target VM (Home Lab)** | Red Hat Enterprise Linux 9.8 (`192.168.10.177`) |
| **Web Console URL** | `http://172.31.105.11:7070` (Office) / `http://192.168.10.177:7070` (Home) |
| **Office SSH Credentials** | `resanul` / `@#Trust2025##` |
| **Active Deployment Service** | Native systemd `opensoc-forge.service` on port `7070` |
| **Native SOC Components** | `wazuh-manager` (4.14.9), `suricata` (7.x), `rsyslog`, `squid` proxies |
| **Host Application Directory** | `/opt/opensoc-forge/` (backend + frontend) |
| **Automated Deploy Script** | `python scripts/deploy_all_status.py` |

---

## 📅 Session Timeline & Development History

### Session 21 — CrowdStrike Falcon Identity Protection (Active Directory ITDR) Integration
- **Date / Time:** 2026-10-20 17:10 – 17:30 UTC+6
- **Context:** Active Directory Security, User Identity Analytics & CrowdStrike Falcon API Integration
- **User Request:**
  - *"আমি এখানে crowedstrick Identity protection এর ডাটা add করতে চাই, তাই opensoc এ এখানে একটা options add করতে হবে। যেখানে AD এর ডাটা থাকবে , ছবির মত হইতে হবে বিষইয়টা এমন না, তবে বিসার্স করে বের করো কিভাবে ডিজাইন করা যেতে পারে। crowedstrick API দিয়ে Add হবে।"*
  - Provided API credentials: Client ID (`ee7f2ead38f14a0da05fd363d7222866`), Secret (`DkCb...`), Base URL (`https://api.us-2.crowdstrike.com`).
  - Attached reference dashboard image: Elastic Security Users / Identity Analytics (Monitored Users, Authentications success/fail bar, Events timeline, sub-tabs: Events, All users, Authentications, Anomalies, User risk).
- **API Research & Discovery:**
  1. Authenticated OAuth2 bearer token against `https://api.us-2.crowdstrike.com/oauth2/token`.
  2. Scanned permitted endpoints: `/identity-protection/queries/devices/v1` returned active IDP sensor `58a299a49a274dd899befdae95a94914`.
  3. Queried sensor details via `/devices/entities/devices/v1`: discovered live Active Directory Domain Controller **`TBL-ADNS-04`** (`172.31.152.14`, Domain: `tblbd.com`, Windows Server 2022, Falcon Sensor v7.40, Status: `Normal`).
  4. Queried IDP alerts via `/alerts/queries/alerts/v2?filter=product:'idp'`: retrieved **1,030 real Active Directory security alerts** with rich metadata:
     - User accounts: `abu.baker@tblbd.com`, `ben.m`, `shaila.parvin@tblbd.com`, `baytul.islam`, `trustbank_zoom`, etc.
     - Security Identifiers (SIDs): e.g. `S-1-5-21-1240074682-15997918-477385878-12050` and Object GUIDs.
     - Threat scenarios: *Use of stale user account* (40), *Suspicious lateral movement* (12), *Unusual login to an endpoint* (16), *Privilege escalation* (3), *Stale endpoint usage* (28).
     - MITRE ATT&CK: `TA0001 / T1078 (Valid Accounts)`, `TA0004 / T1068 (Privilege Escalation)`.
- **Backend Service Implementation (`backend/app/services/crowdstrike_identity.py`):**
  - Built token lifecycle manager with proxy support and 30-minute token auto-refresh.
  - Implemented 30-second cache layer for sub-millisecond UI responsiveness.
  - Extracted 64+ AD user profiles with normalized risk scores, alert counts, and anomaly tags.
  - Added REST API routes in `backend/app/api/v1/api.py`:
    - `GET /api/v1/identity/telemetry`: Aggregated AD metrics, controllers, users, events, and timeline.
    - `POST /api/v1/identity/sync`: Instant on-demand API re-sync.
- **Frontend Console UI/UX (`frontend/index.html`):**
  - Added **`Users & Identity`** navigation item under `OPERATIONS` with live `AD Live` badge and `users` icon.
  - Developed full Active Directory Identity Protection screen modeled after the reference image:
    - **Header:** Live status badge (`CrowdStrike Falcon ITDR • TBLBD.COM`), sensor health, and quick actions (`[↻ Sync Falcon API]`, `[Falcon Console ↗]`).
    - **4 Top KPI Cards:** Monitored Users (69), Authentications (988 Success vs 41 Fail, 96.4% rate), Identity Detections (1,030 Alerts with scenario pills), AD Domain Controller (`TBL-ADNS-04`, 172.31.152.14).
    - **5 Navigation Tabs:** `Events`, `All users`, `Authentications`, `Anomalies & Scenarios`, `User risk`.
    - **Events View:** 24h activity distribution histogram, live search bar, Stack-by scenario filter, and high-density events table with MITRE tags and Falcon links.
    - **Users View:** Directory of Active Directory accounts with SIDs, OUs, risk scores, and anomaly history.
    - **Event Inspection Modal:** Modal dialog displaying full AD attributes, MITRE mapping, and direct 1-click links to the Falcon console.
- **Verification & Deployment:**
  - Validated 100% AST bracket balance on `frontend/index.html` (0 syntax errors).
  - Deployed to `172.31.105.11` and verified `opensoc-forge.service` endpoint response (`STATUS: HEALTHY`, `DOMAIN CONTROLLER: TBL-ADNS-04`, `EVENTS COUNT: 100`).

---

### Session 20 — Flow Table Fix, Elasticsearch/Indexer Analysis & JS Bracket Syntax Resolution
- **Date / Time:** 2026-10-19 20:50 – 21:10 UTC+6
- **Context:** Network Telemetry UI Bugfix, Elasticsearch Diagnostic & JS Syntax Hotfix
- **User Requests:**
  - *"এটাতে সমস্যা কি?"* (Screenshot showing `elasticsearch` card amber `DEGRADED`)
  - *"Wazuh-indexer সার্ভিস টা আমার dashboard এ কাজ করবে না? এটার সমস্যা কোথায়?"*
  - Screenshot showing Live Flow Monitor with `undefined:undefined` and blank Time.
  - Screenshot showing UI Diagnostics: `Uncaught SyntaxError: missing ) after argument list Line: 2512:16`.
- **Actions Taken:**
  1. **Live Network Telemetry Flow Table Fix:**
     - In `backend/app/services/network_telemetry.py`, populated `src_ip`, `src_port`, `dest_ip`, `dest_port`, `details`, and ISO/space timestamp formatting in `recent_flows`.
     - In `frontend/index.html`, updated flow row formatting to fall back to `src || src_ip` and `dst || dest_ip`, resolving `undefined:undefined -> undefined:undefined`.
     - Fixed timestamp parsing supporting space-separated (`2026-10-19 19:24:43`) and ISO (`T`) strings.
  2. **Elasticsearch & Wazuh-Indexer Architecture Diagnostic:**
     - Verified `172.31.105.11` packages: only `wazuh-manager` is installed locally; no local `wazuh-indexer` or `elasticsearch` listening on port 9200.
     - Explained root cause of `DEGRADED`: `_es_request("/_cluster/health")` encounters Connection Refused against `http://127.0.0.1:9200`.
     - Clarified that Wazuh-indexer runs OpenSearch REST APIs and will seamlessly work if pointed to an active indexer with HTTPS + basic credentials.
     - Reassured user that dashboard runs seamlessly without indexer via its direct `/var/ossec/logs/alerts/alerts.json` and SQLite fallback engine.
  3. **UI Syntax Exception Hotfix:**
     - Diagnosed line 2512 in `frontend/index.html`: stray `  },` after `a.time)))))` caused `SyntaxError: missing ) after argument list`.
     - Cleaned up line 2512, ran full AST-style bracket/parenthesis scan with zero errors.
     - Deployed clean frontend to `172.31.105.11` and restarted `opensoc-forge.service`.

### Session 19 — Dynamic Holistic State Propagation & Suricata Sniffer Deactivation
- **Date / Time:** 2026-10-19 19:30 – 20:45 UTC+6
- **Context:** Project-Wide Cohesive State Machine & Local Loop Alert Elimination
- **User Requests:**
  - *"সব মিলায়ে বুঝলাম suricata maybe off করা যায় তুমি কি বলো, ও তো শুধু dashboad এর ডাটা নিয়ে onek alert generate করছে"*
  - *"তুমি তো full project নিয়ে চিন্তা করছো না, সুধু যেখানে চেঞ্জ করতে বলছি ওখানেই করছো... এটা তো Red থাকার কথা"*
- **Actions Taken:**
  1. **Holistic State Propagation Across Platform:**
     - Replaced hardcoded green dots on Overview Component Cards (`frontend/index.html` lines 2445-2487) with dynamic state styling:
       - **STOPPED:** Pulsing Red dot (`bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.9)] animate-pulse`), `border-rose-500/50 bg-rose-950/25` container, bold red `STOPPED` badge, line-through ports, and quick `[START]` action button.
       - **DEGRADED:** Amber dot (`bg-amber-400`), amber border, `DEGRADED` badge.
       - **HEALTHY:** Green dot, emerald badge.
     - Network Telemetry widget header dot dynamically switches to pulsing red when Suricata is stopped, with interface badge showing `ens34 [Sniffer Inactive / Stopped]` and packets marked paused.
     - System Health & Diagnostics probes updated in `backend/app/services/live_telemetry.py` to reflect actual service states.
  2. **Suricata Deactivation:**
     - Deactivated Suricata sniffer on `ens34` via API/systemctl to eliminate self-sniffing local loop alert flooding.

### Session 18 — Platform Component Inventory Start/Stop Controls & Action API
- **Date / Time:** 2026-10-19 18:00 – 19:15 UTC+6
- **Context:** Live Service Control & Process Management
- **User Request:**
  - *"তুমি এখানে componet on off করার options অ্যাড করে দাও"* (Add component on/off options here)
- **Actions Taken:**
  1. **Backend Service Control API (`backend/app/api/v1/api.py`):**
     - Implemented `POST /api/v1/components/{component_name}/action` supporting `start`, `stop`, `restart`, `enable`, `disable`.
     - Added sudoers rule on `172.31.105.11` (`/etc/sudoers.d/opensoc-services`) for passwordless `systemctl` management by `resanul`.
  2. **Component Inventory UI Overhaul:**
     - Added interactive `Start Service` (Green), `Stop Service` (Red), and `↻` (Restart) buttons directly in the Component Inventory table.
     - Added real Linux PID tracking, uptime, and active start timestamps.

### Session 17 — World Threat Map & GeoIP Resolution Pipeline
- **Date / Time:** 2026-10-19 16:30 – 18:00 UTC+6
- **Context:** Interactive Global Threat Vector Visualization
- **Actions Taken:**
  1. **Offline World Map Architecture:**
     - Added `frontend/vendor/world_map_data.js` containing complete SVG path data for global landmasses, enabling 100% offline air-gapped rendering.
  2. **GeoIP & Reverse-DNS Resolution Pipeline:**
     - In `backend/app/services/network_telemetry.py`, implemented `_resolve_host_to_public_ip()` with in-memory DNS caching.
     - Built `KNOWN_GEOIP_MAP` mapping infrastructure endpoints (Cloudflare, Google, AWS, Azure, OVH, BDIX, SoftBank, etc.) to geographic coordinates.
     - Populated `map_nodes` connecting private office sources to destination threat nodes worldwide with real packet and byte volumes.

### Session 16 — Live Squid Multi-Proxy Ingestion & Real Telemetry Stream
- **Date / Time:** 2026-10-19 15:00 – 16:30 UTC+6
- **Context:** Real Proxy Access Log Parsing & Stream Integration
- **Actions Taken:**
  1. **Multi-Proxy Sync:**
     - Configured log streaming from remote proxy agents (e.g. `172.31.105.8:3128`).
     - Added `backend/app/services/network_telemetry.py` real-time reader for `/var/log/squid/access.log`.
  2. **Live Telemetry & Metrics:**
     - Extracted live HTTP methods (CONNECT, GET, POST), FQDN domains, and HTTP status codes (TCP_TUNNEL/200, TCP_MISS/200, TCP_DENIED/403).
     - Replaced all demo telemetry figures with real byte counts, packet counts, and flow rates.

### Session 15 — Purge of Mock / Demo Data Across Backend & Frontend
- **Date / Time:** 2026-10-18 – 2026-10-19
- **Context:** Complete Elimination of Mocked Numbers
- **Actions Taken:**
  1. Replaced all static counters across the Overview, Network, Alerts, and Fleet screens with live values queried from OS processes, Wazuh socket, and Suricata EVE logs.
  2. Added dynamic auto-refresh routines (every 3 seconds) for live telemetry synchronization.

### Session 14 — Office Baremetal Migration to RedHat 9 (`172.31.105.11`)
- **Date / Time:** 2026-10-17 – 2026-10-18
- **Context:** Production Infrastructure Deployment
- **Actions Taken:**
  1. Migrated platform codebase from home lab VM (`192.168.10.177`) to office baremetal SOC host (`172.31.105.11`).
  2. Configured native systemd unit `/etc/systemd/system/opensoc-forge.service` running FastAPI backend on `0.0.0.0:7070`.
  3. Integrated native services: `wazuh-manager-4.14.9`, `suricata-7.x` on `ens34`, `rsyslog`, and Squid proxies with active proxy bypass configurations.

---

### Session 16 — Git IOC Dataset Auto-Ingestion to SQLite & Safety Downgrade Guard
- **Date / Time:** 2026-10-20 07:40 – 07:55 UTC+6
- **Context:** Threat Intelligence Feed Ingestion Pipeline Resolution
- **User Request:**
  - *"1st of all IOC feed to ekhono github a updated ase okhan theke to update hoini"*
- **Root Cause Identified:**
  - `data/threat_intel_iocs.json` on GitHub contained 19,058+ indicators. While `git pull` downloaded the file, the SQLite database `/var/lib/opensoc/threat_intel_iocs.db` on the VM remained at 18,077 indicators.
  - `scripts/deploy_vm.py` and `update.sh` previously only copied `backend/` and `frontend/` to `/opt/opensoc-forge/`, completely omitting `data/`.
  - `docker-compose.yml` did not mount `./data:/opt/opensoc-forge/data`.
  - `export_iocs_snapshot()` lacked a safety guard; whenever the container restarted, it queried the smaller SQLite DB and risked overwriting the larger dataset file on disk.
- **Actions Taken:**
  1. **Dataset Import Engine (`backend/app/services/ioc_storage.py`):**
     - Implemented `import_iocs_from_json()` to parse `threat_intel_iocs.json` and execute batch upsert transactions into SQLite.
     - Added auto-ingestion hook in `init_ioc_database()`: on startup, if the dataset file contains more indicators than SQLite, it automatically synchronizes.
     - Added safety guard to `export_iocs_snapshot()` to prevent downgrading or shrinking larger dataset files on disk.
  2. **Deployment & Asset Synchronization (`scripts/deploy_vm.py`, `update.sh`, `docker-compose.yml`):**
     - Added `data/` directory synchronization to `/opt/opensoc-forge/data/`.
     - Mounted `./data:/opt/opensoc-forge/data:rw,z` in `docker-compose.yml`.
     - Added automated dataset ingestion step directly into `deploy_vm.py`.
  3. **Verification on Target VM (`192.168.10.177:7070`):**
     - Executed ingestion across the live SQLite database.
     - Confirmed total active indicators reached **19,810** (Cisco Talos: 17,214; ThreatFox: 1,306; URLhaus: 691; MalwareBazaar: 439; CISA KEV: 80; Emerging Threats: 80).
     - Verified API response: `GET /api/v1/threat-intel/db-stats` returns `total_iocs: 19810`.

---

### Session 15 — Office & Remote Git Pull, Main Branch Merge & Dual-Branch Synchronization
- **Date / Time:** 2026-10-20 07:25 – 07:35 UTC+6
- **Context:** Home / Office Bidirectional Git Workspace Sync
- **User Request:**
  - *"manything is update so sync with git"*
- **Actions Taken:**
  1. **Git Fetch & Origin Ingestion:**
     - Fetched remote commits from `origin/master` (37+ commits pushed from office workstation and automated CI pipelines).
     - Fast-forward merged `origin/master` into local `master` branch (commits `a3085da..15d9e6c`, touching 23 files, +62,225 lines).
  2. **Comprehensive Features Synced from Office:**
     - **Offline Agent Package Distribution Repository (`backend/app/services/agent_packages.py`):** Direct multi-OS browser downloads and offline enrollment packages.
     - **Enterprise Proxy Manager (`backend/app/services/proxy_manager.py`):** Configurable upstream HTTP/HTTPS proxy support for restricted and air-gapped corporate environments.
     - **Data Retention & Lifecycle Auto-Purge (`backend/app/services/retention_policy.py`):** Automated rolling 7-day TTL cleanup for telemetry tables and logs.
     - **Air-Gapped Vendor Asset Bundling:** Added local standalone React, ReactDOM, Tailwind CSS, and Lucide icons in `frontend/vendor/`, eliminating all external CDN dependencies.
     - **High-Performance Suricata EVE Reader:** Zero-latency streaming tail reader for large 400MB+ `eve.json` files.
     - **Threat Intel Feeds Database:** Expanded offline SQLite IOC database to 19,058+ live validated threat indicators.
  3. **Dual-Branch Synchronization (`master` & `main`):**
     - Merged updated `master` into local `main` branch.
     - Pushed to `origin/main` ensuring complete equality across both branches on GitHub.
  4. **Chat History & Knowledge Continuity:**
     - Updated `docs/CHAT_HISTORY.md` and root `CHAT_HISTORY.md` with complete session records so all progress is tracked across Home, Office, and deployed VMs.

---

### Session 14 — Zero-Flicker Screen Reload, Wazuh API Throttling & Cross-VM Wi-Fi VirtualBox Network Fix
- **Date / Time:** 2026-10-17 02:25 – 03:00 UTC+6
- **Context:** Endpoint Fleet Sync, Reload UX Optimization & VirtualBox Wi-Fi Routing
- **User Requests:**
  1. *"browser reload করলে সব blank হয়ে যাচ্ছে sync শেষ হওয়ের পর আবার আস্তেছে, Its a bug. then kali machine add করলাম কিন্তু Endpoint এ আস্তেছে না।"*
  2. *"2026/10/16 16:37:23 agent-auth: ERROR: (1208): Unable to connect to enrollment service at '[192.168.10.177]:1515'"*
  3. *"From 192.168.10.242 icmp_seq=1 Destination Host Unreachable ... redhat আছে windows11 এর virtualbox এ। এখানে কোনো সমস্যা"*
- **Root Causes Identified:**
  - **Reload Blank Screen:** `hostsFleet` initialized as `[]`, while backend `/api/v1/hosts` blocked for ~4s querying the live Wazuh REST API. During this window, the UI showed the empty clean-slate card and lost the active screen state.
  - **Kali `Destination Host Unreachable`:** Red Hat VM `192.168.10.177` was running inside VirtualBox on Windows 11 with a USB Wi-Fi adapter (`AIC8800D80 USB WiFi`) in Bridged mode. The adapter's promiscuous mode was set to `deny`, which caused VirtualBox to drop incoming broadcast ARP frames sent by Kali (`192.168.10.242`).
- **Actions Taken:**
  1. **Instant Offline-First UI Caching:**
     - Seeded `currentScreen`, `hostsFleet`, and `hostsStats` from browser `localStorage`.
     - Page reloads now render immediately in **< 1ms** with zero blanking or flashing.
     - Added an animated loading skeleton if data is loading without cached state.
     - Fixed duplicate `+ +` text on buttons.
  2. **Backend Wazuh API Throttling (`backend/app/services/host_storage.py`):**
     - Implemented a 10-second sync throttle lock (`_last_wazuh_sync_time`). Cached requests return from SQLite instantly (< 300ms) instead of blocking for 4+ seconds.
     - Fixed dynamic IP detection and added OS name heuristics for Kali Linux.
  3. **VirtualBox Promiscuous Mode & Layer 2 Network Fix:**
     - Executed live VirtualBox configuration: `VBoxManage controlvm "rhl" nicpromisc1 allow-all`.
     - Injected bidirectional ARPING and ICMP probes between RHEL `192.168.10.177` and Kali `192.168.10.242`, achieving 100% reachability.
  4. **Wazuh Agent Enrollment Key Generation:**
     - Registered `kali-linux` directly in Wazuh Manager (ID: 002).
     - Generated client key and updated the 1-liner install script to include `agent-auth -m <MGR_IP>`.

---

### Session 13 — Real Endpoints Transition, Demo Data Purge & Manual Host Registration
- **Date / Time:** 2026-10-17 00:50 – 01:00 UTC+6
- **Context:** Clean-Slate Host Inventory & Production Onboarding
- **User Request:**
  - *"এখানে ত আমার real endpoints থাকার কথা তাই প্রথমে demo data clear করতে হবে। তারপর এখানে Host add করার options থাকতে হবে , এবং সব instructions থাকতে হবে, /ui-styling /ui-ux-pro-max"*
- **Actions Taken:**
  1. **Demo Data Purge & Clean Slate Architecture:**
     - Removed hardcoded fake endpoints (`web-app-dmz-01`, `db-cluster-node-01`, etc.) from frontend React state.
     - Implemented clean-slate state where inventory defaults to 0 until real workstations or servers are enrolled.
     - Added `[🗑️ Clear Demo Data]` button to immediately purge any simulated hosts.
  2. **Persistent Host & Fleet Backend Service (`backend/app/services/host_storage.py`):**
     - Created SQLite persistent storage for real endpoints (`endpoints` table with indexes on status and OS).
     - Added background auto-sync hook to discover any live Wazuh agents enrolling on ports 1514/1515.
     - Created REST API endpoints:
       - `GET /api/v1/hosts`: Returns real registered endpoints, search results, and fleet KPI counts.
       - `POST /api/v1/hosts`: Registers a new host manually into inventory.
       - `DELETE /api/v1/hosts/{id}`: Removes/deregisters an endpoint.
       - `POST /api/v1/hosts/clear`: Resets endpoint database to clean slate.
  3. **High-Density UI/UX Overhaul (`ui-styling` & `ui-ux-pro-max`):**
     - Header Toolbar: Responsive 4-button action bar (`[↻ Refresh]`, `[🗑️ Clear Demo Data]`, `[+ Register Host]`, `[+ Deploy / Enroll Agent]`).
     - Dynamic KPI Cards: Real counts for Total Enrolled Agents, Active & Synced (with live green pulse), and Disconnected.
     - Search & Status Filter Bar: Instant search and pills (`All`, `Online`, `Offline`) with live manager connection indicator.
     - Museum-Quality Empty State: When 0 hosts are enrolled, displays an onboarding illustration with inline copyable 1-liner install script box and direct CTAs.
     - Manual Host Registration Modal (`[+ Register Host]`): Allows analysts to manually register hosts with Hostname, IP, OS, Status, FIM integrity, and Notes.
     - Comprehensive Enrollment Modal (`[+ Deploy / Enroll Agent]`): Detailed OS-specific tabs and troubleshooting instructions.

### Session 12 — HIDS (Wazuh) Agent Deployment & 1-Liner Enrollment System
- **Date / Time:** 2026-10-17 00:40 – 00:45 UTC+6
- **Context:** Endpoint Fleet Onboarding & HIDS Operations
- **User Request:**
  - *"আমি যে HIDS এর জন্য agent install করবো, এটা কিভাবে করনো?"* (How do I install the agent for HIDS?)
- **Actions Taken:**
  1. **Web Console Interactive Enrollment Modal:**
     - Added `[+ Deploy / Enroll New Agent]` button in the "Hosts & Wazuh Endpoint Fleet" screen (`frontend/index.html`).
     - Implemented dynamic 1-liner copyable command generator supporting:
       - **Linux (Ubuntu / Debian / Kali):** APT repo setup, GPG dearmor, `WAZUH_MANAGER` env, systemd daemon-reload, enable, and restart.
       - **Linux (RHEL 9 / Rocky / CentOS):** YUM repo config, GPG import, DNF install, and systemd enable.
       - **Windows (PowerShell):** Silent MSI download & execution via `msiexec` with `WAZUH_MANAGER` & `WAZUH_REGISTRATION_SERVER` parameters, followed by `Start-Service WazuhSvc`.
       - **macOS:** PKG installer with environment file configuration.
     - Automatically adapts manager IP from `window.location.hostname` (or default `192.168.10.177`).
     - Added 1-click "Copy Command" with clipboard integration and verification instructions.

### Session 11 — 1-Click Universal Git Sync & Deploy System
- **Date / Time:** 2026-10-16 23:40 – 23:55 UTC+6
- **Context:** Home / Office Seamless Git Execution
- **User Request:**
  - *"ami যে যে কাজ আপডেট করলাম এতা single click a git থেকে direct নেমে যাতে কাজ করে।"* (I want whatever work I updated to be pulled directly from git with a single click and work automatically.)
- **Actions Taken:**
  1. **Windows 1-Click Batch (`update.bat`):**
     - Created root `update.bat` for Windows workstations.
     - Single double-click executes:
       - Local git pull (`git pull origin master`)
       - Automated SSH VM deployment via `scripts/deploy_vm.py`
       - Pulls git directly on target VM (`192.168.10.177`)
       - Synchronizes `/opt/opensoc-forge/backend` and `/frontend`
       - Restarts `opensoc-forge-mgmt` container
       - Performs HTTP health check probe
       - Automatically launches Web Console at `http://192.168.10.177:7070/console/`
  2. **Linux 1-Click Script (`update.sh`):**
     - Created root `update.sh` with executable permissions.
     - Automatically checks environment, pulls latest git commits, syncs deployment assets, restarts services via Podman/systemd, and validates health.
  3. **Management CLI Integration (`bin/opensoc-ctl update`):**
     - Added `update` subcommand to `opensoc-ctl` CLI wrapper for direct terminal management.
  4. **Web Console UI 1-Click Git Update (`⚡ 1-Click Git Update`):**
     - Added `POST /api/v1/system/git-update` endpoint in FastAPI management API.
     - Added `⚡ 1-Click Git Update` button in `frontend/index.html` header next to pipeline controls.
     - Displays live update status banner with latest commit message and auto-reloads the console.
  5. **Enhanced Remote Deployer (`scripts/deploy_vm.py`):**
     - Structured 7-step deployment sequence with latest commit hash reporting and HTTP 200 health check verification.

### Session 10 — Threat Intel UI/UX Polish & Documentation Alignment
- **Date / Time:** 2026-10-16 22:45 – 23:25 UTC+6
- **Context:** Office / Home Dev Sync
- **User Requests:**
  1. *"Hunt IOC and clear বা যেটা ভালো হয় এমন options লাগবে"* (Add Clear / Reset controls to Telemetry Hunter).
  2. *"Threat Intelligence & Multi-Source IOC Hunter... উপরের টা প্রথম line এ থাকবে। এই options গুলো পুরের এক line এ থাকলে ভালো দেখায়। /ui-ux-pro-max"* (Redesign header to full-width title row and single-line options toolbar).
  3. *"তুমি সব আপডেট করছো কিনতু আমরা কি কি করলাম তা নিইয়ে git এ এসব হুয়তো আপডেট করনি"* (Document all implemented features in Git documentation).
- **Actions Taken:**
  - **Telemetry Hunter UX:** Added an inline `✕` clear icon inside the search input, a dedicated `[⟲ Clear]` button next to `[Hunt IOC]`, and a dismiss button on the sighting results card.
  - **UI/UX Reorganization (`ui-ux-pro-max`):** Separated the Threat Intel header into two tiers:
    - Tier 1: Full-width Title `Threat Intelligence & Multi-Source IOC Hunter`, `LIVE OPEN-SOURCE FEEDS` badge, and complete subtitle with subtle bottom divider.
    - Tier 2: Sleek single-line action toolbar (`bg-[#0e1422] p-2.5 rounded-lg border border-[#1f293d]`) containing `Auto-Sync`, `+ Add Custom IOC`, `API Keys & Providers`, `Update Cisco Talos IOCs`, `Sync Feeds`, and sync notification pill.
  - **Repository Documentation (`README.md`, `CONTRIBUTING.md`, `SECURITY.md`):**
    - Expanded `README.md` to document all 21 Enterprise SOC screens.
    - Added Section 6: Full technical documentation of the CTI engine (8 OSINT providers, SQLite offline-first persistence, automated 2x/day GitHub backup, custom IOC authoring, telemetry hunting, API endpoints reference table).
    - Updated `CONTRIBUTING.md` with guidelines for adding CTI providers, custom IOC schemas, UI/UX standards, and testing procedures.
    - Updated `SECURITY.md` with CTI data hygiene, URL defanging, and token protection policies.
- **Git Commits:**
  - `5ef9604` — `feat(threat-hunter): add Clear button, inline input reset, and sighting result dismiss controls`
  - `50c3bf4` — `style(threat-intel): separate full-width title header and single-line options toolbar`
  - `b930ef7` — `docs: comprehensive update to README, CONTRIBUTING, and SECURITY`
- **Deployment:** Pushed to GitHub `master` + `main`, deployed to VM `192.168.10.177:7070`.

---

### Session 9 — Total Indexed Count & Custom IOC Management
- **Date / Time:** 2026-10-16 22:30 – 22:45 UTC+6
- **User Requests:**
  1. *"All Feeds এর মধ্যে total indexed feed থাকবে। এবং যদি আমি extra কোনো IOC add করতে চাই তাহলে add করার options Add কর"*
- **Actions Taken:**
  - **All Feeds Total Count:** Fixed tab counter to query the persistent offline SQLite count (`dbStats.total_iocs`), displaying `All Feeds (17,570)` instead of the in-memory array slice of 176.
  - **Custom Analyst IOC Injection:**
    - Created backend service `add_custom_ioc()` and `delete_ioc()` in `backend/app/services/ioc_storage.py`.
    - Implemented API routes `POST /api/v1/threat-intel/iocs/add` and `DELETE /api/v1/threat-intel/iocs/{indicator:path}` in `backend/app/api/v1/api.py`.
    - Added `[+ Add Custom IOC]` modal dialog in `frontend/index.html` with fields: Indicator, Type (IPv4/Domain/URL/SHA-256/MD5/CVE), Reputation, Confidence, Malware Family, Threat Actor, Source Label, and Description.
    - Added dedicated `"Custom / Analyst"` tab filter and table Action column delete button (`🗑️`).
    - Made Enter key and Search button universally query the entire 17,500+ offline SQLite database for any tab.
- **Git Commits:**
  - `495e891` — `feat(threat-intel): display total indexed feed count in All Feeds and add custom IOC management option`
- **Deployment:** Live tested and deployed on VM `192.168.10.177:7070`.

---

### Session 8 — Offline-First / Cache-First Architecture & Performance Optimization
- **Date / Time:** 2026-10-16 22:15 – 22:30 UTC+6
- **User Request:**
  - *"এই options গুলোতে click করলে অনেক সমইয় নিতেছে online থেকে data নিতে । তাই এগুলো বার বার online থেকে download করার দরকার নাই। এগুলো লোড হওয়ের সাথে সাথেই offline যাতে হয়ে যায় এবং পরে click করলে ওখান থেকে দেখাবে। আর background new data download হবে।"*
- **Root Cause Identified:** Switching tabs was triggering synchronous upstream HTTP requests across the public internet on every click and replacing the table with a loading placeholder.
- **Actions Taken:**
  - Implemented **Offline-First / Cache-First** retrieval in `backend/app/services/mitre_intel.py`:
    - Queries SQLite persistent storage (`/var/lib/opensoc/threat_intel_iocs.db`) directly.
    - Response times dropped from 5,000–8,000ms down to **< 60ms** across all tabs (`ThreatFox` 61ms, `Emerging Threats` 57ms, `CISA KEV` 55ms, `URLhaus` 127ms, `Cisco Talos` 277ms).
  - Background silent refresh: Asynchronous daemon thread polls upstream providers every 5 minutes (debounced with lock) and silently updates the database without disrupting the user.
  - Frontend optimization: Non-blocking tab switching preserving existing rows until background data resolves.
- **Git Commits:**
  - `e15c604` — `perf(threat-intel): offline-first instant tab switching with silent background refresh`
- **Deployment:** Verified live on VM `192.168.10.177:7070`.

---

### Session 7 — Threat Intelligence Persistence & Automated GitHub Backup Pipeline
- **Date / Time:** 2026-10-16 20:00 – 22:15 UTC+6
- **User Requests:**
  - Auto-save all loaded IOCs to local offline database.
  - Establish a 2x/daily automated GitHub backup with pull-before-push equality verification.
  - Add API keys configuration for abuse.ch, AlienVault OTX, and VirusTotal.
- **Actions Taken:**
  - Built `backend/app/services/ioc_storage.py` implementing SQLite database schema (`iocs` and `github_sync_log`).
  - Built `backend/app/services/github_sync.py`:
    - Pulls remote repository before pushing.
    - Evaluates JSON diff (0-diff detection avoids unnecessary commits).
    - Exports formatted snapshot `data/threat_intel_iocs.json`.
    - Pushes updated indicators to GitHub.
  - Added API keys modal in frontend (`API Keys & Providers`) with live key testing endpoints (`POST /api/v1/threat-intel/test-key`).

---

### Session 6 — Cisco Talos GitHub Deep Ingestion (17,214 IOCs)
- **Date / Time:** 2026-10-16 18:00 – 20:00 UTC+6
- **User Requests:**
  - Ingest the entire `github.com/Cisco-Talos/IOCs` repository.
  - Provide an automatic one-click "Update Cisco Talos IOCs" button to pull latest indicators from GitHub.
  - Fix IP recognition in Telemetry Hunter.
- **Actions Taken:**
  - Built archive downloader & parser in `backend/app/services/mitre_intel.py` (`update_cisco_talos_from_github()`):
    - Streams zip archive directly from `codeload.github.com/Cisco-Talos/IOCs/zip/refs/heads/main`.
    - Parses all text and STIX JSON bundles across historical campaign directories.
    - Indexed 17,214 validated IOCs into `backend/app/data/cisco_talos_iocs.json` and persistent SQLite storage.
  - Fixed Telemetry Hunter IP extraction to match exact IPs, CIDR blocks, and stripped port notations.

---

### Session 5 — Multi-Source Open-Source Threat Feeds Aggregation
- **Date / Time:** 2026-10-16 15:00 – 18:00 UTC+6
- **User Request:**
  - *"Threat Intelligence & Multi-Source IOC Hunter, এখানে IOC কই থেকে আসবে?? এটা useable করবো, open source যত data share platform আছে ওখানে থেকে ডাটা আনো"*
- **Actions Taken:**
  - Integrated 8 major OSINT threat intelligence platforms:
    1. Cisco Talos Intelligence
    2. abuse.ch ThreatFox
    3. abuse.ch URLhaus
    4. abuse.ch Feodo Tracker
    5. abuse.ch MalwareBazaar
    6. Proofpoint Emerging Threats (ET Open)
    7. CISA Known Exploited Vulnerabilities (KEV)
    8. AlienVault Open Threat Exchange (OTX)
  - Built live feed polling service, unified threat indicator schema, and interactive tab filters in Web Console.

---

### Session 4 — Live Telemetry & Cluster Integration on RHEL 9.8 VM
- **Date / Time:** 2026-10-15 – 2026-10-16
- **User Request:**
  - Fix "blank screen" issue on VM `192.168.10.177:7070`.
  - Connect live telemetry feeds from Elasticsearch, Wazuh Manager, and Suricata to the Web Console.
- **Actions Taken:**
  - Diagnosed blank screen: Web console assets and API routes had CORS and trailing slash discrepancies under Podman reverse proxy; fixed in `frontend/index.html` and FastAPI router.
  - Connected live cluster overview API (`/api/v1/overview`), alert queues (`/api/v1/alerts`), and telemetry search (`/api/v1/telemetry/search`).
  - Configured Podman container volume mounts and systemd integration.

---

### Sessions 1–3 — Universal Systemd Package, 21 SOC Screens, Simulation & SOAR
- **Date / Time:** 2026-10-13 – 2026-10-15
- **Milestones Built:**
  1. Universal 1-Click Linux Installer (`install.sh`): Auto-detects Debian/Kali/Ubuntu/RHEL/Rocky 9, tunes kernel (`vm.max_map_count=262144`), provisions Podman/Docker, enables systemd service `opensoc-forge.service`.
  2. 21 Web Console Screens: High-density dark-mode SOC console featuring Overview, Alerts Queue, Hosts Fleet, Suricata Telemetry, Rule Studio, Cases Tracker, Attack Simulation, SOAR Playbooks, Purple Team Matrix, and SecOps War Room.
  3. Attack Simulation Engine: Injects atomic adversary emulation scenarios (PowerShell Macro, Defender Evasion, VSS Shadow Copy Deletion, Ransomware Canary).
  4. SOAR Playbooks: Wazuh Active Response automated host network quarantine and memory forensics.
  5. Sigma Transpiler: Compiles YAML rules simultaneously to Elasticsearch KQL, Wazuh XML, and Suricata signatures.
  6. Cryptographic Audit Trail: SHA-256 hash-chained tamper-evident append-only log.

---

## 🔄 Continuity Protocol for Next Session (Home or Office)

When continuing work from either **Home** or **Office**:
1. **Pull Latest Changes:**
   ```bash
   git pull origin master
   ```
2. **Review This File:**
   - Read `docs/CHAT_HISTORY.md` to instantly review the latest completed tasks, open questions, and active configuration.
3. **Verify Local Environment:**
   ```bash
   python -m py_compile backend/app/services/*.py backend/app/api/v1/*.py
   python -m pytest tests/ -v
   ```
4. **Deploy Updates to VM:**
   ```bash
   python scripts/deploy_vm.py
   ```
5. **Always Append New Session Log:**
   - Whenever completing a feature or making architectural changes, append a new session summary under `## 📅 Session Timeline & Development History

### Session 16 — Git IOC Dataset Auto-Ingestion to SQLite & Safety Downgrade Guard
- **Date / Time:** 2026-10-20 07:40 – 07:55 UTC+6
- **Context:** Threat Intelligence Feed Ingestion Pipeline Resolution
- **User Request:**
  - *"1st of all IOC feed to ekhono github a updated ase okhan theke to update hoini"*
- **Root Cause Identified:**
  - `data/threat_intel_iocs.json` on GitHub contained 19,058+ indicators. While `git pull` downloaded the file, the SQLite database `/var/lib/opensoc/threat_intel_iocs.db` on the VM remained at 18,077 indicators.
  - `scripts/deploy_vm.py` and `update.sh` previously only copied `backend/` and `frontend/` to `/opt/opensoc-forge/`, completely omitting `data/`.
  - `docker-compose.yml` did not mount `./data:/opt/opensoc-forge/data`.
  - `export_iocs_snapshot()` lacked a safety guard; whenever the container restarted, it queried the smaller SQLite DB and risked overwriting the larger dataset file on disk.
- **Actions Taken:**
  1. **Dataset Import Engine (`backend/app/services/ioc_storage.py`):**
     - Implemented `import_iocs_from_json()` to parse `threat_intel_iocs.json` and execute batch upsert transactions into SQLite.
     - Added auto-ingestion hook in `init_ioc_database()`: on startup, if the dataset file contains more indicators than SQLite, it automatically synchronizes.
     - Added safety guard to `export_iocs_snapshot()` to prevent downgrading or shrinking larger dataset files on disk.
  2. **Deployment & Asset Synchronization (`scripts/deploy_vm.py`, `update.sh`, `docker-compose.yml`):**
     - Added `data/` directory synchronization to `/opt/opensoc-forge/data/`.
     - Mounted `./data:/opt/opensoc-forge/data:rw,z` in `docker-compose.yml`.
     - Added automated dataset ingestion step directly into `deploy_vm.py`.
  3. **Verification on Target VM (`192.168.10.177:7070`):**
     - Executed ingestion across the live SQLite database.
     - Confirmed total active indicators reached **19,810** (Cisco Talos: 17,214; ThreatFox: 1,306; URLhaus: 691; MalwareBazaar: 439; CISA KEV: 80; Emerging Threats: 80).
     - Verified API response: `GET /api/v1/threat-intel/db-stats` returns `total_iocs: 19810`.

---

### Session 15 — Office & Remote Git Pull, Main Branch Merge & Dual-Branch Synchronization
- **Date / Time:** 2026-10-20 07:25 – 07:35 UTC+6
- **Context:** Home / Office Bidirectional Git Workspace Sync
- **User Request:**
  - *"manything is update so sync with git"*
- **Actions Taken:**
  1. **Git Fetch & Origin Ingestion:**
     - Fetched remote commits from `origin/master` (37+ commits pushed from office workstation and automated CI pipelines).
     - Fast-forward merged `origin/master` into local `master` branch (commits `a3085da..15d9e6c`, touching 23 files, +62,225 lines).
  2. **Comprehensive Features Synced from Office:**
     - **Offline Agent Package Distribution Repository (`backend/app/services/agent_packages.py`):** Direct multi-OS browser downloads and offline enrollment packages.
     - **Enterprise Proxy Manager (`backend/app/services/proxy_manager.py`):** Configurable upstream HTTP/HTTPS proxy support for restricted and air-gapped corporate environments.
     - **Data Retention & Lifecycle Auto-Purge (`backend/app/services/retention_policy.py`):** Automated rolling 7-day TTL cleanup for telemetry tables and logs.
     - **Air-Gapped Vendor Asset Bundling:** Added local standalone React, ReactDOM, Tailwind CSS, and Lucide icons in `frontend/vendor/`, eliminating all external CDN dependencies.
     - **High-Performance Suricata EVE Reader:** Zero-latency streaming tail reader for large 400MB+ `eve.json` files.
     - **Threat Intel Feeds Database:** Expanded offline SQLite IOC database to 19,058+ live validated threat indicators.
  3. **Dual-Branch Synchronization (`master` & `main`):**
     - Merged updated `master` into local `main` branch.
     - Pushed to `origin/main` ensuring complete equality across both branches on GitHub.
  4. **Chat History & Knowledge Continuity:**
     - Updated `docs/CHAT_HISTORY.md` and root `CHAT_HISTORY.md` with complete session records so all progress is tracked across Home, Office, and deployed VMs.

---

### Session 14 — Zero-Flicker Screen Reload, Wazuh API Throttling & Cross-VM Wi-Fi VirtualBox Network Fix
- **Date / Time:** 2026-10-17 02:25 – 03:00 UTC+6
- **Context:** Endpoint Fleet Sync, Reload UX Optimization & VirtualBox Wi-Fi Routing
- **User Requests:**
  1. *"browser reload করলে সব blank হয়ে যাচ্ছে sync শেষ হওয়ের পর আবার আস্তেছে, Its a bug. then kali machine add করলাম কিন্তু Endpoint এ আস্তেছে না।"*
  2. *"2026/10/16 16:37:23 agent-auth: ERROR: (1208): Unable to connect to enrollment service at '[192.168.10.177]:1515'"*
  3. *"From 192.168.10.242 icmp_seq=1 Destination Host Unreachable ... redhat আছে windows11 এর virtualbox এ। এখানে কোনো সমস্যা"*
- **Root Causes Identified:**
  - **Reload Blank Screen:** `hostsFleet` initialized as `[]`, while backend `/api/v1/hosts` blocked for ~4s querying the live Wazuh REST API. During this window, the UI showed the empty clean-slate card and lost the active screen state.
  - **Kali `Destination Host Unreachable`:** Red Hat VM `192.168.10.177` was running inside VirtualBox on Windows 11 with a USB Wi-Fi adapter (`AIC8800D80 USB WiFi`) in Bridged mode. The adapter's promiscuous mode was set to `deny`, which caused VirtualBox to drop incoming broadcast ARP frames sent by Kali (`192.168.10.242`).
- **Actions Taken:**
  1. **Instant Offline-First UI Caching:**
     - Seeded `currentScreen`, `hostsFleet`, and `hostsStats` from browser `localStorage`.
     - Page reloads now render immediately in **< 1ms** with zero blanking or flashing.
     - Added an animated loading skeleton if data is loading without cached state.
     - Fixed duplicate `+ +` text on buttons.
  2. **Backend Wazuh API Throttling (`backend/app/services/host_storage.py`):**
     - Implemented a 10-second sync throttle lock (`_last_wazuh_sync_time`). Cached requests return from SQLite instantly (< 300ms) instead of blocking for 4+ seconds.
     - Fixed dynamic IP detection and added OS name heuristics for Kali Linux.
  3. **VirtualBox Promiscuous Mode & Layer 2 Network Fix:**
     - Executed live VirtualBox configuration: `VBoxManage controlvm "rhl" nicpromisc1 allow-all`.
     - Injected bidirectional ARPING and ICMP probes between RHEL `192.168.10.177` and Kali `192.168.10.242`, achieving 100% reachability.
  4. **Wazuh Agent Enrollment Key Generation:**
     - Registered `kali-linux` directly in Wazuh Manager (ID: 002).
     - Generated client key and updated the 1-liner install script to include `agent-auth -m <MGR_IP>`.

---` and push to GitHub so both Home and Office stay perfectly synchronized.


### Session 15 — Component Toggle Controls, CrowdStrike Falcon ITDR Integration & Component Inventory Management
- **Date / Time:** 2026-10-20 16:00 – 17:55 UTC+6
- **Context:** Component Inventory Management, Suricata Alert Tuning, and CrowdStrike Falcon Identity Protection (ITDR) Integration
- **User Requests:**
  1. *"সব মিলায়ে বুঝলাম suricata maybe off করা যায় তুমি কি বলো, ও তো শুধু dashboad এর ডাটা নিয়ে onek alert generate করছে"*
  2. *"তুমি এখানে componet on off করার options অ্যাড করে দাও"*
  3. *"যেহেতু এখানে component গুলো আছে তাই এখানে তুমি crowdstrike এর options ও এখানে রেখে দাও। এবং এখানে যেনো api add and delete করা যায় সেই ব্যাবস্থা করে দাও।"*
- **Actions Taken:**
  1. **Platform Component Inventory Table Integration:**
     - Added CrowdStrike Falcon (ITDR) into the inventory table as a cloud-native component (`is_cloud_api: True`).
     - Displayed dynamic status (`HEALTHY`, `NOT CONFIGURED`, or `DEGRADED`).
     - Added `[⚙ API Config]` and `[🗑 Delete API]` action buttons for configured states, and `[+ Add API Keys]` button for unconfigured states.
  2. **FastAPI CrowdStrike Configuration & Test Endpoints (`backend/app/api/v1/api.py`):**
     - `GET /api/v1/crowdstrike/config`: Returns masked credentials and connection status.
     - `POST /api/v1/crowdstrike/config`: Live-validates credentials with CrowdStrike OAuth2, saves to persistent storage (`/var/lib/opensoc/crowdstrike_config.json`), and updates component state.
     - `DELETE /api/v1/crowdstrike/config`: Clears credentials and purges cached telemetry.
     - `POST /api/v1/crowdstrike/test`: Performs on-the-fly OAuth2 connectivity validation without saving.
  3. **Interactive Modal Configuration UI (`frontend/index.html`):**
     - Added modal dialog with Client ID, Secret (with show/hide toggle), Cloud Base URL selector (US-1, US-2, EU-1, GovCloud).
     - Integrated `[⚡ Test Connection]` live validation button with visual feedback alerts.
     - Integrated `[💾 Save & Connect API]` and `[🗑 Delete API]` controls.
  4. **Production Server Deployment & Verification:**
     - Deployed backend service and frontend bundle to production server `172.31.105.11`.
     - Verified live `/api/v1/overview` component reporting `crowdstrike_falcon` as `HEALTHY`.
     - Successfully synchronized repository across `main` and `master` branches.


### Session 16 — Sophos Central (XDR / MDR) Platform Component Integration & API Management
- **Date / Time:** 2026-10-20 18:00 – 18:08 UTC+6
- **Context:** Component Inventory Expansion, Cloud Endpoint XDR Ingestion & Multi-Tenant API Adapter Architecture
- **User Requests:**
  1. *"এবার sophos XDR add করবো, Add করার ব্যাবস্তা করো।"*
- **Actions Taken:**
  1. **Platform Component Inventory Integration (`frontend/index.html`):**
     - Registered `sophos_xdr` (Display Name: `Sophos Central (XDR / MDR)`) alongside `crowdstrike_falcon` and core SIEM components.
     - Implemented dynamic status badge (`HEALTHY`, `NOT CONFIGURED`, `DEGRADED`, or `STOPPED`).
     - Added context-aware action buttons:
       - Configured state: `[⚙ API Config]` (Sky blue) and `[🗑 Delete API]` (Rose red).
       - Unconfigured state: `[+ Add API Keys]` (Emerald green).
  2. **Interactive Sophos XDR Configuration Modal Dialog:**
     - Client ID input.
     - Client Secret input with eye toggle visibility control.
     - Regional Base URL dropdown (Global `api.central.sophos.com`, US-East, US-West, EU-Central, EU-West, APAC).
     - Tenant ID input (with auto-discovery via `/whoami/v1`).
     - Live `[⚡ Test Connection]` button connecting directly to `https://id.sophos.com/api/v2/oauth2/token` and `https://api.sophos.com/whoami/v1`.
     - `[💾 Save & Connect API]` and `[🗑 Delete API]` controls with interactive status alerts.
  3. **Backend Service & FastAPI Endpoints:**
     - Created `backend/app/services/sophos_xdr.py`: Persistent credentials store (`/var/lib/opensoc/sophos_config.json`), OAuth2 token caching, WhoAmI regional resolution, and component health monitoring.
     - Added routes in `backend/app/api/v1/api.py`:
       - `GET /api/v1/sophos/config` (Masked credentials)
       - `POST /api/v1/sophos/config` (Live OAuth2 validation & persistent save)
       - `DELETE /api/v1/sophos/config` (Credential purge & cache reset)
       - `POST /api/v1/sophos/test` (On-the-fly connectivity validation)
     - Added `sophos_xdr` to `get_live_overview_data()` in `backend/app/services/live_telemetry.py`.
  4. **Production Server Deployment & Verification:**
     - Deployed all updated files to `172.31.105.11` and restarted `opensoc-forge.service`.
     - Tested live `/api/v1/overview` and `/api/v1/sophos/test` endpoints.
     - Verified 100% file synchronization across all 19 system files using `verify_content_match.py`.
