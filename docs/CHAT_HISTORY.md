# OpenSOC Forge — Continuous Development & Chat Work History Log
> **Location-Agnostic SOC Engineering Journal**: Documents all user prompts, design decisions, architectural milestones, debugging sessions, deployment configurations, and operational states across **Home** and **Office** work environments.

---

## 📌 Environment & Deployment Quick-Reference

| Parameter | Configuration / Value |
| :--- | :--- |
| **Primary GitHub Repository** | `https://github.com/resanul/siem` |
| **Active Sync Branches** | `master` (default) & `main` (mirrored) |
| **Current Target VM** | Red Hat Enterprise Linux 9.8 (`192.168.10.177`) |
| **Web Console URL** | `http://192.168.10.177:7070` |
| **VM SSH Credentials** | `resanul` / `1100` |
| **Container Engine** | Podman (`opensoc-forge-mgmt`, `elasticsearch`, `kibana`, `wazuh-manager`, `suricata`, `syslog-collector`) |
| **Host Application Directory** | `/opt/opensoc-forge/` (backend + frontend) |
| **Persistent CTI Database** | `/var/lib/opensoc/threat_intel_iocs.db` (SQLite, 17,500+ IOCs) |
| **Automated Deploy Script** | `python scripts/deploy_vm.py` |

---

## 📅 Session Timeline & Development History

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
   - Whenever completing a feature or making architectural changes, append a new session summary under `## 📅 Session Timeline & Development History` and push to GitHub so both Home and Office stay perfectly synchronized.
