session_22_text = '''### Session 22 — RSA NetWitness SIEM Integration (Cluster Discovery, OAuth2/STOMP Protocol, Live Logs & Network Telemetry Sync)
- **Date / Time:** 2026-10-25 12:40 – 13:20 UTC+6
- **Context:** Historical SIEM Ingestion, RSA NetWitness Platform 12.5.1.3 Integration, Live Core Services Telemetry
- **User Request:**
  - *"amader previous siem er data ki ekhane neOya possible?? sobite netwitness siem er Services"*
  - *"tmi ki amar netwitness a login kore check kore dekhbe?"*
  - *"Web UI https://172.31.101.34/login username: resanul pass: CF!WF*$zRvAKh*R7Pv^9"*
  - *"তুমি বোঝার চেষ্টা করছো না আমি একটা enterprise grade software বানাচ্ছি, যত সুন্দর ভাবে ডাটা দেখানো যাবে তত ভালো।"*
  - *"Browser reload করলে ডাটা চলে যায়, আবার নতুন করে load হয়। আমি না সাত দিনের রিটেনশন দিয়েছিলাম। ডাটা আসবে sync হয়ে থাকবে।"*
- **Reverse-Engineering & Protocol Discovery:**
  1. Verified intranet subnet routing (`172.31.105.11` to `172.31.101.34-41`): zero packet loss, active TLS ports 443, 56003, 56005, 56002, 56004, 56008.
  2. Inspected Nginx web application at `https://172.31.101.34`:
     - Discovered Spring Security / OAuth2 password grant endpoint at `/oauth/token`.
     - Authenticated with user `resanul`: retrieved Bearer JWT with `Administrators` authority role and `X-CSRF-TOKEN`.
     - Analyzed single-page Ember application bundle `/assets/sa-b66914c774bf3289f032e8a1edc2b3a1.js` and `/assets/vendor-4f020a8b93148d2e745abf3a89c72c59.js`.
     - Discovered `socketRoutes` environment: NetWitness communicates via Spring WebSocket STOMP over SockJS (`/api/investigate/socket`, `/api/administration/socket`, `/api/respond/socket`).
  3. Reverse-engineered STOMP handshake & message contracts:
     - Established WebSocket connection to `wss://172.31.101.34/api/investigate/socket/000/<sid>/websocket`.
     - Provided headers: `X-CSRF-TOKEN`, `authorization: Bearer <token>`, and session cookies.
     - Queried `/ws/investigate/endpoints` and retrieved the complete enterprise cluster topology (all 6 nodes running version **12.5.1.3**):
       - `RSA-SIEM-SA01 - Broker`: `172.31.101.34:56003` (TLS) [Head Node]
       - `Log-Concentrator01 - Concentrator`: `172.31.101.36:56005` (TLS) [52.9B Sessions Index]
       - `Log-Decoder01 - Log Decoder`: `172.31.101.37:56002` (TLS) [Real-time Syslog & Windows Parser]
       - `Network-Concentrator01 - Concentrator`: `172.31.101.38:56005` (TLS) [2.37B Network Streams]
       - `Network-Decoder01 - Decoder`: `172.31.101.39:56004` (TLS) [Full Packet Capture L7]
       - `Archiver01 - Archiver`: `172.31.101.41:56008` (TLS) [Compliance Cold Archive]
  4. Streamed live telemetry from Concentrators:
     - Log Concentrator: Queried `/ws/investigate/events/count` (100,000+ indexed events in 24 hours alone).
     - Streamed real log events via `/ws/investigate/events/stream`: captured `winevent_nic` (Windows hosts), `ciscorouter` (Cisco network devices), `snort` (IDS) with 55 rich meta keys (`device.ip`, `ip.src`, `ip.dst`, `user.src`, `msg.id`, etc.).
     - Streamed network sessions from Network Concentrator: captured Layer 7 protocols, MAC addresses, Cisco vendors, DHCPv6, and `community.id` (`1:y6y1dNUVxsL+Khq8x3xCiRo6VpM=`).
- **Backend Implementation:**
  - Created `backend/app/services/netwitness_siem.py`:
    - Full `NetWitnessClient` with automatic OAuth2 token caching, CSRF extraction, and STOMP-over-WebSocket client.
    - Added disk persistence (`configs/netwitness_synced_events.json`) ensuring data remains persistent across reloads.
  - Updated `backend/app/services/event_search.py`:
    - Integrated synced NetWitness events directly into unified search under indices `netwitness-logs` and `netwitness-network`.
  - Added REST API routes in `backend/app/api/v1/api.py`:
    - `GET /api/v1/netwitness/status`: Returns cluster topology, node health, versions, and connection state.
    - `GET /api/v1/netwitness/events`: Live streaming of log or network events with filters, sorting, and pagination.
    - `GET /api/v1/netwitness/count`: Time-range indexed event count.
    - `POST /api/v1/netwitness/sync`: Ingests and synchronizes live events from NetWitness into OpenSOC Forge.
- **Frontend Console UI/UX (`frontend/index.html`):**
  - Added **`RSA NetWitness SIEM`** navigation item under `OPERATIONS` with `12.5 Live` badge and `database` icon.
  - Implemented comprehensive NetWitness Console Screen:
    - Header with live connection status pill (`● 6/6 NODES ONLINE`), `Sync NetWitness Data` button, and `Refresh` button.
    - Top 4 KPI metric cards: Cluster Topology (6 Nodes), Log Sessions (100,000+ / 52.9B), Network Sessions (2.37B), Integration Protocol (OAuth2 + STOMP).
    - Cluster Topology Grid displaying 6 interactive node cards with host IP, TLS ports, roles, and version 12.5.1.3.
    - Telemetry Explorer with sub-tabs for Log Concentrator vs Network Concentrator.
    - Multi-column sorting (ascending/descending on Session ID, Timestamp, Device Type, Device IP), search bar, and device type dropdown filter.
    - Full Meta Keys Inspector slide-over modal displaying all 55 extracted NetWitness meta keys for any selected event.
  - Verified DOM stability with headless Microsoft Edge and deployed to production server `172.31.105.11:7070`.

'''

for path in ["CHAT_HISTORY.md", "docs/CHAT_HISTORY.md"]:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    target = "### Session 21"
    if "Session 22" not in content:
        content = content.replace(target, session_22_text + "\n" + target, 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated {path} successfully!")
    else:
        print(f"{path} already updated.")
