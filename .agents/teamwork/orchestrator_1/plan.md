# OpenSOC Forge 1-Click Universal Linux Systemd Service Package Plan

## Objective
Deliver an enterprise-grade, universal 1-click Linux systemd service package for OpenSOC Forge across Kali Linux/Debian and RHEL 9/Rocky Linux, satisfying R1-R5 and all acceptance criteria in demo integrity mode.

## Phases
1. **Phase 0: Survey & Discovery (Parallel Explorers)**
   - Explorer 1: Inspect existing repository layout, backend, frontend, adapters, configs, and scripts to understand existing components and assets.
   - Explorer 2: Analyze container requirements, compose topology (Elasticsearch, Kibana, Wazuh Manager, Suricata host networking, syslog-collector, opensoc-forge-mgmt), port allocations, and healthchecks.
   - Explorer 3: Investigate cross-distribution systemd integration, install.sh provisioning logic (APT/DNF preflights, sysctl, capabilities, firewalld, SELinux), and opensoc-ctl CLI requirements.

2. **Phase 1: Architecture, PROJECT.md, and TEST_INFRA.md**
   - Synthesize survey findings into PROJECT.md (Architecture, Feature Inventory, Milestones, Interface Contracts, Code Layout).
   - Establish E2E Testing Track architecture in TEST_INFRA.md.

3. **Phase 2: E2E Testing Track Execution**
   - Implement opaque-box automated test harness covering Tiers 1-4.
   - Publish TEST_READY.md.

4. **Phase 3: Implementation Track Execution**
   - Milestone 1: Multi-Service Container Data Plane (`docker-compose.yml`, `podman-compose.yml`, container configs, health checks).
   - Milestone 2: Universal 1-Click Installer (`install.sh`, preflights, OS detection, kernel tuning, container engine setup).
   - Milestone 3: Native Systemd Service & Policy Alignment (`systemd/opensoc-forge.service`, SELinux, firewalld, Linux capabilities).
   - Milestone 4: Management CLI Wrapper (`bin/opensoc-ctl`, status, logs, backup, synthetic pipeline test).

5. **Phase 4: Final Milestone (Integration & Hardening)**
   - Phase 1: Pass 100% of E2E test cases across Tiers 1-4.
   - Phase 2: Adversarial Coverage Hardening (Tier 5) with Challengers & Reviewers.
   - Forensic Integrity Audit verification.

6. **Phase 5: Final Delivery**
   - Synthesize handoff report, verify zero integrity violations, message Sentinel for independent Victory Audit.
