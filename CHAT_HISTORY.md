# OpenSOC Forge - Unified Chat & Development History Log

> **Single Source of Truth for Cross-Environment Continuity (Home & Office)**  
> Complete detailed journal with all sessions, architecture decisions, VM deployment details, credentials, and continuity protocols is maintained in:  
> **👉 [`docs/CHAT_HISTORY.md`](docs/CHAT_HISTORY.md)**

---

## 📌 Quick Reference for Developers & AI Assistants

### 1. Multi-Environment Topology
- **Home Workstation:** Windows 11 (`c:\Users\USER\Documents\SIEM`), Git repo `resanul/siem` (branches: `master` & `main`).
- **Office Workstation / Secondary PC:** Secondary workstation cloning `resanul/siem`.
- **Target Deployment VM (Current):** RHEL 9.8 VM at `192.168.10.177:7070` (SSH: `resanul` / `1100`).
- **Container Architecture:** Podman containers managed by `systemd` (`opensoc-forge.service`) or `scripts/deploy_vm.py`.

### 2. Switching Between Environments (Office ⟷ Home)
When arriving at the Office or returning Home:
```bash
# 1. Pull latest commits from GitHub
git pull origin master

# 2. Review the session log
cat docs/CHAT_HISTORY.md

# 3. Before leaving Office or Home, always commit and push:
git add .
git commit -m "sync: work progress from <Home/Office>"
git push origin master
git push origin master:main
```

### 3. Comprehensive Session Details
Please read **[`docs/CHAT_HISTORY.md`](docs/CHAT_HISTORY.md)** for:
- Detailed breakdown of all **Sessions 1 through 10**
- Complete CTI Feed integration (8 feeds, SQLite caching, 2x daily sync)
- Threat Hunting & UI/UX enhancements
- VM deployment steps, commands, and container logs
