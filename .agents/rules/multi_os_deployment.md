# OpenSOC Forge - Universal Linux Service Packaging Standards

1. **Multi-Distribution Support**:
   - Installers and systemd unit generators must explicitly test and branch for both:
     - APT-based systems: Kali Linux, Debian 12, Ubuntu 22.04 LTS.
     - RPM/DNF-based systems: Red Hat Enterprise Linux 9, Rocky Linux 9, AlmaLinux 9.
   - Detect OS family via `/etc/os-release` (`ID_LIKE` and `ID`).

2. **1-Click Systemd Service Deployment**:
   - The entire stack must install and register as systemd units:
     - `opensoc-forge.service`: Management Plane and Web Console
     - `wazuh-manager.service`: Endpoint Security Engine
     - `suricata.service`: Network Intrusion Detection
     - `elasticsearch.service` & `kibana.service`: Data Storage & Search
   - Units must enable on boot and provide unified control: `systemctl start/stop/status opensoc-forge`.

3. **Frontend Pre-Compilation**:
   - Web console HTML files must contain pre-compiled pure JavaScript rather than in-browser runtime Babel transpilation to eliminate CSP blocking and runtime parser overhead.
