#!/usr/bin/env bash
# ==============================================================================
# OpenSOC Forge - 1-Click Universal Linux Git Updater
# Automatically pulls the latest code from GitHub and reloads the platform.
# ==============================================================================
set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================================================${NC}"
echo -e "${GREEN}  OpenSOC Forge — 1-Click Git Update & Service Reload${NC}"
echo -e "${BLUE}================================================================================${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}"

# 1. Pull latest commits from GitHub
if [ -d "${REPO_DIR}/.git" ]; then
    CURRENT_BRANCH=$(git -C "${REPO_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    echo -e "\n${YELLOW}[1/4] Pulling latest commits from GitHub (origin/${CURRENT_BRANCH})...${NC}"
    git -C "${REPO_DIR}" pull origin "${CURRENT_BRANCH}" || git -C "${REPO_DIR}" pull origin main || git -C "${REPO_DIR}" pull origin master
    LATEST_COMMIT=$(git -C "${REPO_DIR}" log -1 --pretty=format:'%h - %s (%cr)')
    echo -e "${GREEN}[OK] Latest Commit: ${LATEST_COMMIT}${NC}"
else
    echo -e "${RED}[ERROR] ${REPO_DIR} is not a git repository.${NC}"
    exit 1
fi

# 2. Sync to /opt/opensoc-forge if repo is in a user directory (like /home/resanul/siem)
if [ -d "/opt/opensoc-forge" ] && [ "${REPO_DIR}" != "/opt/opensoc-forge" ]; then
    echo -e "\n${YELLOW}[2/4] Syncing application files to /opt/opensoc-forge/...${NC}"
    if [ "$(id -u)" -eq 0 ]; then
        cp -rf "${REPO_DIR}/backend" /opt/opensoc-forge/
        cp -rf "${REPO_DIR}/frontend" /opt/opensoc-forge/
        chown -R resanul:resanul /opt/opensoc-forge/backend /opt/opensoc-forge/frontend 2>/dev/null || true
    else
        sudo cp -rf "${REPO_DIR}/backend" /opt/opensoc-forge/
        sudo cp -rf "${REPO_DIR}/frontend" /opt/opensoc-forge/
    fi
    echo -e "${GREEN}[OK] Files synchronized to /opt/opensoc-forge/${NC}"
else
    echo -e "\n${YELLOW}[2/4] Running directly inside deployment root.${NC}"
fi

# 3. Reload Container / Systemd Service
echo -e "\n${YELLOW}[3/4] Restarting OpenSOC Forge Management Service...${NC}"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active opensoc-forge >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        podman restart opensoc-forge-mgmt 2>/dev/null || systemctl restart opensoc-forge
    else
        sudo podman restart opensoc-forge-mgmt 2>/dev/null || sudo systemctl restart opensoc-forge
    fi
elif command -v podman >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        podman restart opensoc-forge-mgmt
    else
        sudo podman restart opensoc-forge-mgmt
    fi
elif command -v docker >/dev/null 2>&1; then
    docker restart opensoc-forge-mgmt
fi
echo -e "${GREEN}[OK] Management service restarted!${NC}"

# 4. Verify Health
# 4. Verify Health
echo -e "\n${YELLOW}[4/4] Verifying platform health check...${NC}"
sleep 3
HEALTH_OK=false
DETECTED_PORT=8000

for i in {1..12}; do
    if curl -s -f http://127.0.0.1:8000/ >/dev/null 2>&1; then
        HEALTH_OK=true
        DETECTED_PORT=8000
        break
    elif curl -s -f http://127.0.0.1:7070/ >/dev/null 2>&1; then
        HEALTH_OK=true
        DETECTED_PORT=7070
        break
    fi
    echo -n "."
    sleep 1
done

HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

if [ "$HEALTH_OK" = true ]; then
    echo -e "\n${GREEN}================================================================================${NC}"
    echo -e "${GREEN}  SUCCESS: OpenSOC Forge is LIVE and updated!${NC}"
    echo -e "  Web Console   : ${BLUE}http://${HOST_IP}:${DETECTED_PORT}/console/${NC}"
    echo -e "  Latest Commit : ${LATEST_COMMIT}"
    echo -e "${GREEN}================================================================================${NC}"
else
    echo -e "\n${YELLOW}[WARN] Services are still initializing. Please verify:${NC}"
    echo -e "  Web Console: http://${HOST_IP}:${DETECTED_PORT}/console/"
fi
