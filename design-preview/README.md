# OpenSOC Forge — Hybrid SOC Design Preview

This directory contains an isolated, static UI preview of the OpenSOC Forge SOC console.

## Safety boundary
- This preview is separate from `frontend/index.html` and the FastAPI backend.
- It uses local synthetic/demo data only.
- It does not call production API endpoints or perform real response, deployment, backup, restore, or configuration actions.
- All controls that resemble operational actions are simulated and display demo-only feedback.
- This is not an authentication-protected production console. Do not publish real credentials, customer data, internal IP inventories, or operational secrets here.

## Run locally
Open `index.html` directly in a browser, or run:
```bash
python3 -m http.server 8088 --directory design-preview
```
Then visit `http://localhost:8088`.

## Included screens
All 23 existing screen IDs are represented: overview, alerts, search, hosts, network, cases, adversary_sim, bas_testing, purple_team, soar_playbooks, threat_hunting, mitre_heatmap, threat_intel, sigma_studio, rules, reports, inventory, jobs, health, releases, backup, audit, settings.

## Live data integration later
Keep the UI components separate from data access. Replace the local demo collections with an API adapter that:
1. obtains a valid session/token using the application's approved authentication flow;
2. calls the existing `/api/v1` endpoints;
3. normalizes API responses into the view models used by each screen;
4. handles loading, empty, stale, unauthorized and failed states;
5. never treats a browser-side role flag as authorization.

Do not point this static preview at a production API until authentication, CORS, CSP, RBAC and data exposure have been reviewed.

## GitHub Pages
The companion workflow publishes only this directory as a Pages artifact when the branch is pushed, provided GitHub Pages is enabled for the repository with the GitHub Actions deployment source and the workflow has Pages permissions.
