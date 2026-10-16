# Contributing to OpenSOC Forge

Thank you for contributing to OpenSOC Forge! OpenSOC Forge is a modular, production-ready SIEM and SOC platform built on principles of architectural safety, offline-first reliability, and strict validation guardrails.

---

## 1. Non-Negotiable Engineering Standards

Before submitting a pull request, ensure your code adheres to:

1. **Adapter Interface**: All component adapters must inherit from `BaseComponentAdapter` in `adapters/base.py` and implement all 17 methods. Never implement an unsupported operation as a silent no-op; return structured `AdapterStatus.UNSUPPORTED` with diagnostic explanation.
2. **Configuration Safety**: Any configuration writer must implement syntax validation before applying changes and must preserve previous working configuration upon validation failure.
3. **No Destructive Reinstalls**: Never write scripts or routines that execute `rm -rf` on data directories or `apt-get purge` without affirmative confirmation tokens (`CONFIRM_DATA_DESTRUCTION`).
4. **Automated Testing**: Every new feature, adapter, endpoint, or detection rule must include automated unit tests in `tests/unit/` or integration tests in `tests/integration/`.
5. **No Plaintext Secrets**: Ensure no credentials, tokens, or private keys are committed. All secrets must be loaded from environment variables or masked via configuration APIs.

---

## 2. Threat Intelligence & IOC Contribution Guidelines

OpenSOC Forge includes an integrated Cyber Threat Intelligence (CTI) engine with offline-first SQLite persistence and automated GitHub synchronization:

- **Adding a New Feed Provider**:
  1. Add the fetch logic to `backend/app/services/mitre_intel.py` with standard timeout (<= 8s) and robust error handling.
  2. Normalize indicators into standard schema (`indicator`, `type`, `reputation`, `confidence`, `threat_actor`, `malware_family`, `source`, `description`).
  3. Wire the provider toggle into `DEFAULT_CONFIG["providers"]` and `load_threat_intel_config()`.
  4. Ensure all fetched feeds persist into `/var/lib/opensoc/threat_intel_iocs.db` via `save_iocs_to_db()`.
- **Custom IOC Authoring**:
  - Always validate input values (strip whitespace, ensure proper indicator type).
  - Supported indicator types: `IPv4`, `IPv6`, `Domain`, `URL`, `SHA-256`, `MD5`, `CVE`.
  - Offline database updates must automatically export a JSON snapshot to `data/threat_intel_iocs.json` for repository backup.

---

## 3. UI/UX Design Standards

We follow modern enterprise SOC UI/UX guidelines:
- **Two-Tier Header Hierarchy**: Primary page titles and status badges occupy the top full-width line; action buttons belong in a cohesive single-line toolbar below.
- **Dark Mode Parity**: Maintain text contrast >= 4.5:1 against dark surfaces (`#080c14`, `#0e1422`, `#131b2e`).
- **No Layout Shifting**: Action states, loading indicators, and hover transitions must not shift adjacent layout bounds.
- **Vector Icons**: Use Lucide SVG icons (`data-lucide="..."`); never use structural emojis for system navigation.

---

## 4. Running Tests & Verification

```bash
# Run the automated pytest suite (33+ tests)
python -m pytest tests/ -v

# Run the OpenSOC CLI status check
python scripts/opensoc_cli.py status

# Run synthetic telemetry integration test
python scripts/opensoc_cli.py test-integration --component suricata

# Verify Python syntax across all modified modules
python -m py_compile backend/app/services/*.py backend/app/api/v1/*.py
```

---

## 5. Git Commit & Pull Request Workflow

1. Create a feature branch: `git checkout -b feat/your-feature-name`.
2. Commit with conventional commit messages (`feat: ...`, `fix: ...`, `perf: ...`, `style: ...`, `docs: ...`).
3. Always verify local tests pass before pushing.
4. Open a pull request against the `master` (or `main`) branch with a clear description and testing evidence.
