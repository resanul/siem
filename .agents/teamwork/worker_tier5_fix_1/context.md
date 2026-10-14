# Context for Worker Tier 5 Fix
- Project Root: c:\Users\USER\Documents\SIEM
- Working Directory: c:\Users\USER\Documents\SIEM\.agents\teamwork\worker_tier5_fix_1
- Original Request: c:\Users\USER\Documents\SIEM\.agents\teamwork\ORIGINAL_REQUEST.md
- Scope Document: c:\Users\USER\Documents\SIEM\PROJECT.md
- Challenger 1 Gap Report: c:\Users\USER\Documents\SIEM\.agents\teamwork\challenger_tier5_1\handoff.md
- Challenger 2 Gap Report: c:\Users\USER\Documents\SIEM\.agents\teamwork\challenger_tier5_2\handoff.md
- Specific Gaps to Remediate:
  1. `install.sh`: Invalid CLI flags must exit with code 1 instead of 0 (`usage 1` or `exit 1`).
  2. `adapters/suricata/adapter.py`: Include sub-second timestamp or UUID in `synthetic_id` (`f"synth-suri-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"`) to prevent collision under high concurrency.
  3. `bin/opensoc-ctl`: Add `--connect-timeout 5 --max-time 10` to curl commands in `opensoc-ctl test`, and escape/normalize Windows paths in the python fallback runner.
  4. `backend/app/core/audit.py`: Implement thread lock (`threading.Lock()`) around `log()` and reload/sync `_entries` / `_last_hash` from the audit log file to prevent hash-chain desynchronization under concurrent multi-threaded writes.
