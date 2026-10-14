## 2026-10-14T18:12:55Z
You are teamwork_preview_worker (Tier 5 Remediation Worker).
Your working directory is `c:\Users\USER\Documents\SIEM\.agents\teamwork\worker_tier5_fix_1`.
You MUST read the authoritative user request at `c:\Users\USER\Documents\SIEM\.agents\teamwork\ORIGINAL_REQUEST.md` before starting work.
You MUST also read `c:\Users\USER\Documents\SIEM\PROJECT.md` and `c:\Users\USER\Documents\SIEM\.agents\teamwork\challenger_tier5_1\handoff.md`.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your task:
Remediate the 4 specific gaps exposed during Tier 5 white-box adversarial stress testing:

1. **`install.sh` invalid flag exit code**:
   - In `install.sh`, modify `usage()` so that it accepts an optional exit code parameter (defaulting to 0 for `--help`, but when invoked for invalid options like `-*`, call `usage 1` or `exit 1`). Ensure invalid flags exit with non-zero exit code 1.

2. **`adapters/suricata/adapter.py` synthetic ID collision under concurrency**:
   - In `integration_test()`, generate `synthetic_id` with microsecond or uuid suffix:
     `f"synth-suri-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"` (import `uuid`), ensuring uniqueness across high-frequency concurrent requests.

3. **`bin/opensoc-ctl` test command curl timeouts and path normalization**:
   - In `bin/opensoc-ctl`, add `--connect-timeout 5 --max-time 10` to all `curl` commands in `test_pipeline()` to avoid hanging indefinitely if the backend is slow or unreachable.
   - In the python fallback runner, ensure path references use forward slashes or raw string escaping for Windows compatibility.

4. **`backend/app/core/audit.py` thread concurrency and hash chain integrity**:
   - Add a `threading.Lock()` to `AuditTrail`.
   - In `log()`, acquire the lock. Read/sync `_last_hash` from the last line of `configs/audit_log.jsonl` if the file exists on disk, compute the SHA-256 hash chaining, append to the file, and release the lock.
   - This ensures concurrent multi-worker logging never writes stale `prev_hash` pointers or desynchronizes the cryptographic chain.

5. **Verification**:
   - Execute the full test suite:
     `python -m pytest tests/`
     `python tests/e2e/e2e_test_runner.py`
   - Verify that all tests pass 100% and that the adversarial suites (`test_tier5_adversarial_probes.py` and `test_tier5_infra_adversarial.py`) pass without failure.
   - Record your fixes and test results in `c:\Users\USER\Documents\SIEM\.agents\teamwork\worker_tier5_fix_1\handoff.md`.
