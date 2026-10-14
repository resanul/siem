# Tier 5 Adversarial Challenger Report: OpenSOC Forge

**Challenger**: `teamwork_preview_challenger` (Tier 5 White-Box Adversarial Challenger 1)  
**Date**: 2026-10-14T18:12:00Z  
**Verdict**: **FIND GAPS** (Core architecture is robust under load, but 4 specific white-box edge case flaws and vulnerabilities were identified and empirically reproduced)  
**Test Suite Implemented**: `tests/e2e/test_tier5_adversarial_probes.py` (19 test cases, 100% pass rate)

---

## 1. Observation

Direct empirical observations, tool commands, file paths, line numbers, and verbatim outputs:

### 1.1 `install.sh` Observations
1. **Invalid CLI Option Returns Exit Code 0**:
   - File: `install.sh:74-77` & `install.sh:33-55`
   - Code:
     ```bash
     *)
         log_error "Unknown option: $1"
         usage
         ;;
     ```
     Where `usage()` terminates with `exit 0`.
   - Tool Command: `& "C:\Program Files\Git\bin\bash.exe" install.sh --invalid-flag`
   - Output:
     ```
     [ERROR] 2026-10-15 00:02:47 - Unknown option: --invalid-flag
     OpenSOC Forge 1-Click Installer
     ...
     ```
   - Exit Code: `0` (Success). Unrecognized CLI flags fail to signal failure to calling processes.
2. **Preflight Hardware Thresholds**:
   - RAM: `install.sh:144` tests `[ "${MEM_TOTAL_KB}" -lt 7782400 ]`.
     * At 7781376 KB (7599 MB) & 7782399 KB: preflight FAILS.
     * At 7782400 KB (7600 MB) & 8192000 KB (8000 MB): preflight PASSES.
   - Disk: `install.sh:166` tests `[ "${DISK_AVAIL_KB}" -lt 31457280 ]`.
     * At 31457279 KB: preflight FAILS.
     * At 31457280 KB (30 GB): preflight PASSES.
   - CPU: `install.sh:154` tests `[ "${CPU_CORES}" -lt 4 ]`.
     * 1, 2, 3 cores: preflight FAILS.
     * 4 cores: preflight PASSES.
3. **OS Classification & Non-Root Checks**:
   - Non-root without `--dry-run`: exits 1 with `[ERROR] install.sh must be executed as root. Please run with sudo: 'sudo ./install.sh'`.
   - Missing `/etc/os-release`: exits 1 with `[ERROR] /etc/os-release not detected. Unsupported platform.`.
   - Unsupported distros (`arch`, `alpine`, `gentoo`): exits 1 with `[ERROR] Unsupported Linux distribution`.

### 1.2 `bin/opensoc-ctl` Observations
1. **Subcommand Validation**:
   - File: `bin/opensoc-ctl:413-417`
   - Command: `& "C:\Program Files\Git\bin\bash.exe" bin/opensoc-ctl invalid_subcmd`
   - Output: `Error: Unknown subcommand 'invalid_subcmd'` (exits 1).
   - Empty command line (`bin/opensoc-ctl` without arguments) exits 1 and displays usage.
2. **Backup Archive Tampering Detection**:
   - Corrupted Gzip Header: Overwriting the first 64 bytes of `backup.tar.gz` with zeros causes `tar -tzf` and `tarfile.open()` to fail immediately with decompression/archive format errors.
   - Corrupted Payload: Flipping bits in the payload body alters the cryptographic hash (`orig_hash != tampered_hash`), causing `sha256sum -c backup.tar.gz.sha256` to fail with `FAILED`.
3. **Network Resilience & Fallback Inefficiencies in `cmd_test`**:
   - File: `bin/opensoc-ctl:240-242` & `bin/opensoc-ctl:250-253`
   - Line 240 lacks `--connect-timeout 2` (unlike line 103 and line 122). When `API_BASE` points to an unreachable host, `curl` blocks waiting for default connection timeouts (~4-5 seconds) before falling back to local Python adapter test.
   - File: `bin/opensoc-ctl:275`:
     ```bash
     sys.path.insert(0, '${INSTALL_DIR}')
     ```
     If `INSTALL_DIR` contains Windows backslashes (e.g. `C:\Users\USER\...`), Python evaluates it as a truncated `\U` unicode escape, raising `SyntaxError: (unicode error) 'unicodeescape'`. Because stderr is silenced with `2>/dev/null || true`, fallback execution fails silently, and `opensoc-ctl test` exits with code 1.

### 1.3 Synthetic Alert Pipeline Observations
1. **Round-Trip Latency Under Concurrency (SLA < 5000ms)**:
   - Evaluated via `tests/e2e/test_tier5_adversarial_probes.py`:
     * 20 concurrent requests: Mean = 170.68 ms, P95 = 206.01 ms, Max = 206.01 ms.
     * 50 concurrent requests: Mean = 271.33 ms, P95 = 362.62 ms, Max = 367.62 ms.
     * All requests succeeded with HTTP 200 and `passed=True`.
     * Active alerts query `GET /api/v1/alerts` immediately populated and queryable.
2. **Synthetic Event ID Collision Under Concurrency**:
   - File: `adapters/suricata/adapter.py:364`
   - Code:
     ```python
     synthetic_id = f"synth-suri-{int(time.time())}"
     ```
   - When 20 requests were fired concurrently within the same second, `int(time.time())` resolved identically across all requests, yielding 1 unique `synthetic_event_id` instead of 20 unique IDs.
3. **Audit Trail Cryptographic Chain Corruption Under Multi-Process Concurrency**:
   - File: `backend/app/core/audit.py:70-94`
   - Initial run of repo test suite failed: `tests/integration/test_api_endpoints.py::TestAPIEndpoints::test_audit_trail_endpoint` failed with `self.assertTrue(data["chain_integrity_valid"])` -> `False is not true`.
   - Inspection of `configs/audit_log.jsonl` revealed broken chain at line 713 (duplicate `entry_id: 697` following `entry_id: 713`).
   - In `AuditTrail`, `prev_hash` is computed from in-memory `self._entries[-1]` rather than disk locking. When two worker processes or independent test runners append to the log file concurrently, both write stale `prev_hash` and colliding `entry_id`s, breaking `verify_integrity()`.

---

## 2. Logic Chain

1. **Premise**: In Unix CLI conventions and automation tooling, a script encountering unknown/unsupported arguments must exit with a non-zero code to halt deployment.
   - Observation 1.1.1 shows `install.sh` calls `usage()` which executes `exit 0` upon encountering unknown flags.
   - Inference: Automated deployment scripts that misspell flags (e.g. `./install.sh --skip-prefligt`) will fail to apply the option, skip installation, yet return exit code 0, masquerading as success.

2. **Premise**: Backup integrity requires both format and cryptographic verification.
   - Observation 1.2.2 shows header corruption is trapped by gzip/tar unpackers, and payload mutations are trapped by `sha256sum -c`.
   - Inference: The backup architecture reliably prevents corrupt restore operations.

3. **Premise**: CLI operational commands must not hang indefinitely or crash silently on path formatting.
   - Observation 1.2.3 shows `opensoc-ctl test` omits `--connect-timeout` on auth/inject calls, and line 275 unescapes backslashes in Python `sys.path.insert`.
   - Inference: On networks with delayed packet drops or environments with Windows path separators, `opensoc-ctl test` degrades or fails silently.

4. **Premise**: Synthetic event injection must reliably trace distinct test injections and maintain immutable, tamper-evident audit logs.
   - Observation 1.3.1 confirms latency (< 370ms) is well within the 5000ms SLA.
   - Observation 1.3.2 proves second-level timestamping (`int(time.time())`) causes synthetic event ID collisions under concurrency.
   - Observation 1.3.3 proves multi-process concurrent writes to `configs/audit_log.jsonl` cause hash chain desynchronization and broken integrity verification.

---

## 3. Caveats

- Tests were conducted using Git Bash 5.3 on Windows host environment simulating Linux execution paths. Actual kernel cgroup memory limits under container OOM pressure were simulated via mathematical threshold assertions rather than triggering host kernel cgroup OOM kills.
- `install.sh` root privilege checking was validated via non-root execution and `--dry-run`; native `sudo` privilege escalation was not executed directly to prevent mutating host system settings.

---

## 4. Conclusion

**Verdict: FIND GAPS**

The OpenSOC Forge platform demonstrates high computational performance (synthetic event round-trip latency < 370ms vs 5000ms SLA) and strong cryptographic tamper detection for backup archives. However, white-box adversarial stress testing surfaced four (4) specific gaps that require remediation:

1. **CLI Exit Code Anomaly (`install.sh`)**:
   - `install.sh:76`: Calling `usage` on unknown options exits 0. Fix: call `usage >&2; exit 1` or exit non-zero for invalid arguments.
2. **Synthetic Event ID Collision (`adapters/suricata/adapter.py`)**:
   - Line 364: `synthetic_id = f"synth-suri-{int(time.time())}"` collides during concurrent injections. Fix: use `uuid.uuid4().hex[:8]` or `time.time_ns()`.
3. **Missing Connect Timeout & Backslash Path Vulnerability (`bin/opensoc-ctl`)**:
   - Lines 240 & 250: Add `--connect-timeout 2` to `curl` calls.
   - Line 275: Convert `${INSTALL_DIR}` to POSIX forward slashes before injecting into the Python code string.
4. **Audit Trail Multi-Process File Concurrency Race Condition (`backend/app/core/audit.py`)**:
   - `AuditTrail.log()` relies on in-memory `_entries` when calculating `prev_hash` and `entry_id`. Under multi-worker concurrency, writers interleave stale hashes into `configs/audit_log.jsonl`. Fix: apply file-level locks (`fcntl.flock` / `portalocker`) and re-read the last entry's hash from disk prior to appending.

---

## 5. Verification Method

To independently execute and verify the Tier 5 Adversarial Test Suite:

```powershell
# Run the complete Tier 5 White-Box Adversarial Stress Test Suite via Python
python tests/e2e/test_tier5_adversarial_probes.py

# Or execute via pytest
python -m pytest tests/e2e/test_tier5_adversarial_probes.py -v
```

### Direct Reproduction Commands for Gaps:
```bash
# 1. Reproduce install.sh exit code 0 on invalid flag:
"C:\Program Files\Git\bin\bash.exe" install.sh --invalid-flag; echo "Exit Code: $?"

# 2. Reproduce multi-worker audit chain corruption:
python -c "from tests.e2e.test_tier5_adversarial_probes import TestSyntheticPipelineAdversarial; t = TestSyntheticPipelineAdversarial(); t.test_audit_log_multiprocess_corruption_vulnerability()"
```
