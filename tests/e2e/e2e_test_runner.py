#!/usr/bin/env python3
"""
OpenSOC Forge E2E Test Runner.
Executes the comprehensive 4-tier E2E test suite:
- Tier 1: Feature Coverage (R1 - R5 Happy Path)
- Tier 2: Boundary & Corner Cases (R1 - R5 Boundary & Error Conditions)
- Tier 3: Pairwise Cross-Feature Interactions
- Tier 4: Real-World Operational Scenarios

Usage:
    python tests/e2e/e2e_test_runner.py
"""

import os
import sys
import time
import unittest
from typing import Dict, Any, List

# Ensure repository root is on PYTHONPATH
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.e2e.test_tier1_feature_coverage import TestTier1FeatureCoverage
from tests.e2e.test_tier2_boundary_corner import TestTier2BoundaryCorner
from tests.e2e.test_tier3_cross_feature import TestTier3CrossFeature
from tests.e2e.test_tier4_real_world import TestTier4RealWorld


TIER_CONFIGS = [
    {
        "id": "Tier 1",
        "name": "Feature Coverage (Happy Path)",
        "test_class": TestTier1FeatureCoverage,
        "req_min": 25,
        "scope": "R1 through R5 primary requirement verification",
    },
    {
        "id": "Tier 2",
        "name": "Boundary & Corner Cases",
        "test_class": TestTier2BoundaryCorner,
        "req_min": 25,
        "scope": "Thresholds, out-of-spec params, negative & error handling",
    },
    {
        "id": "Tier 3",
        "name": "Pairwise Cross-Feature Interactions",
        "test_class": TestTier3CrossFeature,
        "req_min": 10,
        "scope": "Installer, systemd, compose, CLI, policies, and API interactions",
    },
    {
        "id": "Tier 4",
        "name": "Real-World Operational Scenarios",
        "test_class": TestTier4RealWorld,
        "req_min": 5,
        "scope": "Cold install, failure recovery, backup integrity, threat ingestion",
    },
]


def run_tier(tier_info: Dict[str, Any]) -> Dict[str, Any]:
    """Runs a single test tier and captures execution metrics."""
    suite = unittest.TestLoader().loadTestsFromTestCase(tier_info["test_class"])
    runner = unittest.TextTestRunner(verbosity=1, stream=open(os.devnull, "w"))

    t0 = time.time()
    result = runner.run(suite)
    elapsed = time.time() - t0

    return {
        "id": tier_info["id"],
        "name": tier_info["name"],
        "req_min": tier_info["req_min"],
        "total": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "elapsed": round(elapsed, 3),
        "success": result.wasSuccessful(),
    }


def main() -> int:
    print("=" * 78)
    print("       OPENSOC FORGE E2E TEST RUNNER - 4-TIER VERIFICATION SUITE       ")
    print("=" * 78)
    print(f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"Workspace: {REPO_ROOT}\n")

    results = []
    total_run = 0
    total_passed = 0
    total_failures = 0
    total_errors = 0
    total_start = time.time()

    for tier in TIER_CONFIGS:
        print(f"[*] Executing {tier['id']}: {tier['name']}...")
        res = run_tier(tier)
        results.append(res)
        total_run += res["total"]
        total_passed += res["passed"]
        total_failures += res["failures"]
        total_errors += res["errors"]
        status_str = "[PASS]" if res["success"] else "[FAIL]"
        print(f"    {status_str} Ran {res['total']} tests in {res['elapsed']:.2f}s "
              f"({res['passed']} passed, {res['failures']} failed, {res['errors']} errors)")

    total_elapsed = time.time() - total_start

    print("\n" + "=" * 78)
    print("                         E2E TIER RESULTS SUMMARY                      ")
    print("=" * 78)
    header = f"{'Tier':<8} | {'Name':<35} | {'Min Req':<8} | {'Ran':<5} | {'Pass':<5} | {'Status':<6}"
    print(header)
    print("-" * 78)

    all_passed = True
    for r in results:
        status_label = "PASS" if r["success"] and r["passed"] >= r["req_min"] else "FAIL"
        if status_label != "PASS":
            all_passed = False
        print(f"{r['id']:<8} | {r['name']:<35} | {r['req_min']:<8} | {r['total']:<5} | {r['passed']:<5} | {status_label:<6}")

    print("-" * 78)
    total_status = "PASS" if all_passed and total_failures == 0 and total_errors == 0 else "FAIL"
    print(f"{'TOTAL':<8} | {'All Tiers Combined':<35} | {'65':<8} | {total_run:<5} | {total_passed:<5} | {total_status:<6}")
    print("=" * 78)
    print(f"Overall Duration: {total_elapsed:.2f}s")
    print(f"Final Outcome:    {total_status} (Success Rate: {(total_passed / total_run * 100):.1f}%)\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
