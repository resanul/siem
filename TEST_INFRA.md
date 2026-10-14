# E2E Test Infra: OpenSOC Forge 1-Click Universal Linux Systemd Service Package

## Test Philosophy
- Opaque-box, requirement-driven testing derived directly from `ORIGINAL_REQUEST.md` and `PROJECT.md § Feature Inventory`.
- Independent of internal implementation details; exercises public interfaces (`install.sh`, `systemd/opensoc-forge.service`, `bin/opensoc-ctl`, HTTP/TLS endpoints).
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Interaction Testing + Real-World Workload Testing.
- Progressive testability: Test mechanisms do not require features more complex than what they verify. Tests run cleanly under both standard Python pytest and native command execution.

## Core Requirement Areas & Feature Inventory
| # | Requirement Area | Source | Tier 1 (Min) | Tier 2 (Min) | Tier 3 (Pairwise) |
|---|-----------------|--------|:------------:|:------------:|:-----------------:|
| 1 | R1: Universal Installer (`install.sh`) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 2 | R2: Containerized Data Plane (`docker-compose.yml`) | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 3 | R3: Native Systemd Service (`systemd/opensoc-forge.service`) | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |
| 4 | R4: Network & Security Policy Alignment | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |
| 5 | R5: Self-Contained CLI Wrapper (`bin/opensoc-ctl`) | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ |

## Test Architecture
- **Test Runner**:
  - Primary invocation: `python -m pytest tests/e2e/ -v` or `python tests/e2e/e2e_test_runner.py`
  - Pass/Fail semantics: Exit code 0, 100% assertions pass, zero unexpected errors or timeouts.
- **Directory Layout**:
  - `tests/e2e/test_tier1_feature_coverage.py`: Happy-path feature coverage for all 5 requirement areas (>= 25 test cases).
  - `tests/e2e/test_tier2_boundary_corner.py`: Boundary conditions, invalid inputs, edge cases, out-of-spec parameters (>= 25 test cases).
  - `tests/e2e/test_tier3_cross_feature.py`: Pairwise interactions between installer, systemd, compose, and CLI (>= 10 test cases).
  - `tests/e2e/test_tier4_real_world.py`: Realistic end-to-end operational scenarios (>= 5 scenarios).
  - `tests/e2e/e2e_test_runner.py`: Unified standalone test suite runner with detailed tier reporting.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Clean Cold Install & Auto-Boot Sequence | R1 (Installer), R2 (Compose), R3 (Systemd), R4 (Policies) | High |
| 2 | Automated Failure Recovery & Service Health | R3 (Restart=on-failure), R5 (opensoc-ctl status), R2 (Containers) | High |
| 3 | Multi-Component Backup & Cryptographic Verification | R5 (opensoc-ctl backup), ES Snapshots, SHA-256 verification | Medium |
| 4 | Rapid End-to-End Threat Ingestion & Console Alerting | R5 (opensoc-ctl test), FastAPI, Suricata, React UI (<5s render) | High |
| 5 | Cross-Distribution Migration & Policy Re-Alignment | R1 (OS detection), R4 (firewalld/SELinux vs setcap/UFW) | Medium |

## Coverage Thresholds
- **Tier 1 (Feature Coverage)**: >= 25 test cases (>= 5 per requirement area).
- **Tier 2 (Boundary & Corner Cases)**: >= 25 test cases (>= 5 per requirement area).
- **Tier 3 (Cross-Feature Combinations)**: >= 10 pairwise test cases.
- **Tier 4 (Real-World Application Scenarios)**: >= 5 realistic operational scenarios.
- **Total Minimum Target**: >= 65 E2E test cases.
