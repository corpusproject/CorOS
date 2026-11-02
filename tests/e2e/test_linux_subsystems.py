#!/usr/bin/env python3
"""
CorOS Linux Subsystems E2E Verification Master Suite
====================================================
CorOS/tests/e2e/test_linux_subsystems.py

Executes all 4 tiers of comprehensive opaque-box tests for the 11 Linux subsystems:
- Tier 1: Feature Coverage (F01 - F21, 105 test cases)
- Tier 2: Boundary & Corner Cases (F01 - F21, 105 test cases)
- Tier 3: Cross-Feature Interactions (12 pairwise integration tests)
- Tier 4: Real-World Application Workloads (8 multi-subsystem scenarios)
Total: 230 test cases.
"""

import argparse
import io
import json
import os
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path

# Add tests/e2e to sys.path
E2E_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(E2E_DIR))

from linux_subsystems.test_tier1_feature_coverage import build_suite as build_linux_tier1_suite
from linux_subsystems.test_tier2_boundary_cases import build_suite as build_linux_tier2_suite
from linux_subsystems.test_tier3_cross_feature import build_suite as build_linux_tier3_suite
from linux_subsystems.test_tier4_real_world import build_suite as build_linux_tier4_suite


def get_linux_suites_for_tier(tier: str):
    suites = []
    if tier in ("1", "all"):
        suites.append(build_linux_tier1_suite())
    if tier in ("2", "all"):
        suites.append(build_linux_tier2_suite())
    if tier in ("3", "all"):
        suites.append(build_linux_tier3_suite())
    if tier in ("4", "all"):
        suites.append(build_linux_tier4_suite())
    return suites


def main():
    parser = argparse.ArgumentParser(description="CorOS Linux Subsystems E2E Test Runner")
    parser.add_argument("--tier", choices=["1", "2", "3", "4", "all"], default="all",
                        help="Filter execution by tier (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose per-test output")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    suites = get_linux_suites_for_tier(args.tier)

    if not args.json:
        print("\n" + "=" * 78)
        print("CorOS Linux Subsystems (11 Subsystems / 21 Features) E2E Test Execution".center(78))
        print("=" * 78 + "\n")
        print(f"Target OS: CorOS (x86_64-unknown-uefi pure #![no_std])")
        print(f"Executing Tiers: {args.tier.upper()} ({len(suites)} suites selected)\n")

    t_start = time.time()
    total_passed = 0
    total_failed = 0
    tier_stats = {1: {"passed": 0, "failed": 0},
                  2: {"passed": 0, "failed": 0},
                  3: {"passed": 0, "failed": 0},
                  4: {"passed": 0, "failed": 0}}
    results_detail = {}

    for suite in suites:
        if args.json:
            buf = io.StringIO()
            with redirect_stdout(buf):
                p, f, details = suite.run(verbose=False)
        else:
            p, f, details = suite.run(verbose=args.verbose)

        total_passed += p
        total_failed += f
        tier_stats[suite.tier]["passed"] += p
        tier_stats[suite.tier]["failed"] += f

        results_detail[suite.name] = {
            "tier": suite.tier,
            "passed": p,
            "failed": f,
            "total": p + f,
            "tests": details
        }

    total_elapsed = time.time() - t_start
    total_tests = total_passed + total_failed

    if args.json:
        out = {
            "suites_executed": len(suites),
            "total_tests": total_tests,
            "passed_tests": total_passed,
            "failed_tests": total_failed,
            "duration_sec": total_elapsed,
            "tier_breakdown": tier_stats,
            "suites": results_detail
        }
        print(json.dumps(out, indent=2))
    else:
        print("\n" + "=" * 78)
        print("CorOS Linux Subsystems Test Suite Summary".center(78))
        print("=" * 78)
        print(f"  Tier 1 - Feature Coverage (F01-F21):   {tier_stats[1]['passed']:>3} passed, {tier_stats[1]['failed']:>2} failed")
        print(f"  Tier 2 - Boundaries & Corner Cases:    {tier_stats[2]['passed']:>3} passed, {tier_stats[2]['failed']:>2} failed")
        print(f"  Tier 3 - Cross-Feature Interactions:   {tier_stats[3]['passed']:>3} passed, {tier_stats[3]['failed']:>2} failed")
        print(f"  Tier 4 - Real-World Scenarios:         {tier_stats[4]['passed']:>3} passed, {tier_stats[4]['failed']:>2} failed")
        print(f"  {'-' * 60}")
        print(f"  TOTAL:                                 {total_passed:>3} passed, {total_failed:>2} failed in {total_elapsed:.3f}s")

        if total_failed == 0:
            print(f"\n>>> ALL {total_passed} LINUX SUBSYSTEM TESTS PASSED SUCCESSFULLY! <<<\n")
        else:
            print(f"\n>>> {total_failed} TESTS FAILED! <<<\n")

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
