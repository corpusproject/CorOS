#!/usr/bin/env python3
"""
CorOS End-to-End Test Suite Master Runner
=========================================
CorOS/tests/e2e/run_e2e_tests.py

Autonomous, zero-dependency test runner executing Tiers 1-4:
- Tier 1: Feature Coverage (F01 - F32, >= 160 test cases)
- Tier 2: Boundary & Corner Cases (F01 - F32, >= 160 test cases)
- Tier 3: Cross-Feature Interactions (6 pairwise subsystem suites)
- Tier 4: Real-World Application Scenarios (16 realistic workloads)

Zero external packages required (pure Python standard library).
Zero network access required.
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

# Tier 1 Suite Builders
from tier1_feature_coverage.test_f01_f07_multiarch_hal import build_suite as build_t1_multiarch
from tier1_feature_coverage.test_f08_f12_hardware_drivers import build_suite as build_t1_drivers
from tier1_feature_coverage.test_f13_f18_core_subsystems import build_suite as build_t1_subsystems
from tier1_feature_coverage.test_f19_f24_services_peripherals import build_suite as build_t1_services
from tier1_feature_coverage.test_f25_f32_hardening_acceptance import build_suite as build_t1_hardening

# Tier 2 Suite Builders
from tier2_boundaries.test_boundaries_multiarch import build_suite as build_t2_multiarch
from tier2_boundaries.test_boundaries_drivers import build_suite as build_t2_drivers
from tier2_boundaries.test_boundaries_subsystems import build_suite as build_t2_subsystems
from tier2_boundaries.test_boundaries_services import build_suite as build_t2_services
from tier2_boundaries.test_boundaries_hardening import build_suite as build_t2_hardening

# Tier 3 Suite Builders
from tier3_cross_feature.test_cross_vfs_block import build_suite as build_t3_vfs_block
from tier3_cross_feature.test_cross_syscall_mm_sched import build_suite as build_t3_syscall_mm_sched
from tier3_cross_feature.test_cross_net_security import build_suite as build_t3_net_security
from tier3_cross_feature.test_cross_drm_input import build_suite as build_t3_drm_input
from tier3_cross_feature.test_cross_crypto_boot import build_suite as build_t3_crypto_boot
from tier3_cross_feature.test_cross_virt_syscall import build_suite as build_t3_virt_syscall

# Tier 4 Suite Builder
from tier4_real_world.test_scenarios import build_suite as build_t4_scenarios

# Linux Subsystems Suite Builders (11 Subsystems / 21 Features across 4 Tiers)
from test_linux_subsystems import (
    build_linux_tier1_suite,
    build_linux_tier2_suite,
    build_linux_tier3_suite,
    build_linux_tier4_suite,
)

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def print_header(title: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 78}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title.center(78)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 78}{Colors.RESET}\n")

def get_suites_for_tier(tier: str):
    suites = []
    
    if tier in ("1", "all"):
        suites.extend([
            build_t1_multiarch(),
            build_t1_drivers(),
            build_t1_subsystems(),
            build_t1_services(),
            build_t1_hardening(),
            build_linux_tier1_suite(),
        ])
        
    if tier in ("2", "all"):
        suites.extend([
            build_t2_multiarch(),
            build_t2_drivers(),
            build_t2_subsystems(),
            build_t2_services(),
            build_t2_hardening(),
            build_linux_tier2_suite(),
        ])
        
    if tier in ("3", "all"):
        suites.extend([
            build_t3_vfs_block(),
            build_t3_syscall_mm_sched(),
            build_t3_net_security(),
            build_t3_drm_input(),
            build_t3_crypto_boot(),
            build_t3_virt_syscall(),
            build_linux_tier3_suite(),
        ])
        
    if tier in ("4", "all"):
        suites.extend([
            build_t4_scenarios(),
            build_linux_tier4_suite(),
        ])
        
    return suites

def main():
    parser = argparse.ArgumentParser(description="CorOS End-to-End Master Test Runner")
    parser.add_argument("--tier", choices=["1", "2", "3", "4", "all"], default="all",
                        help="Filter execution by tier (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose per-test output")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    suites = get_suites_for_tier(args.tier)
    
    if not args.json:
        print_header("CorOS Opaque-Box E2E Test Suite Execution")
        print(f"Target OS: CorOS (x86_64-unknown-uefi / Linux ABI Equivalent)")
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
        print_header("CorOS E2E Test Suite Summary")
        print(f"  Tier 1 - Feature Coverage:          {tier_stats[1]['passed']:>3} passed, {tier_stats[1]['failed']:>2} failed")
        print(f"  Tier 2 - Boundaries & Corner Cases: {tier_stats[2]['passed']:>3} passed, {tier_stats[2]['failed']:>2} failed")
        print(f"  Tier 3 - Cross-Feature Subsystems:  {tier_stats[3]['passed']:>3} passed, {tier_stats[3]['failed']:>2} failed")
        print(f"  Tier 4 - Real-World Scenarios:      {tier_stats[4]['passed']:>3} passed, {tier_stats[4]['failed']:>2} failed")
        print(f"  {'-' * 60}")
        print(f"  TOTAL:                              {total_passed:>3} passed, {total_failed:>2} failed in {total_elapsed:.3f}s")
        
        if total_failed == 0:
            print(f"\n{Colors.BOLD}{Colors.GREEN}>>> ALL {total_passed} E2E TESTS PASSED SUCCESSFULLY! <<<{Colors.RESET}\n")
        else:
            print(f"\n{Colors.BOLD}{Colors.RED}>>> {total_failed} TESTS FAILED! <<<{Colors.RESET}\n")

    sys.exit(0 if total_failed == 0 else 1)

if __name__ == "__main__":
    main()
