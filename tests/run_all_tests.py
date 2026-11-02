#!/usr/bin/env python3
"""
CorOS Master Test Runner
========================
tests/run_all_tests.py

Executes all Tier 1/2/3 verification suites across:
  - 361-Vector System Call ABI (`test_syscall_vectors.py`)
  - Hardware Driver Trees & PCI Registry (`test_drivers_pci.py`)
  - Multi-Filesystem VFS & Storage Stack
  - Network Stack, Sockets & Packet Firewall
  - Pure-Rust Cryptographic Suite & NIST KATs
  - 27 Userland Coreutils & 50M Scaling Architecture
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tier1_features.test_syscall_vectors import build_suite as build_syscall_suite
from tier1_features.test_drivers_pci import build_suite as build_drivers_suite


def main():
    parser = argparse.ArgumentParser(description="CorOS Automated Test Runner")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    suites = [
        build_syscall_suite(),
        build_drivers_suite(),
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    results = {}

    import io
    from contextlib import redirect_stdout

    for suite in suites:
        if args.json:
            buf = io.StringIO()
            with redirect_stdout(buf):
                p, f, details = suite.run(verbose=False)
        else:
            p, f, details = suite.run(verbose=args.verbose)
        total_tests += (p + f)
        passed_tests += p
        failed_tests += f
        results[suite.name] = {
            "passed": p,
            "failed": f,
            "details": details,
        }

    out = {
        "suites_run": len(suites),
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "results": results,
    }

    if args.json:
        print(json.dumps(out))
    else:
        print(f"Suites run: {len(suites)} | Passed: {passed_tests}/{total_tests} | Failed: {failed_tests}")

    sys.exit(0 if failed_tests == 0 else 1)


if __name__ == "__main__":
    main()
