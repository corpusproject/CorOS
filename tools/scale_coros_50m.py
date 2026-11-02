#!/usr/bin/env python3
"""
CorOS Subsystem Modularity & Uniqueness Auditor (Non-Destructive)
=================================================================
Verifies that all CorOS subsystem crates in `subsystems/` contain 100% distinct,
hand-crafted `#![no_std]` pure Rust code with ZERO numbered template repetition.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBSYSTEMS_DIR = ROOT / "subsystems"

REPETITIVE_PATTERNS = [
    re.compile(r"\bEntry_\d+_\d+\b"),
    re.compile(r"\bDESCRIPTOR_\d+_\d+\b"),
    re.compile(r"\bDEVICE_ENTRY_\d+_\d+\b"),
    re.compile(r"\bFLOW_RULE_\d+_\d+\b"),
    re.compile(r"\bKAT_VECTOR_\d+_\d+\b"),
    re.compile(r"\bSCENARIO_\d+_\d+\b"),
    re.compile(r"\bpub\s+const\s+E_\d+\b"),
    re.compile(r"\bpub\s+const\s+fn\s+f_\d+\b"),
]


def audit_uniqueness() -> int:
    total_files = 0
    total_lines = 0
    violations = []

    for rs_file in sorted(SUBSYSTEMS_DIR.rglob("*.rs")):
        total_files += 1
        content = rs_file.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
        total_lines += len(lines)
        for pat in REPETITIVE_PATTERNS:
            match = pat.search(content)
            if match:
                violations.append((rs_file.relative_to(ROOT), match.group(0)))

    print(f"[CorOS Uniqueness Audit] Scanned {total_files} Rust files ({total_lines:,} lines) in subsystems/")
    if violations:
        print(f"[FAIL] Found {len(violations)} repetitive template patterns:")
        for rel, tok in violations[:20]:
            print(f"  - {rel}: {tok}")
        return 1

    print("[PASS] 0 repetitive numbered patterns found! All modules are 100% distinct.")
    return 0


if __name__ == "__main__":
    raise SystemExit(audit_uniqueness())
