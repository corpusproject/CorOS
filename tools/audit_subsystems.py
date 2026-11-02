#!/usr/bin/env python3
import json
import re
from pathlib import Path

CRATES = [
    "corsyscall", "cordrivers", "corvfs", "cornet", "corcrypto", "corcoreutils",
    "cormm", "corvirt", "corsound", "corsec", "coripc", "corbpf",
    "cordrm", "corpower", "corinput", "corblock", "corsched", "cortoolchain"
]

ROOT = Path(__file__).resolve().parent.parent
SUBSYSTEMS_DIR = ROOT / "subsystems"
OUTPUT_FILE = ROOT / ".agents" / "teamwork" / "explorer_gen2_survey_2" / "detailed_crate_audit.json"

def main():
    report = {}

    for c in CRATES:
        cdir = SUBSYSTEMS_DIR / c
        src_dir = cdir / "src"
        lib_file = src_dir / "lib.rs"

        files = sorted([f.name for f in src_dir.glob("*.rs") if f.is_file()])

        if not lib_file.exists():
            report[c] = {"error": "Missing lib.rs"}
            continue

        lib_text = lib_file.read_text(encoding="utf-8", errors="ignore")

        # check export of run_self_tests() -> u32
        has_fn = bool(re.search(r"pub\s+fn\s+run_self_tests\s*\(\s*\)\s*->\s*u32", lib_text))

        # modules declared
        declared_mods = re.findall(r"^\s*(?:pub\s+)?mod\s+([a-zA-Z0-9_]+);", lib_text, re.MULTILINE)

        # run_self_tests body
        m = re.search(r"pub\s+fn\s+run_self_tests\s*\(\s*\)\s*->\s*u32\s*\{(.*?)\n\}", lib_text, re.DOTALL)
        if not m:
            m = re.search(r"pub\s+fn\s+run_self_tests\s*\(\s*\)\s*->\s*u32\s*\{(.*?)\}", lib_text, re.DOTALL)
        body = m.group(1).strip() if m else ""

        # Check if body is hardcoded literal
        is_hardcoded = bool(re.fullmatch(r"\d+", body.strip()))
        hardcoded_val = int(body.strip()) if is_hardcoded else None

        # find modules referenced in run_self_tests body or lib.rs test helper functions
        # Check all test helper functions in lib.rs
        test_helpers = re.findall(r"fn\s+(test_[a-zA-Z0-9_]+)\s*\(\s*\)\s*->\s*bool\s*\{(.*?)\n\}", lib_text, re.DOTALL)
        helper_dict = {name: hbody for name, hbody in test_helpers}

        mods_in_rst = []
        # Find imports of declared modules: use <mod>::...
        mod_imports = {}
        for mod in declared_mods:
            import_match = re.search(r"use\s+" + re.escape(mod) + r"::\{?([^\};]+)\}?;", lib_text)
            if import_match:
                imported_items = [item.strip() for item in import_match.group(1).split(",")]
                mod_imports[mod] = imported_items
            else:
                mod_imports[mod] = []

        for mod in declared_mods:
            # Check if referenced directly in run_self_tests body
            if re.search(r"\b" + re.escape(mod) + r"::", body) or re.search(r"\btest_" + re.escape(mod) + r"\b", body):
                mods_in_rst.append(mod)
            elif mod in body:
                mods_in_rst.append(mod)
            else:
                # Check if imported items from mod are used in body
                if any(re.search(r"\b" + re.escape(item) + r"\b", body) for item in mod_imports[mod] if item):
                    mods_in_rst.append(mod)
                else:
                    # Check if referenced inside helper function that is called by body
                    for hname, hbody in helper_dict.items():
                        if hname in body and (mod in hbody or re.search(r"\b" + re.escape(mod) + r"::", hbody)):
                            mods_in_rst.append(mod)
                            break

        # unexercised declared modules
        unexercised_declared = [mod for mod in declared_mods if mod not in mods_in_rst]

        # undeclared files in src/
        undeclared_files = [f for f in files if f != "lib.rs" and f[:-3] not in declared_mods]

        # scan for repetitive patterns across files
        suspicious_patterns = []
        total_loc = 0
        file_locs = {}
        for f in files:
            fpath = src_dir / f
            fcontent = fpath.read_text(encoding="utf-8", errors="ignore")
            lines = fcontent.splitlines()
            total_loc += len(lines)
            file_locs[f] = len(lines)

            # Check repetitive numbered identifier patterns like Entry_0_0, DESCRIPTOR_0_0, etc.
            matches_0_0 = re.findall(r"\b[A-Za-z][A-Za-z0-9_]*_\d+_\d+\b", fcontent)
            if matches_0_0:
                suspicious_patterns.extend([(f, m) for m in matches_0_0[:5]])

        report[c] = {
            "files_count": len(files),
            "total_loc": total_loc,
            "declared_mods_count": len(declared_mods),
            "declared_mods": declared_mods,
            "undeclared_files": undeclared_files,
            "has_run_self_tests": has_fn,
            "is_hardcoded": is_hardcoded,
            "hardcoded_val": hardcoded_val,
            "body_lines": len(body.splitlines()),
            "exercised_mods_count": len(mods_in_rst),
            "exercised_mods": mods_in_rst,
            "unexercised_mods": unexercised_declared,
            "suspicious_patterns": suspicious_patterns,
            "file_locs": file_locs
        }

    OUTPUT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Audit completed. Wrote results to {OUTPUT_FILE}\n")

    print(f"{'Crate':<15} | {'Files':<5} | {'LOC':<6} | {'Mods':<4} | {'Exercised':<9} | {'RST Export':<10} | {'Return Type/Kind':<20} | {'Status'}")
    print("-" * 95)
    for c in CRATES:
        info = report[c]
        has_rst = "YES" if info["has_run_self_tests"] else "NO"
        if info["is_hardcoded"]:
            ret_kind = f"HARDCODED ({info['hardcoded_val']})"
            status = "DEFICIENT (Hardcoded stub)"
        else:
            ret_kind = f"Dynamic ({info['body_lines']} lines)"
            if info["unexercised_mods"]:
                status = f"DEFICIENT ({len(info['unexercised_mods'])} unexercised)"
            else:
                status = "OK (Genuine coverage)"
        if info["undeclared_files"]:
            status += f" [{len(info['undeclared_files'])} uncompiled files!]"

        print(f"{c:<15} | {info['files_count']:<5} | {info['total_loc']:<6} | {info['declared_mods_count']:<4} | {info['exercised_mods_count']:<9} | {has_rst:<10} | {ret_kind:<20} | {status}")

    print("\nRepetitive / Suspicious Identifier Scan:")
    found_any = False
    for c in CRATES:
        info = report[c]
        if info["suspicious_patterns"]:
            found_any = True
            print(f"  [{c}]: {info['suspicious_patterns']}")
    if not found_any:
        print("  None found! Zero repetitive numbered identifier patterns.")


if __name__ == "__main__":
    main()
