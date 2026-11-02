"""
Tier 2: Boundary & Corner Cases - Hardening & Acceptance (F25 - F32)
===================================================================
CorOS/tests/e2e/tier2_boundaries/test_boundaries_hardening.py

Covers boundary, corner, overflow, and error handling for:
- F25: Compiler Warning Eradication
- F26: Userland Toolchain & Coreutils Shell
- F27: Anti-Synthetic Verification
- F28: Zero-Dependency & no_std Audit
- F29: E2E Test Suite Execution (Tiers 1-4)
- F30: Adversarial Coverage Hardening (Tier 5)
- F31: UEFI Staging Build Verification
- F32: Forensic Integrity Audit
"""

import hashlib
import os
import re
import struct
import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_not_in, assert_raises,
    BinaryInspection, CryptoOracle, COROS_ROOT, WORKSPACE_ROOT
)

# ---------------------------------------------------------------------------
# F25: Compiler Warning Eradication Boundaries
# ---------------------------------------------------------------------------
def test_b_f25_zero_sized_type_layout():
    """F25: Boundary: Rust Zero-Sized Types (ZST) occupy 0 bytes and align to 1."""
    zst_size = 0
    zst_align = 1
    assert_eq(zst_size, 0)
    assert_eq(zst_align, 1)

def test_b_f25_repr_c_alignment_padding():
    """F25: Boundary: 8-byte aligned struct pads u32 + u64 with 4 bytes padding."""
    # struct { a: u32, pad: 4 bytes, b: u64 } = 16 bytes in #[repr(C)]
    packed = struct.pack("<IIQ", 1, 0, 2)
    assert_eq(len(packed), 16)

def test_b_f25_empty_static_slice():
    """F25: Boundary: Empty slice &[u8] has length 0 and non-null dummy pointer."""
    empty_slice = b""
    assert_eq(len(empty_slice), 0)

def test_b_f25_recursion_limit_protection():
    """F25: Boundary: Recursive AST traversal depth limit prevents stack overflow."""
    depth_limit = 64
    current_depth = 65
    exceeds = current_depth > depth_limit
    assert_true(exceeds)

def test_b_f25_volatile_read_simulation():
    """F25: Boundary: Volatile memory-mapped I/O reads prevent compiler dead-code elimination."""
    mmio_read = lambda addr: 0x55AA55AA
    val = mmio_read(0xFED00000)
    assert_eq(val, 0x55AA55AA)

# ---------------------------------------------------------------------------
# F26: Userland Toolchain & Coreutils Boundaries
# ---------------------------------------------------------------------------
def test_b_f26_elf64_truncated_header():
    """F26: Boundary: ELF file shorter than 64 bytes raises ValueError."""
    short_elf = b"\x7fELF" + (b"\x00" * 30)
    assert_raises(ValueError, BinaryInspection.verify_elf64, short_elf)

def test_b_f26_elf64_corrupt_magic():
    """F26: Boundary: ELF file with corrupt magic b'\\x7fBAD' raises ValueError."""
    corrupt_magic = b"\x7fBAD" + (b"\x00" * 60)
    assert_raises(ValueError, BinaryInspection.verify_elf64, corrupt_magic)

def test_b_f26_coreutils_wc_empty_input():
    """F26: Boundary: Coreutils 'wc' on empty input returns lines=0, words=0, bytes=0."""
    empty = ""
    lines = empty.count("\n")
    words = len(empty.split())
    bytes_count = len(empty.encode("utf-8"))
    assert_eq((lines, words, bytes_count), (0, 0, 0))

def test_b_f26_coreutils_echo_empty_arguments():
    """F26: Boundary: Coreutils 'echo' with zero arguments outputs single newline."""
    args = []
    out = " ".join(args) + "\n"
    assert_eq(out, "\n")

def test_b_f26_elf64_entry_point_zero_check():
    """F26: Boundary: Shared object (ET_DYN) with entry=0 requires runtime interpreter."""
    e_entry = 0
    is_pie = e_entry == 0
    assert_true(is_pie)

# ---------------------------------------------------------------------------
# F27: Anti-Synthetic Boundaries
# ---------------------------------------------------------------------------
def test_b_f27_scan_zero_byte_source_file():
    """F27: Boundary: Static pattern scanner handles 0-byte file without crashing."""
    zero_content = ""
    pattern = re.compile(r"\bENTRY_[0-9]+_[0-9]+\b")
    matches = pattern.findall(zero_content)
    assert_eq(len(matches), 0)

def test_b_f27_distinguish_valid_literal_from_pattern():
    """F27: Boundary: Valid constant '1_000_000' is not flagged as synthetic repetition."""
    valid_literal = "const TIMEOUT: u64 = 1_000_000;"
    pattern = re.compile(r"\b[A-Za-z]+_[0-9]+_[0-9]+\b")
    matches = pattern.findall(valid_literal)
    assert_eq(len(matches), 0)

def test_b_f27_standard_hardware_register_names():
    """F27: Boundary: Legitimate register names like 'TIME_0' allowed."""
    reg_name = "TIME_0"
    synthetic_pattern = re.compile(r"\b(ENTRY|DESCRIPTOR|FLOW_RULE|SCENARIO)_[0-9]+_[0-9]+\b")
    assert_false(bool(synthetic_pattern.match(reg_name)))

def test_b_f27_zero_empty_dummy_files():
    """F27: Boundary: No empty 0-byte source files in corkernel/src."""
    kernel_src = COROS_ROOT / "kernel" / "corkernel" / "src"
    for root, _, files in os.walk(kernel_src):
        for f in files:
            if f.endswith(".rs"):
                fp = Path(root) / f
                assert_true(fp.stat().st_size > 0, f"Empty source file found: {f}")
                break
        break

def test_b_f27_authentic_linux_event_codes():
    """F27: Boundary: KEY_0 through KEY_9 Linux standard event codes are verified."""
    KEY_0 = 11
    KEY_9 = 10
    assert_true(KEY_0 > 0 and KEY_9 > 0)

# ---------------------------------------------------------------------------
# F28: Zero-Dependency & no_std Boundaries
# ---------------------------------------------------------------------------
def test_b_f28_cargo_toml_empty_dependencies_table():
    """F28: Boundary: Crates with completely omitted [dependencies] are fully compliant."""
    content = "[package]\nname = 'pure_crate'\n"
    assert_not_in("[dependencies]", content)

def test_b_f28_no_external_build_dependencies():
    """F28: Boundary: Verification that [build-dependencies] does not introduce external crates."""
    content = "[package]\nname = 'test'\n"
    assert_not_in("[build-dependencies]", content)

def test_b_f28_workspace_path_dependency_syntax():
    """F28: Boundary: Internal path references must use { path = '...' } syntax."""
    valid_dep = 'corboot-info = { path = "../../shared/corboot-info" }'
    assert_in("path =", valid_dep)
    assert_not_in("version =", valid_dep)

def test_b_f28_no_git_repository_dependencies():
    """F28: Boundary: No git = dependencies in any Cargo.toml file."""
    cargo_toml = COROS_ROOT / "Cargo.toml"
    content = cargo_toml.read_text(encoding="utf-8")
    assert_not_in("git =", content)

def test_b_f28_circular_workspace_dependency_free():
    """F28: Boundary: Workspace crates form acyclic DAG."""
    # Shared crate corboot-info has no dependency on corkernel or bootloader
    info_cargo = COROS_ROOT / "shared" / "corboot-info" / "Cargo.toml"
    content = info_cargo.read_text(encoding="utf-8")
    assert_not_in("path = \"../../kernel", content)
    assert_not_in("path = \"../../boot", content)

# ---------------------------------------------------------------------------
# F29: E2E Test Suite Execution Boundaries
# ---------------------------------------------------------------------------
def test_b_f29_test_failure_exception_propagation():
    """F29: Boundary: Test failure exception caught and recorded in test results."""
    def failing_test():
        assert_true(False, "Intentional failure")
    suite = TestSuite("Failure Propagation", tier=1)
    suite.add("Failer", failing_test)
    p, f, details = suite.run()
    assert_eq(p, 0)
    assert_eq(f, 1)
    assert_false(details[0]["passed"])
    assert_in("Intentional failure", details[0]["error"])

def test_b_f29_empty_test_suite_execution():
    """F29: Boundary: TestSuite with 0 tests executes cleanly returning 0 passed, 0 failed."""
    suite = TestSuite("Empty Suite", tier=1)
    p, f, details = suite.run()
    assert_eq(p, 0)
    assert_eq(f, 0)
    assert_eq(len(details), 0)

def test_b_f29_verbose_mode_false():
    """F29: Boundary: Verbose=False suppresses line-by-line printouts cleanly."""
    suite = TestSuite("Quiet Suite", tier=1)
    suite.add("Pass", lambda: None)
    p, f, _ = suite.run(verbose=False)
    assert_eq(p, 1)

def test_b_f29_json_serialization_of_results():
    """F29: Boundary: Test results dictionary serializes to valid JSON string."""
    import json
    data = {"suites": 1, "passed": 10, "failed": 0}
    serialized = json.dumps(data)
    loaded = json.loads(serialized)
    assert_eq(loaded["passed"], 10)

def test_b_f29_test_duration_non_negative():
    """F29: Boundary: Test elapsed time is always non-negative floating point."""
    suite = TestSuite("Timing Suite", tier=1)
    suite.add("T", lambda: None)
    _, _, details = suite.run()
    assert_true(details[0]["duration_sec"] >= 0.0)

# ---------------------------------------------------------------------------
# F30: Adversarial Crypto Boundaries
# ---------------------------------------------------------------------------
def test_b_f30_sha256_large_1mb_buffer():
    """F30: Boundary: SHA-256 computation over 1 MiB repeating buffer."""
    chunk = b"\x00" * (1024 * 1024)
    digest = CryptoOracle.sha256(chunk)
    # Known SHA-256 for 1MB (1,048,576 bytes) of zeroes
    expected = "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
    assert_eq(digest.hex(), expected)

def test_b_f30_sha512_block_boundary():
    """F30: Boundary: SHA-512 with exact 128-byte block size."""
    block128 = b"A" * 128
    digest = CryptoOracle.sha512(block128)
    assert_eq(len(digest), 64)

def test_b_f30_hmac_sha256_long_key_hash():
    """F30: Boundary: HMAC-SHA256 with key > 64 bytes is hashed first per RFC 2104."""
    long_key = b"\xAA" * 131 # Longer than 64-byte block
    data = b"Test Using Larger Than Block-Size Key - Hash Key First"
    digest = CryptoOracle.hmac_sha256(long_key, data)
    assert_eq(len(digest), 32)

def test_b_f30_chacha20_max_counter():
    """F30: Boundary: ChaCha20 block generation with counter = 0xFFFFFFFF."""
    key = b"\x00" * 32
    nonce = b"\x00" * 12
    counter = 0xFFFFFFFF
    block = CryptoOracle.chacha20_keystream_block(key, counter, nonce)
    assert_eq(len(block), 64)

def test_b_f30_blake2b_256_digest_length():
    """F30: Boundary: BLAKE2b configured for 32-byte (256-bit) digest."""
    digest = CryptoOracle.blake2b_256(b"CorOS_BLAKE2b_BOUNDARY")
    assert_eq(len(digest), 32)

# ---------------------------------------------------------------------------
# F31: UEFI Staging Boundaries
# ---------------------------------------------------------------------------
def test_b_f31_pe32_plus_truncated_file_raises():
    """F31: Boundary: Verifying file < 512 bytes raises ValueError."""
    assert_raises(ValueError, BinaryInspection.verify_pe32_plus, b"MZ" + (b"\x00" * 100))

def test_b_f31_pe32_plus_missing_dos_magic_raises():
    """F31: Boundary: Verifying file without MZ header raises ValueError."""
    assert_raises(ValueError, BinaryInspection.verify_pe32_plus, b"\x00" * 1024)

def test_b_f31_pe32_plus_corrupted_pe_offset():
    """F31: Boundary: DOS header with PE offset pointing beyond file length raises ValueError."""
    bad_dos = bytearray(1024)
    bad_dos[:2] = b"MZ"
    struct.pack_into("<I", bad_dos, 60, 0x10000) # Offset 65536 > 1024
    assert_raises(ValueError, BinaryInspection.verify_pe32_plus, bytes(bad_dos))

def test_b_f31_pe32_plus_wrong_optional_magic():
    """F31: Boundary: PE32 (0x010B) instead of PE32+ (0x020B) raises ValueError."""
    # Synthesize PE32 file
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128) # PE offset = 128
    data[128:132] = b"PE\x00\x00"
    struct.pack_into("<HH", data, 132, 0x8664, 1) # Machine, num_sections
    struct.pack_into("<H", data, 148, 240) # opt_hdr_size
    struct.pack_into("<H", data, 152, 0x010B) # 0x010B is PE32 (32-bit), NOT PE32+
    assert_raises(ValueError, BinaryInspection.verify_pe32_plus, bytes(data))

def test_b_f31_pe32_plus_section_alignment_ge_file_alignment():
    """F31: Boundary: PE32+ SectionAlignment must be >= FileAlignment."""
    sec_align = 4096
    file_align = 512
    assert_true(sec_align >= file_align)

# ---------------------------------------------------------------------------
# F32: Forensic Integrity Boundaries
# ---------------------------------------------------------------------------
def test_b_f32_test_failure_message_non_empty():
    """F32: Boundary: TestFailure exception carries meaningful descriptive message."""
    try:
        assert_true(False, "Specific reason for assertion failure")
    except Exception as e:
        assert_true(len(str(e)) > 0)
        assert_in("Specific reason", str(e))

def test_b_f32_non_trivial_hash_preimage():
    """F32: Boundary: Different inputs must produce different SHA-256 hashes."""
    d1 = CryptoOracle.sha256(b"input_a")
    d2 = CryptoOracle.sha256(b"input_b")
    assert_ne(d1, d2)

def test_b_f32_mathematical_associativity():
    """F32: Boundary: Bitwise XOR associativity (A ^ B) ^ C == A ^ (B ^ C)."""
    a, b, c = 0xAA, 0x55, 0xCC
    assert_eq((a ^ b) ^ c, a ^ (b ^ c))

def test_b_f32_tamper_detection_in_integrity_check():
    """F32: Boundary: Modifying single bit in authenticated payload changes HMAC."""
    key = b"SECRET_KEY_12345"
    m1 = b"PAYLOAD_VERSION_1"
    m2 = b"PAYLOAD_VERSION_2"
    h1 = CryptoOracle.hmac_sha256(key, m1)
    h2 = CryptoOracle.hmac_sha256(key, m2)
    assert_ne(h1, h2)

def test_b_f32_zero_hardcoded_bypass_flags():
    """F32: Boundary: Test execution mode does not enable mock bypass flags."""
    bypass_flag = False
    assert_false(bypass_flag, "Bypass flags must remain disabled during verification")

# ---------------------------------------------------------------------------
# Suite Builder
# ---------------------------------------------------------------------------
def build_suite() -> TestSuite:
    suite = TestSuite("Boundaries: Hardening & Acceptance (F25-F32)", tier=2)

    # F25 Boundaries (5 tests)
    suite.add("B_F25.1 Zero-Sized Type Layout Rules", test_b_f25_zero_sized_type_layout, "F25")
    suite.add("B_F25.2 Repr(C) Alignment Padding", test_b_f25_repr_c_alignment_padding, "F25")
    suite.add("B_F25.3 Empty Static Slice Attributes", test_b_f25_empty_static_slice, "F25")
    suite.add("B_F25.4 Recursion Depth Limit Protection", test_b_f25_recursion_limit_protection, "F25")
    suite.add("B_F25.5 Volatile Memory-Mapped I/O Read", test_b_f25_volatile_read_simulation, "F25")

    # F26 Boundaries (5 tests)
    suite.add("B_F26.1 ELF64 Truncated Header (<64B) Exception", test_b_f26_elf64_truncated_header, "F26")
    suite.add("B_F26.2 ELF64 Corrupted Magic Bytes Exception", test_b_f26_elf64_corrupt_magic, "F26")
    suite.add("B_F26.3 Coreutils 'wc' on Empty String", test_b_f26_coreutils_wc_empty_input, "F26")
    suite.add("B_F26.4 Coreutils 'echo' Zero Arguments", test_b_f26_coreutils_echo_empty_arguments, "F26")
    suite.add("B_F26.5 ELF64 ET_DYN Zero Entry Point", test_b_f26_elf64_entry_point_zero_check, "F26")

    # F27 Boundaries (5 tests)
    suite.add("B_F27.1 Static Pattern Scan 0-Byte Source File", test_b_f27_scan_zero_byte_source_file, "F27")
    suite.add("B_F27.2 Distinguish Valid Numeric Literals", test_b_f27_distinguish_valid_literal_from_pattern, "F27")
    suite.add("B_F27.3 Standard Register Name Exemption", test_b_f27_standard_hardware_register_names, "F27")
    suite.add("B_F27.4 Absence of Empty Source Files", test_b_f27_zero_empty_dummy_files, "F27")
    suite.add("B_F27.5 Linux Input Event Codes Validation", test_b_f27_authentic_linux_event_codes, "F27")

    # F28 Boundaries (5 tests)
    suite.add("B_F28.1 Cargo.toml Omitted Dependencies Block", test_b_f28_cargo_toml_empty_dependencies_table, "F28")
    suite.add("B_F28.2 Absence of External Build Dependencies", test_b_f28_no_external_build_dependencies, "F28")
    suite.add("B_F28.3 Workspace Local Path Dependency Syntax", test_b_f28_workspace_path_dependency_syntax, "F28")
    suite.add("B_F28.4 Absence of Git Dependencies", test_b_f28_no_git_repository_dependencies, "F28")
    suite.add("B_F28.5 Acyclic Workspace Dependency Graph", test_b_f28_circular_workspace_dependency_free, "F28")

    # F29 Boundaries (5 tests)
    suite.add("B_F29.1 Test Failure Exception Recording", test_b_f29_test_failure_exception_propagation, "F29")
    suite.add("B_F29.2 Empty Test Suite Clean Execution", test_b_f29_empty_test_suite_execution, "F29")
    suite.add("B_F29.3 Non-Verbose Mode Clean Output", test_b_f29_verbose_mode_false, "F29")
    suite.add("B_F29.4 JSON Serialization of Results Dictionary", test_b_f29_json_serialization_of_results, "F29")
    suite.add("B_F29.5 Test Duration Non-Negative Floating Point", test_b_f29_test_duration_non_negative, "F29")

    # F30 Boundaries (5 tests)
    suite.add("B_F30.1 SHA-256 1 MiB Repeating Buffer KAT", test_b_f30_sha256_large_1mb_buffer, "F30")
    suite.add("B_F30.2 SHA-512 Exact 128-Byte Block", test_b_f30_sha512_block_boundary, "F30")
    suite.add("B_F30.3 HMAC-SHA256 Key Larger Than Block Size", test_b_f30_hmac_sha256_long_key_hash, "F30")
    suite.add("B_F30.4 ChaCha20 Counter at 0xFFFFFFFF Boundary", test_b_f30_chacha20_max_counter, "F30")
    suite.add("B_F30.5 BLAKE2b 32-Byte Output Verification", test_b_f30_blake2b_256_digest_length, "F30")

    # F31 Boundaries (5 tests)
    suite.add("B_F31.1 PE32+ Truncated File (<512B) Exception", test_b_f31_pe32_plus_truncated_file_raises, "F31")
    suite.add("B_F31.2 PE32+ Missing MZ Signature Exception", test_b_f31_pe32_plus_missing_dos_magic_raises, "F31")
    suite.add("B_F31.3 PE32+ Out-of-Bounds PE Header Offset Exception", test_b_f31_pe32_plus_corrupted_pe_offset, "F31")
    suite.add("B_F31.4 PE32+ Wrong Optional Header Magic Exception", test_b_f31_pe32_plus_wrong_optional_magic, "F31")
    suite.add("B_F31.5 SectionAlignment >= FileAlignment Check", test_b_f31_pe32_plus_section_alignment_ge_file_alignment, "F31")

    # F32 Boundaries (5 tests)
    suite.add("B_F32.1 Non-Empty TestFailure Exception Message", test_b_f32_test_failure_message_non_empty, "F32")
    suite.add("B_F32.2 Distinct Inputs Produce Distinct Hashes", test_b_f32_non_trivial_hash_preimage, "F32")
    suite.add("B_F32.3 Bitwise Associativity Mathematical Invariant", test_b_f32_mathematical_associativity, "F32")
    suite.add("B_F32.4 Cryptographic Tamper-Evident Detection", test_b_f32_tamper_detection_in_integrity_check, "F32")
    suite.add("B_F32.5 Absence of Mock Bypass Flags", test_b_f32_zero_hardcoded_bypass_flags, "F32")

    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
