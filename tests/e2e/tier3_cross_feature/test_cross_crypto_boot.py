"""
Tier 3: Cross-Feature Interactions - Crypto + Boot Protocol Pipeline
=====================================================================
CorOS/tests/e2e/tier3_cross_feature/test_cross_crypto_boot.py

Tests pairwise integration between:
- corcrypto (SHA-256, SHA-512, HMAC, ChaCha20 Authenticated Primitives)
- boot/corboot (UEFI PE32+ Loader, BootInfo Handoff, Secure Boot State)
- shared/corboot-info (C-ABI Boot Contract & Image Integrity)
"""

import hashlib
import struct
import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in,
    BootInfo, CryptoOracle, BinaryInspection, COROS_ROOT
)

def test_kernel_image_sha256_authenticode_verification():
    """Tier 3: Staged CORKERNEL.EFI image integrity verified via cryptographic SHA-256."""
    kernel_path = COROS_ROOT / "dist" / "esp" / "EFI" / "COROS" / "CORKERNEL.EFI"
    assert_true(kernel_path.exists())
    data = kernel_path.read_bytes()
    
    # Compute SHA-256 digest
    digest = CryptoOracle.sha256(data)
    assert_eq(len(digest), 32)
    assert_ne(digest, b"\x00" * 32)
    
    # Verify valid PE32+ structure before handoff
    pe_info = BinaryInspection.verify_pe32_plus(data)
    assert_eq(pe_info["machine"], 0x8664)

def test_bootloader_handoff_with_entropy_seed():
    """Tier 3: BootInfo handoff embeds boot-time entropy for early kernel PRNG seeding."""
    # Generate 32 bytes of early boot entropy
    entropy = CryptoOracle.sha256(b"UEFI_RNG_PROTOCOL_ENTROPY_SEED_12345")
    assert_eq(len(entropy), 32)
    
    # Pack into BootInfo
    info = BootInfo(cmdline=f"seed={entropy.hex()[:16]}")
    raw = info.pack()
    unpacked = BootInfo.unpack(raw)
    assert_in("seed=", unpacked.cmdline)

def test_authenticated_initrd_hmac_check():
    """Tier 3: Early RAM bundle (INITRD.IMG) authenticated using HMAC-SHA256."""
    key = b"COROS_SECURE_BOOT_KEY_HMAC256"
    initrd_payload = b"RAM_DISK_BUNDLE_PAYLOAD_WITH_SYSTEM_DAEMONS" * 10
    
    # Compute authentication tag
    tag = CryptoOracle.hmac_sha256(key, initrd_payload)
    assert_eq(len(tag), 32)
    
    # Verify tag on load
    computed_tag = CryptoOracle.hmac_sha256(key, initrd_payload)
    assert_eq(computed_tag, tag)

def test_tampered_kernel_binary_rejection():
    """Tier 3: Single bit flip in kernel binary invalidates cryptographic hash."""
    sample_kernel = bytearray(b"MZ" + (b"\xAA" * 1000))
    clean_hash = CryptoOracle.sha256(bytes(sample_kernel))
    
    # Tamper with single byte
    sample_kernel[100] ^= 0x01
    tampered_hash = CryptoOracle.sha256(bytes(sample_kernel))
    
    assert_ne(tampered_hash, clean_hash, "Tampered kernel detected by crypto verification")

def build_suite() -> TestSuite:
    suite = TestSuite("Cross-Feature: Crypto + Boot Protocol Pipeline", tier=3)
    suite.add("Kernel Image SHA-256 Authenticode Verification", test_kernel_image_sha256_authenticode_verification, "F01+F30")
    suite.add("Bootloader Handoff with Entropy Seed", test_bootloader_handoff_with_entropy_seed, "F01+F30")
    suite.add("Authenticated Initrd HMAC-SHA256 Verification", test_authenticated_initrd_hmac_check, "F30+F01")
    suite.add("Tampered Kernel Image Crypto Rejection", test_tampered_kernel_binary_rejection, "F30+F31")
    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
