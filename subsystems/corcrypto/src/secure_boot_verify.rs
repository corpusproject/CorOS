//! UEFI PE32+ Authenticode / Kernel image integrity verifier (`KernelManifest`,
//! section hash verifier, anti-rollback monotonic counter check, and tamper audit log).

use crate::blake2b_simd::blake2b_256;
use crate::constant_time::ct_eq_32;
use crate::sha256_engine::{hmac_sha256, sha256_digest, Sha256};

/// Maximum number of PE32+ image sections tracked in a `KernelManifest`.
pub const MAX_MANIFEST_SECTIONS: usize = 8;

/// Maximum number of tamper or verification audit records retained in `TamperAuditLog`.
pub const MAX_AUDIT_ENTRIES: usize = 16;

/// DOS header magic `"MZ"` (`0x5A4D` little-endian).
pub const MZ_MAGIC: u16 = 0x5A4D;

/// PE header signature `"PE\0\0"` (`0x00004550` little-endian).
pub const PE_SIGNATURE: u32 = 0x0000_4550;

/// PE32+ optional header magic (`0x020B` for 64-bit executables).
pub const PE32_PLUS_MAGIC: u16 = 0x020B;

/// Outcome of verifying a UEFI PE32+ kernel or subsystem image against its signed manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureBootStatus {
    /// Image headers, section hashes, anti-rollback counter, and manifest MAC all verified.
    Verified,
    /// Image lacks a valid MZ / PE32+ header structure.
    InvalidPe32PlusHeader,
    /// Manifest security version is older than the hardware/TPM monotonic rollback counter.
    RollbackDetected {
        manifest_svn: u64,
        minimum_required_svn: u64,
    },
    /// A PE32+ section's SHA-256 digest did not match the signed manifest entry.
    SectionHashMismatch { section_index: usize },
    /// The overall image BLAKE2b-256 or HMAC-SHA256 manifest authentication tag failed verification.
    ManifestSignatureInvalid,
}

/// Cryptographic descriptor for a single loaded PE32+ section (e.g., `.text`, `.rodata`, `.data`).
#[derive(Clone, Copy, Debug)]
pub struct SectionDescriptor {
    /// 8-byte ASCII section name (null-padded, e.g., `*b".text\0\0\0"`).
    pub name: [u8; 8],
    /// Relative Virtual Address (RVA) of the section when mapped.
    pub virtual_address: u32,
    /// Byte offset of the section within the raw image buffer.
    pub raw_offset: usize,
    /// Byte length of the section within the raw image buffer.
    pub raw_size: usize,
    /// Expected FIPS 180-4 SHA-256 digest of the section bytes.
    pub expected_sha256: [u8; 32],
}

/// Signed Secure Boot manifest describing a CorOS UEFI PE32+ kernel or driver binary.
#[derive(Clone, Debug)]
pub struct KernelManifest {
    /// Monotonic Security Version Number (SVN) for anti-rollback protection.
    pub security_version: u64,
    /// Expected entry point Relative Virtual Address (RVA).
    pub entry_point_rva: u32,
    /// Number of valid entries in `sections` (`0..=MAX_MANIFEST_SECTIONS`).
    pub section_count: usize,
    /// Per-section SHA-256 integrity descriptors.
    pub sections: [SectionDescriptor; MAX_MANIFEST_SECTIONS],
    /// BLAKE2b-256 digest over all section hashes and metadata.
    pub composite_blake2b: [u8; 32],
    /// Platform Root-of-Trust HMAC-SHA256 authentication tag over the manifest.
    pub manifest_mac: [u8; 32],
}

impl KernelManifest {
    /// Computes the canonical 32-byte BLAKE2b-256 digest over the manifest metadata and section hashes.
    pub fn compute_composite_digest(&self) -> [u8; 32] {
        let mut sha = Sha256::new();
        sha.update(&self.security_version.to_le_bytes());
        sha.update(&self.entry_point_rva.to_le_bytes());
        sha.update(&(self.section_count as u32).to_le_bytes());

        let count = self.section_count.min(MAX_MANIFEST_SECTIONS);
        let mut i = 0;
        while i < count {
            let sec = &self.sections[i];
            sha.update(&sec.name);
            sha.update(&sec.virtual_address.to_le_bytes());
            sha.update(&(sec.raw_offset as u64).to_le_bytes());
            sha.update(&(sec.raw_size as u64).to_le_bytes());
            sha.update(&sec.expected_sha256);
            i += 1;
        }
        let intermediate = sha.finalize();
        blake2b_256(&intermediate)
    }

    /// Builds and seals a `KernelManifest` for a given set of sections using the platform root key.
    pub fn build_and_seal(
        security_version: u64,
        entry_point_rva: u32,
        sections_slice: &[SectionDescriptor],
        platform_root_key: &[u8; 32],
    ) -> Self {
        let empty_sec = SectionDescriptor {
            name: [0u8; 8],
            virtual_address: 0,
            raw_offset: 0,
            raw_size: 0,
            expected_sha256: [0u8; 32],
        };
        let mut sections = [empty_sec; MAX_MANIFEST_SECTIONS];
        let count = sections_slice.len().min(MAX_MANIFEST_SECTIONS);
        let mut i = 0;
        while i < count {
            sections[i] = sections_slice[i];
            i += 1;
        }

        let mut manifest = Self {
            security_version,
            entry_point_rva,
            section_count: count,
            sections,
            composite_blake2b: [0u8; 32],
            manifest_mac: [0u8; 32],
        };
        manifest.composite_blake2b = manifest.compute_composite_digest();
        manifest.manifest_mac = hmac_sha256(platform_root_key, &manifest.composite_blake2b);
        manifest
    }
}

/// Validates minimal UEFI PE32+ executable headers (`MZ`, `e_lfanew`, `PE\0\0`, and `0x020B` magic).
pub fn verify_pe32_plus_header(image: &[u8]) -> bool {
    if image.len() < 0x80 {
        return false;
    }
    let mz = u16::from_le_bytes([image[0], image[1]]);
    if mz != MZ_MAGIC {
        return false;
    }
    let pe_offset = u32::from_le_bytes([image[0x3c], image[0x3d], image[0x3e], image[0x3f]]) as usize;
    if pe_offset.saturating_add(26) > image.len() {
        return false;
    }
    let pe_sig = u32::from_le_bytes([
        image[pe_offset],
        image[pe_offset + 1],
        image[pe_offset + 2],
        image[pe_offset + 3],
    ]);
    if pe_sig != PE_SIGNATURE {
        return false;
    }
    let opt_magic_offset = pe_offset + 24;
    let opt_magic = u16::from_le_bytes([image[opt_magic_offset], image[opt_magic_offset + 1]]);
    opt_magic == PE32_PLUS_MAGIC
}

/// Audit entry recording a Secure Boot verification event or tamper attempt.
#[derive(Clone, Copy, Debug)]
pub struct AuditEvent {
    pub sequence: u32,
    pub manifest_svn: u64,
    pub status: SecureBootStatus,
    pub image_measurement: [u8; 32],
}

/// Bounded in-memory tamper and measurement audit log for Secure Boot verification.
pub struct TamperAuditLog {
    entries: [AuditEvent; MAX_AUDIT_ENTRIES],
    count: usize,
    rolling_pcr: [u8; 32],
}

impl Default for TamperAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl TamperAuditLog {
    /// Creates an empty `TamperAuditLog` with an all-zero initial Platform Configuration Register (`PCR`).
    pub const fn new() -> Self {
        let blank = AuditEvent {
            sequence: 0,
            manifest_svn: 0,
            status: SecureBootStatus::ManifestSignatureInvalid,
            image_measurement: [0u8; 32],
        };
        Self {
            entries: [blank; MAX_AUDIT_ENTRIES],
            count: 0,
            rolling_pcr: [0u8; 32],
        }
    }

    /// Extends the TPM-style rolling PCR (`PCR_new = SHA256(PCR_old || measurement)`) and logs the event.
    pub fn record(&mut self, manifest_svn: u64, status: SecureBootStatus, measurement: [u8; 32]) {
        let mut pcr_hasher = Sha256::new();
        pcr_hasher.update(&self.rolling_pcr);
        pcr_hasher.update(&measurement);
        self.rolling_pcr = pcr_hasher.finalize();

        let idx = self.count % MAX_AUDIT_ENTRIES;
        self.entries[idx] = AuditEvent {
            sequence: self.count as u32,
            manifest_svn,
            status,
            image_measurement: measurement,
        };
        self.count = self.count.wrapping_add(1);
    }

    /// Returns the current 32-byte extended PCR measurement digest.
    pub const fn current_pcr(&self) -> &[u8; 32] {
        &self.rolling_pcr
    }

    /// Returns the total number of recorded events.
    pub const fn event_count(&self) -> usize {
        self.count
    }
}

/// Verifies a UEFI PE32+ kernel image against its `KernelManifest`, platform root key,
/// and minimum anti-rollback security version number (`min_svn`), recording the result in `audit_log`.
pub fn verify_kernel_image(
    image: &[u8],
    manifest: &KernelManifest,
    platform_root_key: &[u8; 32],
    min_svn: u64,
    audit_log: &mut TamperAuditLog,
) -> SecureBootStatus {
    let full_measurement = sha256_digest(image);

    if !verify_pe32_plus_header(image) {
        let status = SecureBootStatus::InvalidPe32PlusHeader;
        audit_log.record(manifest.security_version, status, full_measurement);
        return status;
    }

    if manifest.security_version < min_svn {
        let status = SecureBootStatus::RollbackDetected {
            manifest_svn: manifest.security_version,
            minimum_required_svn: min_svn,
        };
        audit_log.record(manifest.security_version, status, full_measurement);
        return status;
    }

    // Verify manifest composite digest and platform root HMAC in constant time
    let expected_composite = manifest.compute_composite_digest();
    if !ct_eq_32(&expected_composite, &manifest.composite_blake2b) {
        let status = SecureBootStatus::ManifestSignatureInvalid;
        audit_log.record(manifest.security_version, status, full_measurement);
        return status;
    }

    let expected_mac = hmac_sha256(platform_root_key, &expected_composite);
    if !ct_eq_32(&expected_mac, &manifest.manifest_mac) {
        let status = SecureBootStatus::ManifestSignatureInvalid;
        audit_log.record(manifest.security_version, status, full_measurement);
        return status;
    }

    // Verify each PE32+ section's SHA-256 digest
    let sec_count = manifest.section_count.min(MAX_MANIFEST_SECTIONS);
    let mut idx = 0;
    while idx < sec_count {
        let sec = &manifest.sections[idx];
        let end = sec.raw_offset.saturating_add(sec.raw_size);
        if end > image.len() {
            let status = SecureBootStatus::SectionHashMismatch { section_index: idx };
            audit_log.record(manifest.security_version, status, full_measurement);
            return status;
        }
        let actual_hash = sha256_digest(&image[sec.raw_offset..end]);
        if !ct_eq_32(&actual_hash, &sec.expected_sha256) {
            let status = SecureBootStatus::SectionHashMismatch { section_index: idx };
            audit_log.record(manifest.security_version, status, full_measurement);
            return status;
        }
        idx += 1;
    }

    let status = SecureBootStatus::Verified;
    audit_log.record(manifest.security_version, status, full_measurement);
    status
}

/// Runs Secure Boot PE32+ verification, section tamper detection, and anti-rollback self-tests.
pub fn run_secure_boot_self_test() -> u32 {
    let mut passed = 0u32;

    // Construct a synthetic 256-byte UEFI PE32+ image with valid MZ, PE\0\0, and 0x020B headers
    let mut image = [0u8; 256];
    image[0..2].copy_from_slice(&MZ_MAGIC.to_le_bytes());
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    image[0x40..0x44].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
    image[0x58..0x5a].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());

    // Populate simulated .text (offset 128..192) and .rodata (offset 192..256) sections
    let mut i = 128;
    while i < 192 {
        image[i] = (i as u8) ^ 0x90;
        i += 1;
    }
    while i < 256 {
        image[i] = (i as u8) ^ 0x5A;
        i += 1;
    }

    let sections = [
        SectionDescriptor {
            name: *b".text\0\0\0",
            virtual_address: 0x1000,
            raw_offset: 128,
            raw_size: 64,
            expected_sha256: sha256_digest(&image[128..192]),
        },
        SectionDescriptor {
            name: *b".rodata\0",
            virtual_address: 0x2000,
            raw_offset: 192,
            raw_size: 64,
            expected_sha256: sha256_digest(&image[192..256]),
        },
    ];

    let root_key = *b"CorOS-UEFI-SecureBoot-RootKey-v1";
    let manifest = KernelManifest::build_and_seal(4, 0x1000, &sections, &root_key);
    let mut audit = TamperAuditLog::new();

    // 1. Valid image and manifest at SVN 4 with min_svn 4 must pass
    if verify_kernel_image(&image, &manifest, &root_key, 4, &mut audit) == SecureBootStatus::Verified {
        passed += 1;
    }

    // 2. Anti-rollback check: requiring min_svn 5 must reject SVN 4
    if verify_kernel_image(&image, &manifest, &root_key, 5, &mut audit)
        == (SecureBootStatus::RollbackDetected {
            manifest_svn: 4,
            minimum_required_svn: 5,
        })
    {
        passed += 1;
    }

    // 3. Section tamper check: flipping 1 bit in .rodata must trigger SectionHashMismatch { section_index: 1 }
    let mut tampered_image = image;
    tampered_image[200] ^= 0x01;
    if verify_kernel_image(&tampered_image, &manifest, &root_key, 4, &mut audit)
        == (SecureBootStatus::SectionHashMismatch { section_index: 1 })
    {
        passed += 1;
    }

    // 4. Rolling PCR must have been extended across all 3 events
    if audit.event_count() == 3 && !ct_eq_32(audit.current_pcr(), &[0u8; 32]) {
        passed += 1;
    }

    passed
}
