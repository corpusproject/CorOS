//! Integrity Measurement Architecture (`IMA`) runtime measurement log and binary appraisal verifier.
//!
//! Implements genuine FIPS 180-4 SHA-256 hashing, `ImaLogEntry` (`ima-ng` template hash computation),
//! TPM PCR-10 running hash extension (`PCR_new = SHA256(PCR_old || template_hash)`),
//! log replay verification, and binary execution appraisal policy verification.

use alloc::string::String;
use alloc::vec::Vec;

/// Default TPM Platform Configuration Register index used by IMA (`PCR-10`).
pub const IMA_DEFAULT_PCR_INDEX: u8 = 10;

/// FIPS 180-4 SHA-256 initial hash values (`H0..H7`).
const SHA256_INIT_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// FIPS 180-4 SHA-256 round constants (`K0..K63`).
const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming FIPS 180-4 SHA-256 state machine.
#[derive(Clone)]
pub struct Sha256Hasher {
    state: [u32; 8],
    block_buf: [u8; 64],
    block_len: usize,
    total_bytes: u64,
}

impl Sha256Hasher {
    pub const fn new() -> Self {
        Self {
            state: SHA256_INIT_STATE,
            block_buf: [0u8; 64],
            block_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        let mut offset = 0;

        if self.block_len > 0 {
            let needed = 64 - self.block_len;
            if data.len() < needed {
                self.block_buf[self.block_len..self.block_len + data.len()].copy_from_slice(data);
                self.block_len += data.len();
                return;
            }
            self.block_buf[self.block_len..64].copy_from_slice(&data[..needed]);
            let block = self.block_buf;
            self.compress_block(&block);
            self.block_len = 0;
            offset += needed;
        }

        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.compress_block(&block);
            offset += 64;
        }

        let rem = data.len() - offset;
        if rem > 0 {
            self.block_buf[..rem].copy_from_slice(&data[offset..]);
            self.block_len = rem;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_bytes.wrapping_mul(8);
        self.block_buf[self.block_len] = 0x80;
        self.block_len += 1;

        if self.block_len > 56 {
            for b in &mut self.block_buf[self.block_len..64] {
                *b = 0;
            }
            let block = self.block_buf;
            self.compress_block(&block);
            self.block_len = 0;
        }

        for b in &mut self.block_buf[self.block_len..56] {
            *b = 0;
        }
        self.block_buf[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let final_block = self.block_buf;
        self.compress_block(&final_block);

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress_block(&mut self, block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (i, slot) in schedule.iter_mut().take(16).enumerate() {
            let base = i * 4;
            *slot = u32::from_be_bytes([
                block[base],
                block[base + 1],
                block[base + 2],
                block[base + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = schedule[i - 15].rotate_right(7)
                ^ schedule[i - 15].rotate_right(18)
                ^ (schedule[i - 15] >> 3);
            let s1 = schedule[i - 2].rotate_right(17)
                ^ schedule[i - 2].rotate_right(19)
                ^ (schedule[i - 2] >> 10);
            schedule[i] = schedule[i - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sigma1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_ROUND_CONSTANTS[i])
                .wrapping_add(schedule[i]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sigma0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Convenience helper computing `SHA-256(data)`.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Hook source that triggered an IMA measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaMeasureHook {
    BprmCheck,
    FileMmap,
    KernelModuleLoad,
    KexecImageLoad,
    FirmwareLoad,
}

/// Single entry in the IMA runtime measurement list (`ima-ng` template).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaLogEntry {
    pub pcr_index: u8,
    pub file_data_hash: [u8; 32],
    pub template_hash: [u8; 32],
    pub file_path: String,
    pub hook: ImaMeasureHook,
}

impl ImaLogEntry {
    /// Computes the `ima-ng` template hash: `SHA256(len(algo_prefix + file_hash) || "sha256:" || file_hash || len(path) || path || NUL)`.
    pub fn compute_template_hash(file_data_hash: &[u8; 32], file_path: &str) -> [u8; 32] {
        let algo_prefix = b"sha256:";
        let digest_field_len = (algo_prefix.len() + file_data_hash.len()) as u32;
        let path_bytes = file_path.as_bytes();
        let path_field_len = (path_bytes.len() + 1) as u32;

        let mut hasher = Sha256Hasher::new();
        hasher.update(&digest_field_len.to_le_bytes());
        hasher.update(algo_prefix);
        hasher.update(file_data_hash);
        hasher.update(&path_field_len.to_le_bytes());
        hasher.update(path_bytes);
        hasher.update(&[0u8]);
        hasher.finalize()
    }
}

/// Result of IMA binary execution appraisal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaAppraisalResult {
    Verified,
    HashMismatch,
    MissingGoldenMeasurement,
}

/// Golden reference digest entry in the IMA appraisal policy table.
#[derive(Debug, Clone)]
struct AppraisalPolicyEntry {
    file_path: String,
    expected_sha256: [u8; 32],
}

/// IMA subsystem maintaining the runtime measurement log, PCR-10 running value, and appraisal policy.
pub struct ImaSubsystem {
    pub pcr10_value: [u8; 32],
    log_entries: Vec<ImaLogEntry>,
    appraisal_policy: Vec<AppraisalPolicyEntry>,
    pub enforce_appraisal: bool,
}

impl ImaSubsystem {
    pub fn new(enforce_appraisal: bool) -> Self {
        Self {
            pcr10_value: [0u8; 32],
            log_entries: Vec::new(),
            appraisal_policy: Vec::new(),
            enforce_appraisal,
        }
    }

    pub fn entries(&self) -> &[ImaLogEntry] {
        &self.log_entries
    }

    /// Registers a golden SHA-256 reference measurement (`security.ima` digest) for `file_path`.
    pub fn register_golden_digest(&mut self, file_path: &str, expected_sha256: [u8; 32]) {
        for entry in self.appraisal_policy.iter_mut() {
            if entry.file_path == file_path {
                entry.expected_sha256 = expected_sha256;
                return;
            }
        }
        self.appraisal_policy.push(AppraisalPolicyEntry {
            file_path: String::from(file_path),
            expected_sha256,
        });
    }

    /// Measures `file_bytes`, appends a new `ImaLogEntry` (unless an identical `(file_path, file_data_hash)`
    /// was already measured), and extends `PCR-10`: `PCR_new = SHA256(PCR_old || template_hash)`.
    pub fn measure_buffer(
        &mut self,
        file_path: &str,
        file_bytes: &[u8],
        hook: ImaMeasureHook,
    ) -> [u8; 32] {
        let file_data_hash = sha256_digest(file_bytes);

        // Skip duplicate measurement if already present in the runtime log
        let already_logged = self
            .log_entries
            .iter()
            .any(|e| e.file_path == file_path && e.file_data_hash == file_data_hash);

        if !already_logged {
            let template_hash = ImaLogEntry::compute_template_hash(&file_data_hash, file_path);
            self.pcr10_value = Self::extend_pcr(&self.pcr10_value, &template_hash);
            self.log_entries.push(ImaLogEntry {
                pcr_index: IMA_DEFAULT_PCR_INDEX,
                file_data_hash,
                template_hash,
                file_path: String::from(file_path),
                hook,
            });
        }

        file_data_hash
    }

    /// Computes TPM PCR extend operation: `SHA256(old_pcr || template_hash)`.
    pub fn extend_pcr(old_pcr: &[u8; 32], template_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256Hasher::new();
        hasher.update(old_pcr);
        hasher.update(template_hash);
        hasher.finalize()
    }

    /// Replays the entire measurement log from an all-zero initial PCR and verifies that it matches `pcr10_value`
    /// and that every entry's `template_hash` matches its `(file_data_hash, file_path)`.
    pub fn verify_log_integrity(&self) -> bool {
        let mut replay_pcr = [0u8; 32];
        for entry in &self.log_entries {
            let expected_template =
                ImaLogEntry::compute_template_hash(&entry.file_data_hash, &entry.file_path);
            if expected_template != entry.template_hash {
                return false;
            }
            replay_pcr = Self::extend_pcr(&replay_pcr, &entry.template_hash);
        }
        replay_pcr == self.pcr10_value
    }

    /// Measures and appraises an executable or critical file against the registered golden digest table.
    pub fn measure_and_appraise(
        &mut self,
        file_path: &str,
        file_bytes: &[u8],
        hook: ImaMeasureHook,
    ) -> ImaAppraisalResult {
        let measured_hash = self.measure_buffer(file_path, file_bytes, hook);
        for rule in &self.appraisal_policy {
            if rule.file_path == file_path {
                return if rule.expected_sha256 == measured_hash {
                    ImaAppraisalResult::Verified
                } else {
                    ImaAppraisalResult::HashMismatch
                };
            }
        }
        if self.enforce_appraisal {
            ImaAppraisalResult::MissingGoldenMeasurement
        } else {
            ImaAppraisalResult::Verified
        }
    }
}
