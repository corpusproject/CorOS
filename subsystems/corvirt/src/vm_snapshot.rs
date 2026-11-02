//! Live VM Checkpoint & Migration Stream Codec (`MigrationHeader`, `VcpuSnapshotRecord`,
//! `DirtyRamPageChunk`, IEEE 802.3 CRC-32 integrity checksum, and incremental pre-copy
//! convergence estimator).

use alloc::vec::Vec;

/// Magic number for CorVirt live migration streams (`"CVMG0001"` in little-endian).
pub const CORVIRT_MIGRATION_MAGIC: u64 = 0x3130_3030_474D_5643;

/// Computes the standard IEEE 802.3 CRC-32 checksum over a byte slice using polynomial `0xEDB88320`.
pub fn compute_crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// 32-byte Live Migration Stream Header (`MigrationHeader`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MigrationHeader {
    pub magic: u64,
    pub version: u32,
    pub vcpu_count: u32,
    pub dirty_page_chunks: u32,
    pub flags: u32,
    pub payload_crc32: u32,
    pub reserved: u32,
}

impl MigrationHeader {
    pub const SIZE_BYTES: usize = 32;

    pub fn new(vcpu_count: u32, dirty_page_chunks: u32, flags: u32, payload_crc32: u32) -> Self {
        Self {
            magic: CORVIRT_MIGRATION_MAGIC,
            version: 1,
            vcpu_count,
            dirty_page_chunks,
            flags,
            payload_crc32,
            reserved: 0,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.magic.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.vcpu_count.to_le_bytes());
        out.extend_from_slice(&self.dirty_page_chunks.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.payload_crc32.to_le_bytes());
        out.extend_from_slice(&self.reserved.to_le_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < Self::SIZE_BYTES {
            return Err("Migration stream shorter than 32-byte header");
        }
        let magic = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if magic != CORVIRT_MIGRATION_MAGIC {
            return Err("Invalid CorVirt migration header magic");
        }
        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let vcpu_count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let dirty_page_chunks = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let flags = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let payload_crc32 = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let reserved = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);

        Ok(Self {
            magic,
            version,
            vcpu_count,
            dirty_page_chunks,
            flags,
            payload_crc32,
            reserved,
        })
    }
}

/// Serializable vCPU architectural checkpoint record (`VcpuSnapshotRecord`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct VcpuSnapshotRecord {
    pub vcpu_id: u32,
    pub apic_id: u32,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub rax: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub tsc_offset: u64,
}

impl VcpuSnapshotRecord {
    pub const SIZE_BYTES: usize = 80;

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.vcpu_id.to_le_bytes());
        out.extend_from_slice(&self.apic_id.to_le_bytes());
        out.extend_from_slice(&self.rip.to_le_bytes());
        out.extend_from_slice(&self.rsp.to_le_bytes());
        out.extend_from_slice(&self.rflags.to_le_bytes());
        out.extend_from_slice(&self.rax.to_le_bytes());
        out.extend_from_slice(&self.cr0.to_le_bytes());
        out.extend_from_slice(&self.cr3.to_le_bytes());
        out.extend_from_slice(&self.cr4.to_le_bytes());
        out.extend_from_slice(&self.efer.to_le_bytes());
        out.extend_from_slice(&self.tsc_offset.to_le_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < Self::SIZE_BYTES {
            return Err("Buffer too small for VcpuSnapshotRecord");
        }
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ])
        };
        Ok(Self {
            vcpu_id: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            apic_id: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            rip: read_u64(8),
            rsp: read_u64(16),
            rflags: read_u64(24),
            rax: read_u64(32),
            cr0: read_u64(40),
            cr3: read_u64(48),
            cr4: read_u64(56),
            efer: read_u64(64),
            tsc_offset: read_u64(72),
        })
    }
}

/// Dirty guest RAM page chunk transmitted during pre-copy or stop-and-copy migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyRamPageChunk {
    pub gfn: u64,
    pub is_zero_page: bool,
    pub payload: Vec<u8>,
}

impl DirtyRamPageChunk {
    /// Creates a dirty page chunk, automatically compressing all-zero pages into a zero-length payload.
    pub fn from_slice(gfn: u64, page_bytes: &[u8]) -> Self {
        let all_zero = page_bytes.iter().all(|&b| b == 0);
        if all_zero {
            Self {
                gfn,
                is_zero_page: true,
                payload: Vec::new(),
            }
        } else {
            Self {
                gfn,
                is_zero_page: false,
                payload: page_bytes.to_vec(),
            }
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.gfn.to_le_bytes());
        let flags_and_len: u32 = if self.is_zero_page {
            1 << 31
        } else {
            (self.payload.len() as u32) & 0x7FFF_FFFF
        };
        out.extend_from_slice(&flags_and_len.to_le_bytes());
        if !self.is_zero_page {
            out.extend_from_slice(&self.payload);
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        if bytes.len() < 12 {
            return Err("Buffer too short for DirtyRamPageChunk header");
        }
        let gfn = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let flags_and_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let is_zero_page = (flags_and_len & (1 << 31)) != 0;
        let payload_len = (flags_and_len & 0x7FFF_FFFF) as usize;

        if is_zero_page {
            Ok((
                Self {
                    gfn,
                    is_zero_page: true,
                    payload: Vec::new(),
                },
                12,
            ))
        } else {
            if bytes.len() < 12 + payload_len {
                return Err("Truncated DirtyRamPageChunk payload");
            }
            let payload = bytes[12..12 + payload_len].to_vec();
            Ok((
                Self {
                    gfn,
                    is_zero_page: false,
                    payload,
                },
                12 + payload_len,
            ))
        }
    }
}

/// Serializes a complete VM checkpoint (header + vCPU records + dirty RAM chunks + CRC-32 verification).
pub fn serialize_vm_checkpoint(
    vcpus: &[VcpuSnapshotRecord],
    chunks: &[DirtyRamPageChunk],
    flags: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    for vcpu in vcpus {
        vcpu.encode(&mut payload);
    }
    for chunk in chunks {
        chunk.encode(&mut payload);
    }
    let crc = compute_crc32_ieee(&payload);
    let hdr = MigrationHeader::new(vcpus.len() as u32, chunks.len() as u32, flags, crc);

    let mut stream = Vec::with_capacity(MigrationHeader::SIZE_BYTES + payload.len());
    hdr.encode(&mut stream);
    stream.extend_from_slice(&payload);
    stream
}

/// Deserializes and verifies the CRC-32 checksum of a VM checkpoint stream.
pub fn deserialize_vm_checkpoint(
    stream: &[u8],
) -> Result<(MigrationHeader, Vec<VcpuSnapshotRecord>, Vec<DirtyRamPageChunk>), &'static str> {
    let hdr = MigrationHeader::decode(stream)?;
    let payload = &stream[MigrationHeader::SIZE_BYTES..];
    let computed_crc = compute_crc32_ieee(payload);
    if computed_crc != hdr.payload_crc32 {
        return Err("Migration stream CRC-32 integrity check failed");
    }

    let mut offset = 0usize;
    let mut vcpus = Vec::with_capacity(hdr.vcpu_count as usize);
    for _ in 0..hdr.vcpu_count {
        if offset + VcpuSnapshotRecord::SIZE_BYTES > payload.len() {
            return Err("Truncated vCPU records in migration payload");
        }
        let rec = VcpuSnapshotRecord::decode(&payload[offset..])?;
        vcpus.push(rec);
        offset += VcpuSnapshotRecord::SIZE_BYTES;
    }

    let mut chunks = Vec::with_capacity(hdr.dirty_page_chunks as usize);
    for _ in 0..hdr.dirty_page_chunks {
        let (chunk, consumed) = DirtyRamPageChunk::decode(&payload[offset..])?;
        chunks.push(chunk);
        offset += consumed;
    }

    Ok((hdr, vcpus, chunks))
}

/// Decision returned by the Live Migration Pre-Copy Convergence Estimator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreCopyConvergenceDecision {
    ContinuePreCopyIteration { estimated_downtime_ms: u64 },
    SwitchToStopAndCopy { estimated_downtime_ms: u64 },
    ActivateAutoConvergeThrottling { estimated_downtime_ms: u64 },
}

/// Evaluates whether iterative pre-copy live migration has converged within `target_downtime_ms`.
pub fn evaluate_precopy_convergence(
    remaining_dirty_pages: u64,
    page_dirty_rate_pps: u64,
    network_tx_rate_pps: u64,
    target_downtime_ms: u64,
    iteration: u32,
    max_iterations: u32,
) -> PreCopyConvergenceDecision {
    if network_tx_rate_pps == 0 {
        return PreCopyConvergenceDecision::ActivateAutoConvergeThrottling {
            estimated_downtime_ms: u64::MAX,
        };
    }

    let estimated_downtime_ms = (remaining_dirty_pages.saturating_mul(1_000)) / network_tx_rate_pps;
    if estimated_downtime_ms <= target_downtime_ms {
        return PreCopyConvergenceDecision::SwitchToStopAndCopy {
            estimated_downtime_ms,
        };
    }

    if page_dirty_rate_pps >= network_tx_rate_pps || iteration >= max_iterations {
        return PreCopyConvergenceDecision::ActivateAutoConvergeThrottling {
            estimated_downtime_ms,
        };
    }

    PreCopyConvergenceDecision::ContinuePreCopyIteration {
        estimated_downtime_ms,
    }
}
