//! Dynamic Kernel Tracing (`kprobes`, `tracepoints`, and `PerfEventRing`).
//!
//! Implements dynamic instruction breakpoint patching (`0xCC` `INT3` saving original
//! opcode byte), static kernel tracepoint hooks, and a timestamped per-CPU
//! perf event sample ring.

use crate::bpf_insn::BpfInsn;
use crate::bpf_vm::BpfVm;
use alloc::string::String;
use alloc::vec::Vec;

/// Architectural x86_64 `INT3` software breakpoint opcode.
pub const X86_INT3_OPCODE: u8 = 0xCC;

/// Error returned by `KprobeManager` and `TracepointRegistry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceError {
    ProbeAlreadyAttached,
    ProbeNotFound,
    TargetSliceEmpty,
    TracepointAlreadyRegistered,
    TracepointNotFound,
}

/// Active dynamic kernel probe (`kprobe`) descriptor.
pub struct KprobeEntry {
    pub probe_id: u32,
    pub symbol_name: String,
    pub target_va: u64,
    pub saved_opcode: u8,
    pub armed: bool,
    pub hit_count: u64,
    pub bpf_prog: Vec<BpfInsn>,
}

/// Manages dynamic `kprobe` instruction patching (`0xCC` `INT3`) and execution.
pub struct KprobeManager {
    probes: Vec<KprobeEntry>,
    next_id: u32,
    vm: BpfVm,
}

impl KprobeManager {
    pub const fn new() -> Self {
        Self {
            probes: Vec::new(),
            next_id: 1,
            vm: BpfVm::new(),
        }
    }

    /// Attach a `kprobe` at `target_va`, saving `code_bytes[0]` and patching `0xCC` (`INT3`).
    pub fn attach_kprobe(
        &mut self,
        symbol_name: &str,
        target_va: u64,
        code_bytes: &mut [u8],
        bpf_prog: Vec<BpfInsn>,
    ) -> Result<u32, TraceError> {
        if code_bytes.is_empty() {
            return Err(TraceError::TargetSliceEmpty);
        }
        if self.probes.iter().any(|p| p.target_va == target_va && p.armed) {
            return Err(TraceError::ProbeAlreadyAttached);
        }

        let saved_opcode = code_bytes[0];
        code_bytes[0] = X86_INT3_OPCODE;

        let id = self.next_id;
        self.next_id += 1;
        self.probes.push(KprobeEntry {
            probe_id: id,
            symbol_name: String::from(symbol_name),
            target_va,
            saved_opcode,
            armed: true,
            hit_count: 0,
            bpf_prog,
        });
        Ok(id)
    }

    /// Detach a `kprobe` and restore its original instruction byte into `code_bytes[0]`.
    pub fn detach_kprobe(&mut self, probe_id: u32, code_bytes: &mut [u8]) -> Result<(), TraceError> {
        if code_bytes.is_empty() {
            return Err(TraceError::TargetSliceEmpty);
        }
        let pos = self
            .probes
            .iter()
            .position(|p| p.probe_id == probe_id && p.armed)
            .ok_or(TraceError::ProbeNotFound)?;

        let entry = &mut self.probes[pos];
        code_bytes[0] = entry.saved_opcode;
        entry.armed = false;
        Ok(())
    }

    /// Handle an `INT3` trap at `trap_va`, executing the attached eBPF probe with `pt_regs_ctx`.
    pub fn handle_breakpoint_trap(
        &mut self,
        trap_va: u64,
        pt_regs_ctx: &mut [u8],
        perf_ring: &mut PerfEventRing,
        cpu_id: u32,
        pid: u32,
        timestamp_ns: u64,
    ) -> Option<u64> {
        let probe = self
            .probes
            .iter_mut()
            .find(|p| p.target_va == trap_va && p.armed)?;
        probe.hit_count += 1;
        let ret = self.vm.execute(&probe.bpf_prog, pt_regs_ctx).ok()?;
        perf_ring.RecordSample(PerfTraceSample {
            timestamp_ns,
            cpu_id,
            pid,
            probe_id: probe.probe_id,
            return_value: ret,
        });
        Some(ret)
    }

    pub fn probe_hit_count(&self, probe_id: u32) -> Option<u64> {
        self.probes
            .iter()
            .find(|p| p.probe_id == probe_id)
            .map(|p| p.hit_count)
    }
}

impl Default for KprobeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Static kernel tracepoint entry (e.g., `sched:sched_switch`, `syscalls:sys_enter_read`).
pub struct TracepointSite {
    pub category: String,
    pub name: String,
    pub invocation_count: u64,
    pub bpf_prog: Vec<BpfInsn>,
}

/// Registry of static kernel tracepoints.
pub struct TracepointRegistry {
    sites: Vec<TracepointSite>,
    vm: BpfVm,
}

impl TracepointRegistry {
    pub const fn new() -> Self {
        Self {
            sites: Vec::new(),
            vm: BpfVm::new(),
        }
    }

    pub fn register_tracepoint(
        &mut self,
        category: &str,
        name: &str,
        bpf_prog: Vec<BpfInsn>,
    ) -> Result<(), TraceError> {
        if self
            .sites
            .iter()
            .any(|s| s.category == category && s.name == name)
        {
            return Err(TraceError::TracepointAlreadyRegistered);
        }
        self.sites.push(TracepointSite {
            category: String::from(category),
            name: String::from(name),
            invocation_count: 0,
            bpf_prog,
        });
        Ok(())
    }

    pub fn fire_tracepoint(
        &mut self,
        category: &str,
        name: &str,
        payload_ctx: &mut [u8],
    ) -> Result<u64, TraceError> {
        let site = self
            .sites
            .iter_mut()
            .find(|s| s.category == category && s.name == name)
            .ok_or(TraceError::TracepointNotFound)?;
        site.invocation_count += 1;
        Ok(self.vm.execute(&site.bpf_prog, payload_ctx).unwrap_or(0))
    }
}

impl Default for TracepointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamped perf trace event emitted by a `kprobe` or `tracepoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfTraceSample {
    pub timestamp_ns: u64,
    pub cpu_id: u32,
    pub pid: u32,
    pub probe_id: u32,
    pub return_value: u64,
}

/// Bounded circular buffer of `PerfTraceSample` events (`BPF_MAP_TYPE_PERF_EVENT_ARRAY` sink).
pub struct PerfEventRing {
    samples: Vec<PerfTraceSample>,
    capacity: usize,
    write_idx: usize,
    lost_samples: u64,
}

impl PerfEventRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
            capacity: capacity.max(1),
            write_idx: 0,
            lost_samples: 0,
        }
    }

    #[allow(non_snake_case)]
    pub fn RecordSample(&mut self, sample: PerfTraceSample) {
        if self.samples.len() < self.capacity {
            self.samples.push(sample);
            self.write_idx = (self.write_idx + 1) % self.capacity;
        } else {
            self.samples[self.write_idx] = sample;
            self.write_idx = (self.write_idx + 1) % self.capacity;
            self.lost_samples += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn samples(&self) -> &[PerfTraceSample] {
        &self.samples
    }
}
