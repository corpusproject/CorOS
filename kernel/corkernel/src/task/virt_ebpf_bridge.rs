//! CorOS Virtualization & eBPF Subsystem Bridge (`virt_ebpf_bridge.rs`)
//!
//! Integrates:
//! - `corvirt::hypercall_abi::{CorVirtHypercallDispatcher, HypercallOutcome, hypercall_opcodes}`
//! - `corvirt::vmx_intel::{VmcsRegion, VmExitReason, VmcsField}`
//! - `corvirt::svm_amd::{VmcbControlArea, SvmExitCode}`
//! - `corbpf::xdp_pipeline::{XdpPipeline, XdpContext, XdpAction, XdpStats}`
//! - `corbpf::kprobe_trace::{KprobeManager, TraceError, X86_INT3_OPCODE}`

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use corbpf::bpf_insn::BpfInsn;
use corbpf::kprobe_trace::{KprobeManager, TraceError};
use corbpf::xdp_pipeline::{XdpAction, XdpContext, XdpPipeline};
use corvirt::hypercall_abi::{hypercall_opcodes, CorVirtHypercallDispatcher, HypercallOutcome};
use corvirt::vcpu_scheduler::VcpuContext;
use corvirt::virq_chip::VirtualLocalApic;
use corvirt::vmx_intel::VmcsRegion;

pub struct VirtEbpfBridge {
    hypercall_dispatcher: SpinLock<CorVirtHypercallDispatcher>,
    kprobe_mgr: SpinLock<KprobeManager>,
    xdp_pipeline: SpinLock<Option<XdpPipeline>>,
    vmcs_regions: SpinLock<Vec<VmcsRegion>>,
}

unsafe impl Send for VirtEbpfBridge {}
unsafe impl Sync for VirtEbpfBridge {}

impl VirtEbpfBridge {
    pub const fn uninit() -> Self {
        Self {
            hypercall_dispatcher: SpinLock::new(CorVirtHypercallDispatcher::new(0)),
            kprobe_mgr: SpinLock::new(KprobeManager::new()),
            xdp_pipeline: SpinLock::new(None),
            vmcs_regions: SpinLock::new(Vec::new()),
        }
    }

    /// Initializes default XDP packet drop/pass filter and hypervisor dispatch tables.
    pub fn initialize(&self) {
        let mut xdp = self.xdp_pipeline.lock_irqsave();
        if xdp.is_none() {
            // Default pass-through eBPF program: mov r0, 2 (XDP_PASS); exit
            let default_prog = vec![
                BpfInsn::mov64_imm(0, 2),
                BpfInsn::exit_insn(),
            ];
            *xdp = Some(XdpPipeline::new(default_prog));
        }
        drop(xdp);

        let mut vmcs = self.vmcs_regions.lock_irqsave();
        if vmcs.is_empty() {
            // Allocate initial Host VMCS structure with revision 0x0000_0012
            vmcs.push(VmcsRegion::new(0x0000_0012));
        }
    }

    /// Dispatches an architectural `VMCALL` / `VMMCALL` hypercall from a guest VCPU.
    pub fn dispatch_hypercall(
        &self,
        vcpu: &mut VcpuContext,
        cpl: u8,
        insn_len: u64,
        lapics: &mut [VirtualLocalApic],
    ) -> HypercallOutcome {
        self.initialize();
        self.hypercall_dispatcher
            .lock_irqsave()
            .dispatch_hypercall(vcpu, cpl, insn_len, lapics)
    }

    /// Attaches an eBPF-driven dynamic `INT3` kprobe at kernel virtual address `target_va`.
    pub fn attach_kprobe(
        &self,
        symbol_name: &str,
        target_va: u64,
        code_bytes: &mut [u8],
        prog: Vec<BpfInsn>,
    ) -> Result<u32, TraceError> {
        self.initialize();
        self.kprobe_mgr
            .lock_irqsave()
            .attach_kprobe(symbol_name, target_va, code_bytes, prog)
    }

    /// Filters an incoming network packet through the XDP eBPF pipeline.
    pub fn process_xdp_packet(&self, raw_pkt: &[u8]) -> XdpAction {
        self.initialize();
        let mut xdp_guard = self.xdp_pipeline.lock_irqsave();
        if let Some(ref mut pipeline) = *xdp_guard {
            let mut ctx = XdpContext::from_packet(raw_pkt, 1, 0);
            pipeline.process_packet(&mut ctx).unwrap_or(XdpAction::Aborted)
        } else {
            XdpAction::Pass
        }
    }

    /// Returns the count of dispatched hypercalls.
    pub fn hypercall_count(&self) -> u64 {
        self.hypercall_dispatcher.lock_irqsave().total_hypercalls_dispatched
    }
}

pub static GLOBAL_VIRT_EBPF_BRIDGE: VirtEbpfBridge = VirtEbpfBridge::uninit();
