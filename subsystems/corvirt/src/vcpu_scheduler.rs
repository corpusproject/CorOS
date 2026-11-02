//! Virtual CPU (`vCPU`) Execution Context, Run-Loop State Machine,
//! Adaptive Halt-Polling Window Calculator, and Paravirtual Steal-Time Accounting.

/// Execution state of a Virtual CPU in the hypervisor run loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuRunState {
    Runnable,
    RunningInGuest,
    HaltedWaitingForIrq,
    BlockedOnMmio,
    BlockedOnHypercall,
    CrashedTripleFault,
}

/// Guest 64-bit General-Purpose Registers saved/restored across VM-Entries and VM-Exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestGeneralRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// Guest Control, Debug, and Model-Specific System Registers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestSystemRegs {
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub efer: u64,
    pub pat: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub tsc_offset: u64,
}

/// KVM-compatible Paravirtual Steal-Time structure (`MSR_KVM_STEAL_TIME`).
/// Sequence counter is odd while an update is in progress and even when consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PvStealTime {
    pub steal_time_ns: u64,
    pub version_seq: u32,
    pub flags: u32,
    pub preempted_indicator: u8,
    pub pad: [u8; 47],
}

impl Default for PvStealTime {
    fn default() -> Self {
        Self::new()
    }
}

impl PvStealTime {
    /// Creates an initialized paravirtual steal-time page record.
    pub const fn new() -> Self {
        Self {
            steal_time_ns: 0,
            version_seq: 0,
            flags: 0,
            preempted_indicator: 0,
            pad: [0; 47],
        }
    }

    /// Atomically updates accumulated steal time in nanoseconds using seqlock semantics.
    pub fn record_steal_delta(&mut self, delta_ns: u64, currently_preempted: bool) {
        // Begin write critical section (odd version)
        self.version_seq = self.version_seq.wrapping_add(1);
        self.steal_time_ns = self.steal_time_ns.saturating_add(delta_ns);
        self.preempted_indicator = if currently_preempted { 1 } else { 0 };
        // Complete write critical section (even version)
        self.version_seq = self.version_seq.wrapping_add(1);
    }

    /// Serializes the first 16 bytes of the steal-time structure for guest memory writeback.
    pub fn to_guest_header_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.steal_time_ns.to_le_bytes());
        out[8..12].copy_from_slice(&self.version_seq.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out
    }
}

/// Adaptive Halt-Polling controller that dynamically grows and shrinks the host busy-wait
/// window before yielding the physical CPU when a vCPU executes `HLT`.
#[derive(Debug, Clone, Copy)]
pub struct HaltPollController {
    pub current_window_ns: u64,
    pub min_window_ns: u64,
    pub max_window_ns: u64,
    pub grow_multiplier: u64,
    pub grow_start_ns: u64,
    pub shrink_divisor: u64,
    pub successful_polls: u64,
    pub expired_polls: u64,
}

impl HaltPollController {
    /// Creates a KVM-grade adaptive halt-polling controller (default max 200 microseconds).
    pub const fn new(max_window_ns: u64) -> Self {
        Self {
            current_window_ns: 10_000, // 10 us initial window
            min_window_ns: 0,
            max_window_ns,
            grow_multiplier: 2,
            grow_start_ns: 10_000,
            shrink_divisor: 2,
            successful_polls: 0,
            expired_polls: 0,
        }
    }

    /// Updates the halt-polling window based on the actual `HLT` block duration (`block_duration_ns`)
    /// until the waking interrupt arrived.
    pub fn adjust_after_wakeup(&mut self, block_duration_ns: u64) -> u64 {
        if block_duration_ns <= self.current_window_ns {
            // Poll succeeded in catching the wakeup without sleeping!
            self.successful_polls += 1;
        } else if block_duration_ns <= self.max_window_ns {
            // Wakeup arrived shortly after poll expired, but within max_window_ns -> grow window
            self.expired_polls += 1;
            if self.current_window_ns == 0 {
                self.current_window_ns = self.grow_start_ns.min(self.max_window_ns);
            } else {
                self.current_window_ns = self
                    .current_window_ns
                    .saturating_mul(self.grow_multiplier)
                    .min(self.max_window_ns);
            }
        } else {
            // Long idle sleep (> max_window_ns) -> shrink poll window to avoid wasting host CPU
            self.expired_polls += 1;
            if self.shrink_divisor == 0 {
                self.current_window_ns = 0;
            } else {
                self.current_window_ns /= self.shrink_divisor;
                if self.current_window_ns < self.grow_start_ns {
                    self.current_window_ns = 0;
                }
            }
        }
        self.current_window_ns
    }
}

/// Complete per-vCPU architectural and scheduling context.
#[derive(Debug, Clone)]
pub struct VcpuContext {
    pub vcpu_id: u32,
    pub apic_id: u32,
    pub run_state: VcpuRunState,
    pub gprs: GuestGeneralRegs,
    pub sregs: GuestSystemRegs,
    pub halt_poll: HaltPollController,
    pub steal_time: PvStealTime,
    pub steal_time_gpa: Option<u64>,
    pub total_vm_entries: u64,
    pub total_vm_exits: u64,
    pub guest_instructions_retired: u64,
    pub pending_external_vector: Option<u8>,
}

impl VcpuContext {
    /// Creates a new vCPU context in real/unrestricted reset state (`CS:RIP = F000:FFF0`, `RFLAGS = 0x2`).
    pub fn new(vcpu_id: u32) -> Self {
        let mut gprs = GuestGeneralRegs::default();
        gprs.rip = 0xFFF0;
        gprs.rflags = 0x0000_0002;

        let mut sregs = GuestSystemRegs::default();
        sregs.cr0 = 0x6000_0010; // ET=1, CD=1, NW=1 at reset
        sregs.dr6 = 0xFFFF_0FF0;
        sregs.dr7 = 0x0000_0400;
        sregs.pat = 0x0007_0406_0007_0406;

        Self {
            vcpu_id,
            apic_id: vcpu_id,
            run_state: VcpuRunState::Runnable,
            gprs,
            sregs,
            halt_poll: HaltPollController::new(200_000),
            steal_time: PvStealTime::new(),
            steal_time_gpa: None,
            total_vm_entries: 0,
            total_vm_exits: 0,
            guest_instructions_retired: 0,
            pending_external_vector: None,
        }
    }

    /// Transitions the vCPU into guest execution (`VMLAUNCH`/`VMRESUME` or `VMRUN`) if runnable.
    pub fn enter_guest(&mut self, host_wait_delta_ns: u64) -> Result<(), &'static str> {
        if self.run_state == VcpuRunState::HaltedWaitingForIrq && self.pending_external_vector.is_some()
        {
            self.run_state = VcpuRunState::Runnable;
        }
        if self.run_state != VcpuRunState::Runnable {
            return Err("vCPU is not in Runnable state");
        }
        if host_wait_delta_ns > 0 {
            self.steal_time.record_steal_delta(host_wait_delta_ns, false);
        }
        self.run_state = VcpuRunState::RunningInGuest;
        self.total_vm_entries += 1;
        Ok(())
    }

    /// Handles a guest `HLT` exit and transitions to `HaltedWaitingForIrq` unless an interrupt is already pending.
    pub fn handle_hlt_exit(&mut self, instruction_length: u64) {
        self.total_vm_exits += 1;
        self.gprs.rip = self.gprs.rip.wrapping_add(instruction_length);
        if self.pending_external_vector.is_some() {
            self.run_state = VcpuRunState::Runnable;
        } else {
            self.run_state = VcpuRunState::HaltedWaitingForIrq;
        }
    }

    /// Delivers an external interrupt vector to the vCPU, waking it from `HLT` and updating the halt-poll window.
    pub fn notify_interrupt_wakeup(&mut self, vector: u8, halted_duration_ns: u64) {
        self.pending_external_vector = Some(vector);
        if self.run_state == VcpuRunState::HaltedWaitingForIrq {
            self.halt_poll.adjust_after_wakeup(halted_duration_ns);
            self.run_state = VcpuRunState::Runnable;
        }
    }

    /// Emulates a deterministic `CPUID` instruction exit and advances `RIP`.
    pub fn emulate_cpuid_exit(&mut self, instruction_length: u64) {
        self.total_vm_exits += 1;
        let leaf = self.gprs.rax as u32;
        match leaf {
            0x0000_0000 => {
                // Maximum standard leaf & "GenuineIntel" signature
                self.gprs.rax = 0x0000_0016;
                self.gprs.rbx = 0x756E_6547;
                self.gprs.rdx = 0x4965_6E69;
                self.gprs.rcx = 0x6C65_746E;
            }
            0x4000_0000 => {
                // Hypervisor CPUID leaf: "CorVirtKVM\0\0"
                self.gprs.rax = 0x4000_0001;
                self.gprs.rbx = 0x5672_6F43; // "CorV"
                self.gprs.rcx = 0x4B74_7269; // "irtK"
                self.gprs.rdx = 0x0000_4D56; // "VM\0\0"
            }
            0x4000_0001 => {
                // KVM paravirtual features: clocksource2 | nop_io_delay | pv_unhalt | steal_time
                self.gprs.rax = (1 << 3) | (1 << 1) | (1 << 7) | (1 << 9);
                self.gprs.rbx = 0;
                self.gprs.rcx = 0;
                self.gprs.rdx = 0;
            }
            _ => {
                self.gprs.rax = 0;
                self.gprs.rbx = 0;
                self.gprs.rcx = 1 << 31; // Hypervisor Present bit (ECX bit 31)
                self.gprs.rdx = 0;
            }
        }
        self.gprs.rip = self.gprs.rip.wrapping_add(instruction_length);
        self.run_state = VcpuRunState::Runnable;
    }
}
