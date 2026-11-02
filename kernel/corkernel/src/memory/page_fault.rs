//! CorOS Advanced Page Fault (#PF Exception Vector 14) Engine (`page_fault.rs`)
//!
//! Handles x86_64 CPU Virtual Memory Page Faults:
//! - CR2 Fault Address inspection & CR3 Active PML4 Root
//! - Error Code Bit Analysis:
//!   - Bit 0 (P): Present (0 = Page not present, 1 = Page-level protection violation)
//!   - Bit 1 (W/R): Write (0 = Read access, 1 = Write access)
//!   - Bit 2 (U/S): User (0 = CPL 0 supervisor, 1 = CPL 3 userland)
//!   - Bit 3 (RSVD): Reserved bit violation in page directory entry
//!   - Bit 4 (I/D): Instruction Fetch (NX/XD execute disable violation)
//!   - Bit 5 (PK): Protection Key violation
//!   - Bit 6 (SS): Shadow Stack access violation
//! - Recovery Actions:
//!   - Demand Paging: Allocate zeroed frame for uncommitted anonymous VMA
//!   - Copy-on-Write (COW): Duplicate shared frame when ref_count > 1 and write is attempted
//!   - Stack Auto-Expansion: Grow userland stack VMA downwards within resource limits
//!   - Guard Page Violation: Detect stack overflow and prevent stack smashing
//!   - Fatal Segmentation Fault (SIGSEGV / STATUS_ACCESS_VIOLATION)

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const PF_ERR_PRESENT: u64 = 1 << 0;
pub const PF_ERR_WRITE: u64 = 1 << 1;
pub const PF_ERR_USER: u64 = 1 << 2;
pub const PF_ERR_RESERVED: u64 = 1 << 3;
pub const PF_ERR_INSTRUCTION: u64 = 1 << 4;
pub const PF_ERR_PROTECTION_KEY: u64 = 1 << 5;
pub const PF_ERR_SHADOW_STACK: u64 = 1 << 6;

/// Page Fault Resolution Action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    HandledDemandZero,
    HandledCow,
    HandledStackGrow,
    HandledSwapIn,
    FatalAccessViolation,
    FatalNullDeref,
    FatalStackOverflow,
    FatalInstructionExecution,
}

/// Structured Page Fault Error Code
#[derive(Debug, Clone, Copy)]
pub struct PageFaultErrorCode {
    pub raw: u64,
    pub is_present: bool,
    pub is_write: bool,
    pub is_user: bool,
    pub is_reserved_violation: bool,
    pub is_instruction_fetch: bool,
}

impl PageFaultErrorCode {
    pub fn from_raw(code: u64) -> Self {
        Self {
            raw: code,
            is_present: (code & PF_ERR_PRESENT) != 0,
            is_write: (code & PF_ERR_WRITE) != 0,
            is_user: (code & PF_ERR_USER) != 0,
            is_reserved_violation: (code & PF_ERR_RESERVED) != 0,
            is_instruction_fetch: (code & PF_ERR_INSTRUCTION) != 0,
        }
    }
}

/// Statistics for page fault handling
#[derive(Debug, Clone, Default)]
pub struct PageFaultStats {
    pub total_faults: u64,
    pub demand_zero_handled: u64,
    pub cow_breaks: u64,
    pub stack_growths: u64,
    pub swap_ins: u64,
    pub fatal_segvs: u64,
}

/// Complete Page Fault Handler Engine
pub struct PageFaultHandler {
    pub stats: PageFaultStats,
    pub user_stack_max_bytes: u64,
}

impl PageFaultHandler {
    pub fn new() -> Self {
        Self {
            stats: PageFaultStats::default(),
            user_stack_max_bytes: 8 * 1024 * 1024, // 8 MiB max stack
        }
    }

    /// Primary `#PF` handler dispatch routine with swap entry detection
    pub fn handle_fault_with_swap(
        &mut self,
        fault_addr: u64,
        error_code_raw: u64,
        rip: u64,
        user_rsp: u64,
        is_cow_page: bool,
        is_swap_page: bool,
    ) -> FaultAction {
        self.stats.total_faults += 1;
        let err = PageFaultErrorCode::from_raw(error_code_raw);

        // 1. Check for Null pointer dereference
        if fault_addr < 0x1000 {
            self.stats.fatal_segvs += 1;
            return FaultAction::FatalNullDeref;
        }

        // 2. Check for NX / Execute-Disable violation
        if err.is_instruction_fetch {
            self.stats.fatal_segvs += 1;
            return FaultAction::FatalInstructionExecution;
        }

        // 3. Check for Copy-On-Write (COW): Page is Present, Access is Write, and frame marked COW
        if err.is_present && err.is_write && is_cow_page {
            self.stats.cow_breaks += 1;
            return FaultAction::HandledCow;
        }

        // 4. Check for Demand Swap-In: Not Present and marked as swap entry (evaluated before stack grow)
        if !err.is_present && is_swap_page {
            self.stats.swap_ins += 1;
            return FaultAction::HandledSwapIn;
        }

        // 5. Check for User Stack auto-expansion
        // x86_64 allows faults within 128 bytes below RSP (Red Zone) or downwards from stack top
        if !is_swap_page && err.is_user && fault_addr >= user_rsp.saturating_sub(128) && fault_addr < 0x0000_7FFF_FFFF_0000 {
            let stack_top = 0x0000_7FFF_FFFF_0000u64;
            let current_stack_size = stack_top.saturating_sub(fault_addr);

            if current_stack_size <= self.user_stack_max_bytes {
                self.stats.stack_growths += 1;
                return FaultAction::HandledStackGrow;
            } else {
                self.stats.fatal_segvs += 1;
                return FaultAction::FatalStackOverflow;
            }
        }

        // 6. Check for Demand Paging (Not Present in uninitialized anonymous heap/mmap)
        if !err.is_present {
            // Allocate new zeroed 4 KiB frame
            self.stats.demand_zero_handled += 1;
            return FaultAction::HandledDemandZero;
        }

        // Default: Fatal segmentation fault
        self.stats.fatal_segvs += 1;
        let _ = rip;
        FaultAction::FatalAccessViolation
    }

    /// Primary `#PF` handler dispatch routine
    pub fn handle_fault(
        &mut self,
        fault_addr: u64,
        error_code_raw: u64,
        rip: u64,
        user_rsp: u64,
        is_cow_page: bool,
    ) -> FaultAction {
        self.handle_fault_with_swap(fault_addr, error_code_raw, rip, user_rsp, is_cow_page, false)
    }

    /// Format detailed crash diagnostic summary for fatal page fault
    pub fn format_crash_report(&self, fault_addr: u64, error_code: u64, rip: u64, rsp: u64) -> String {
        let err = PageFaultErrorCode::from_raw(error_code);
        let mut s = alloc::format!("KERNEL PANIC: #PF Page Fault at Virtual Address 0x{:016x}\n", fault_addr);
        s.push_str(&alloc::format!("Faulting Instruction Pointer (RIP): 0x{:016x}\n", rip));
        s.push_str(&alloc::format!("Stack Pointer (RSP):               0x{:016x}\n", rsp));
        s.push_str(&alloc::format!("Error Code: 0x{:04x} [ ", error_code));

        if err.is_present { s.push_str("PROTECTION_VIOLATION "); } else { s.push_str("NOT_PRESENT "); }
        if err.is_write { s.push_str("WRITE "); } else { s.push_str("READ "); }
        if err.is_user { s.push_str("USER_MODE "); } else { s.push_str("KERNEL_MODE "); }
        if err.is_instruction_fetch { s.push_str("INSTRUCTION_FETCH_NX "); }
        if err.is_reserved_violation { s.push_str("RESERVED_BIT "); }
        s.push_str("]\n");

        s
    }
}
