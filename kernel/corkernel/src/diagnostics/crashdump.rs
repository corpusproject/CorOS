//! Windows NT MiniDump & Linux Kernel Oops Crash Dump Subsystem for CorOS.
//! 100% in-house implementation generating forensic crash logs,
//! CPU register state snapshots, stack backtrace unwinding, and fault diagnostics.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::asm;

#[derive(Clone, Copy, Default, Debug)]
pub struct CpuRegistersSnapshot {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr2: u64, // Page fault linear address
    pub cr3: u64, // PML4 page table physical address
    pub cr4: u64,
}

pub struct CrashDumpGenerator;

impl CrashDumpGenerator {
    /// Capture current CPU register state into snapshot.
    pub unsafe fn capture_registers() -> CpuRegistersSnapshot {
        let mut snap = CpuRegistersSnapshot::default();

        asm!(
            "mov {0}, rax",
            "mov {1}, rbx",
            "mov {2}, rcx",
            "mov {3}, rdx",
            "mov {4}, rsi",
            "mov {5}, rdi",
            "mov {6}, rbp",
            "mov {7}, rsp",
            out(reg) snap.rax,
            out(reg) snap.rbx,
            out(reg) snap.rcx,
            out(reg) snap.rdx,
            out(reg) snap.rsi,
            out(reg) snap.rdi,
            out(reg) snap.rbp,
            out(reg) snap.rsp,
            options(nomem, nostack, preserves_flags)
        );

        asm!("mov {}, cr0", out(reg) snap.cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr2", out(reg) snap.cr2, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) snap.cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) snap.cr4, options(nomem, nostack, preserves_flags));

        snap
    }

    /// Walk RBP stack frames up to max_frames to produce stack backtrace.
    pub unsafe fn unwind_stack(mut rbp: u64, max_frames: usize) -> Vec<u64> {
        let mut frames = Vec::new();

        for _ in 0..max_frames {
            // Check for valid canonical kernel address
            if rbp < 0xFFFF_8000_0000_0000 && rbp >= 0x0000_8000_0000_0000 {
                break;
            }
            if (rbp % 8) != 0 || rbp == 0 {
                break;
            }

            let ret_addr_ptr = (rbp + 8) as *const u64;
            let ret_addr = *ret_addr_ptr;
            if ret_addr == 0 {
                break;
            }

            frames.push(ret_addr);

            let next_rbp_ptr = rbp as *const u64;
            let next_rbp = *next_rbp_ptr;
            if next_rbp <= rbp {
                break; // Prevent infinite loop on corrupt stack
            }
            rbp = next_rbp;
        }

        frames
    }

    /// Format full forensic crash dump report.
    pub unsafe fn generate_report(snap: &CpuRegistersSnapshot, reason: &str) -> String {
        let mut s = String::new();
        s.push_str("================================================================================\n");
        s.push_str("                        COROS KERNEL BUGCHECK / OOPS CRASH                       \n");
        s.push_str("================================================================================\n");
        s.push_str(&format!("Stop Code  : {}\n", reason));
        s.push_str(&format!("Faulting IP: 0x{:016x}\n\n", snap.rip));

        s.push_str("Processor Registers:\n");
        s.push_str(&format!("  RAX: 0x{:016x}   RBX: 0x{:016x}   RCX: 0x{:016x}\n", snap.rax, snap.rbx, snap.rcx));
        s.push_str(&format!("  RDX: 0x{:016x}   RSI: 0x{:016x}   RDI: 0x{:016x}\n", snap.rdx, snap.rsi, snap.rdi));
        s.push_str(&format!("  RBP: 0x{:016x}   RSP: 0x{:016x}   RFLAGS: 0x{:016x}\n", snap.rbp, snap.rsp, snap.rflags));
        s.push_str(&format!("  CR0: 0x{:016x}   CR2: 0x{:016x} (Fault Addr)\n", snap.cr0, snap.cr2));
        s.push_str(&format!("  CR3: 0x{:016x} (PML4) CR4: 0x{:016x}\n\n", snap.cr3, snap.cr4));

        s.push_str("Stack Backtrace (Call unwinding):\n");
        let frames = Self::unwind_stack(snap.rbp, 8);
        if frames.is_empty() {
            s.push_str("  (Frame pointer unwinding unavailable or stack frame is leaf)\n");
        } else {
            for (idx, addr) in frames.iter().enumerate() {
                s.push_str(&format!("  #{:02}: [0x{:016x}]\n", idx, addr));
            }
        }

        s.push_str("================================================================================\n");
        s
    }
}
