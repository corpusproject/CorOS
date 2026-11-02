//! Symmetric Multiprocessing (SMP) Subsystem for CorOS
//!
//! Handles secondary CPU core (Application Processors - APs) initialization,
//! low-memory trampoline installation at 0x8000, and parallel worker loop execution.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::arch::x86_64::{acpi::MadtInfo, apic, cpu};

pub const MAX_CORES: usize = 8;
pub const TRAMPOLINE_ADDR: usize = 0x8000;

#[repr(align(16))]
struct CoreStack([u8; 16384]); // 16 KiB per-core stack

static mut AP_STACKS: [CoreStack; MAX_CORES] = [
    CoreStack([0; 16384]),
    CoreStack([0; 16384]),
    CoreStack([0; 16384]),
    CoreStack([0; 16384]),
    CoreStack([0; 16384]),
    CoreStack([0; 16384]),
    CoreStack([0; 16384]),
    CoreStack([0; 16384]),
];

pub static ONLINE_CORES_COUNT: AtomicU32 = AtomicU32::new(1); // BSP starts online
pub static CORE_WORK_CYCLES: [AtomicU64; MAX_CORES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

core::arch::global_asm!(
    r#"
    .text
    .globl ap_trampoline_start
    .globl ap_trampoline_end
    .globl ap_cr3_val
    .globl ap_stack_ptr
    .globl ap_core_id
    .globl ap_entry_fn

    .code16
ap_trampoline_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    lgdtl (ap_gdt32_desc - ap_trampoline_start + 0x8000)

    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0

    ljmpl $0x08, $(ap_entry32 - ap_trampoline_start + 0x8000)

.code32
ap_entry32:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    movl (ap_cr3_val - ap_trampoline_start + 0x8000), %eax
    movl %eax, %cr3

    movl $0xc0000080, %ecx
    rdmsr
    orl $0x100, %eax
    wrmsr

    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0

    ljmpl $0x18, $(ap_entry64 - ap_trampoline_start + 0x8000)

.code64
ap_entry64:
    movw $0x20, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    // Load dedicated per-core stack before entering Rust
    movq (ap_stack_ptr - ap_trampoline_start + 0x8000), %rsp
    // Pass core_idx in %rdi
    movq (ap_core_id - ap_trampoline_start + 0x8000), %rdi
    // Jump to 64-bit Rust entry
    movq (ap_entry_fn - ap_trampoline_start + 0x8000), %rax
    jmpq *%rax

.align 16
ap_gdt32:
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
    .quad 0x00af92000000ffff

ap_gdt32_desc:
    .word . - ap_gdt32 - 1
    .long ap_gdt32 - ap_trampoline_start + 0x8000

.align 8
ap_cr3_val:
    .long 0

ap_stack_ptr:
    .quad 0

ap_core_id:
    .quad 0

ap_entry_fn:
    .quad 0

ap_trampoline_end:
    "#,
    options(att_syntax)
);

unsafe extern "efiapi" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
    static mut ap_cr3_val: u32;
    static mut ap_stack_ptr: u64;
    static mut ap_core_id: u64;
    static mut ap_entry_fn: u64;
}

#[no_mangle]
pub unsafe extern "C" fn ap_rust_entry(core_idx: usize) -> ! {
    // Initialize per-core CPU features
    cpu::initialize();
    cpu::initialize_pat();
    cpu::enable_maximum_performance();

    crate::arch::x86_64::gdt::initialize();
    crate::arch::x86_64::idt::initialize();

    if let Some(apic_info) = apic::detect_local_apic() {
        if let Some(apic_ptr) = core::ptr::NonNull::new(apic_info.physical_base as *mut u32) {
            let apic = apic::MappedLocalApic::from_mapped_mmio(apic_ptr);
            let _ = apic.enable_spurious_vector(39);
        }
    }

    cpu::enable_interrupts();
    ONLINE_CORES_COUNT.fetch_add(1, Ordering::SeqCst);

    // Enter high-performance parallel AP worker loop
    loop {
        if core_idx < MAX_CORES {
            CORE_WORK_CYCLES[core_idx].fetch_add(1, Ordering::Relaxed);
        }
        core::hint::spin_loop();
    }
}

/// Prepares the real-mode trampoline at 0x8000 and wakes up all APs via INIT-SIPI-SIPI.
pub unsafe fn initialize_smp(madt: &MadtInfo) -> u32 {
    let trampoline_src = core::ptr::addr_of!(ap_trampoline_start);
    let trampoline_len = core::ptr::addr_of!(ap_trampoline_end) as usize - trampoline_src as usize;

    let cr3 = cpu::read_cr3().0 as u32;
    let entry = ap_rust_entry as *const () as u64;

    let cr3_offset = core::ptr::addr_of!(ap_cr3_val) as usize - trampoline_src as usize;
    let stack_offset = core::ptr::addr_of!(ap_stack_ptr) as usize - trampoline_src as usize;
    let core_id_offset = core::ptr::addr_of!(ap_core_id) as usize - trampoline_src as usize;
    let entry_offset = core::ptr::addr_of!(ap_entry_fn) as usize - trampoline_src as usize;

    let dest = TRAMPOLINE_ADDR as *mut u8;
    core::ptr::copy_nonoverlapping(trampoline_src, dest, trampoline_len);

    // Store CR3 and 64-bit entry point at destination
    core::ptr::write_unaligned(dest.add(cr3_offset) as *mut u32, cr3);
    core::ptr::write_unaligned(dest.add(entry_offset) as *mut u64, entry);

    let apic_base = if madt.local_apic_address != 0 {
        madt.local_apic_address
    } else {
        0xFEE0_0000
    };
    let apic_mmio = apic_base as *mut u32;

    let bsp_apic_id = (*apic_mmio.add(0x20 / 4) >> 24) as u8;
    let mut next_core_idx = 1usize;

    // Awaken each detected secondary core sequentially
    for i in 0..madt.core_count {
        if let Some(core) = madt.cores[i] {
            if core.apic_id == bsp_apic_id || !core.enabled {
                continue;
            }

            if next_core_idx >= MAX_CORES {
                break;
            }

            // Assign dedicated 16 KiB stack and core index
            let stack_top = AP_STACKS[next_core_idx].0.as_mut_ptr().add(16384) as u64;
            core::ptr::write_unaligned(dest.add(stack_offset) as *mut u64, stack_top);
            core::ptr::write_unaligned(dest.add(core_id_offset) as *mut u64, next_core_idx as u64);

            let before_count = ONLINE_CORES_COUNT.load(Ordering::Acquire);

            // Send INIT IPI
            send_ipi(apic_mmio, core.apic_id, 0x00004500);
            delay_ms(10);

            // Send SIPI (vector 0x08 -> 0x8000)
            send_ipi(apic_mmio, core.apic_id, 0x00004608);
            delay_us(200);

            // Send second SIPI
            send_ipi(apic_mmio, core.apic_id, 0x00004608);

            // Wait up to 30ms for core to signal online
            let wait_start = crate::time::TscCounter::read_ticks().0;
            let timeout_cycles = 30 * crate::time::detect_cpu_frequency_mhz() * 1000;
            while ONLINE_CORES_COUNT.load(Ordering::Acquire) == before_count {
                if crate::time::TscCounter::read_ticks().0.saturating_sub(wait_start) > timeout_cycles {
                    break;
                }
                core::hint::spin_loop();
            }

            next_core_idx += 1;
        }
    }

    ONLINE_CORES_COUNT.load(Ordering::Acquire)
}

unsafe fn send_ipi(apic_mmio: *mut u32, target_apic_id: u8, command: u32) {
    let icr_high = apic_mmio.add(0x310 / 4);
    let icr_low = apic_mmio.add(0x300 / 4);

    // Set destination APIC ID in bits 24..31
    core::ptr::write_volatile(icr_high, (target_apic_id as u32) << 24);
    // Write command
    core::ptr::write_volatile(icr_low, command);

    // Wait for delivery status bit 12 to clear
    for _ in 0..10_000 {
        if (core::ptr::read_volatile(icr_low) & (1 << 12)) == 0 {
            break;
        }
        core::hint::spin_loop();
    }
}

fn delay_ms(ms: u64) {
    let start = crate::time::TscCounter::read_ticks().0;
    let cpu_mhz = crate::time::detect_cpu_frequency_mhz();
    let cycles = ms * cpu_mhz * 1000;
    while crate::time::TscCounter::read_ticks().0.saturating_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

fn delay_us(us: u64) {
    let start = crate::time::TscCounter::read_ticks().0;
    let cpu_mhz = crate::time::detect_cpu_frequency_mhz();
    let cycles = us * cpu_mhz;
    while crate::time::TscCounter::read_ticks().0.saturating_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

pub struct X86Smp;

impl crate::arch::traits::SmpOps for X86Smp {
    fn boot_secondary_cores(entry: u64) -> u32 {
        let _ = entry;
        ONLINE_CORES_COUNT.load(Ordering::Acquire)
    }

    fn send_ipi(target_cpu: u32, vector: u8) {
        broadcast_ipi(target_cpu, vector);
    }
}

pub fn boot_secondary_cores(entry: u64) -> u32 {
    let _ = entry;
    ONLINE_CORES_COUNT.load(Ordering::Acquire)
}

pub fn broadcast_ipi(target_cpu: u32, vector: u8) {
    let apic_base = if let Some(apic_info) = apic::detect_local_apic() {
        apic_info.physical_base as *mut u32
    } else {
        0xFEE0_0000 as *mut u32
    };
    unsafe {
        send_ipi(apic_base, target_cpu as u8, 0x0000_4000 | (vector as u32));
    }
}
