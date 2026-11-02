use core::{arch::asm, sync::atomic::{fence, AtomicBool, AtomicU8, Ordering}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Cr3(pub u64);
const IA32_EFER: u32 = 0xc000_0080;
static NX_ENABLED: AtomicBool = AtomicBool::new(false);
// Unknown until CPUID confirms the physical-address width; users must treat
// zero as unavailable and fail closed rather than assume a 52-bit machine.
static PHYSICAL_ADDRESS_BITS: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingMode { Unknown, FourLevel, FiveLevel }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingSnapshot {
    pub mode: PagingMode,
    pub physical_address_bits: Option<u8>,
    pub nxe_enabled: bool,
    pub pke_enabled: bool,
    pub page_1g_supported: bool,
}

pub const fn classify_paging_mode(cr0: u64, cr4: u64, efer: u64) -> PagingMode {
    let pg = cr0 & (1 << 31) != 0;
    let pae = cr4 & (1 << 5) != 0;
    let la57 = cr4 & (1 << 12) != 0;
    let long_mode_active = efer & (1 << 10) != 0;
    if !pg || !pae || !long_mode_active { PagingMode::Unknown }
    else if la57 { PagingMode::FiveLevel }
    else { PagingMode::FourLevel }
}

/// Establishes bootstrap CPU state: maskable interrupts start disabled and
/// legacy x87/SSE state save/restore is enabled for interrupt entry stubs.
pub fn initialize() {
    disable_interrupts();
    let cr0 = (read_cr0() | (1 << 1) | (1 << 5)) & !((1 << 2) | (1 << 3));
    unsafe { write_cr0(cr0); }
    // x86_64 guarantees FXSAVE/SSE2; set the OS support bits before handlers
    // can run compiler-generated SSE code and preserve interrupted state.
    unsafe { write_cr4(read_cr4() | (1 << 9) | (1 << 10)); }
    let max_extended = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) }.eax;
    if max_extended >= 0x8000_0008 {
        let bits = unsafe { core::arch::x86_64::__cpuid(0x8000_0008) }.eax as u8;
        if physical_width_from_cpuid_value(bits).is_some() { PHYSICAL_ADDRESS_BITS.store(bits, Ordering::Release); }
    }
    if max_extended >= 0x8000_0001 {
        let features = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) }.edx;
        if features & (1 << 20) != 0 {
            // SAFETY: CPUID reports NX support; setting EFER.NXE enables PTE bit 63.
            let efer = unsafe { read_msr(IA32_EFER) };
            unsafe { write_msr(IA32_EFER, efer | (1 << 11)); }
            NX_ENABLED.store(true, Ordering::Release);
        }
    }
}

pub fn nx_enabled() -> bool { NX_ENABLED.load(Ordering::Acquire) }
pub fn physical_address_bits() -> Option<u8> {
    physical_width_from_cpuid_value(PHYSICAL_ADDRESS_BITS.load(Ordering::Acquire))
}

/// Captures the current mode without changing CR0, CR4, or EFER.
pub fn paging_snapshot() -> PagingSnapshot {
    let cr0 = read_cr0();
    let cr4 = read_cr4();
    let efer = unsafe { read_msr(IA32_EFER) };
    let max_extended = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) }.eax;
    let page_1g_supported = max_extended >= 0x8000_0001
        && unsafe { core::arch::x86_64::__cpuid(0x8000_0001) }.edx & (1 << 26) != 0;
    PagingSnapshot {
        mode: classify_paging_mode(cr0, cr4, efer),
        physical_address_bits: physical_address_bits(),
        nxe_enabled: efer & (1 << 11) != 0,
        pke_enabled: cr4 & (1 << 22) != 0,
        page_1g_supported,
    }
}

#[inline]
pub fn disable_interrupts() { unsafe { asm!("cli", options(nomem, nostack)); } }

/// Enables maskable interrupts. Call only after CorOS IDT and handlers are installed.
#[inline]
pub unsafe fn enable_interrupts() { asm!("sti", options(nomem, nostack)); }

#[inline]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem)); }
    flags & (1 << 9) != 0
}

#[inline]
pub fn halt() { unsafe { asm!("hlt", options(nomem, nostack)); } }

#[inline]
pub fn halt_forever() -> ! { loop { disable_interrupts(); halt(); } }

#[inline]
pub fn pause() { unsafe { asm!("pause", options(nomem, nostack)); } }

#[inline]
pub fn relax() {
    pause();
}

pub fn current_cpu_id() -> u32 {
    let max_std = unsafe { core::arch::x86_64::__cpuid(0) }.eax;
    if max_std >= 1 {
        let ebx = unsafe { core::arch::x86_64::__cpuid(1) }.ebx;
        (ebx >> 24) & 0xff
    } else {
        0
    }
}

pub struct X86Cpu;

impl crate::arch::traits::CpuOps for X86Cpu {
    fn halt() -> ! {
        halt_forever()
    }
    fn enable_interrupts() {
        unsafe { enable_interrupts(); }
    }
    fn disable_interrupts() {
        disable_interrupts();
    }
    fn interrupts_enabled() -> bool {
        interrupts_enabled()
    }
    fn relax() {
        relax();
    }
    fn current_cpu_id() -> u32 {
        current_cpu_id()
    }
}

#[inline]
pub fn memory_fence() { fence(Ordering::SeqCst); }

#[inline]
pub fn read_cr0() -> u64 { let value; unsafe { asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags)); } value }
#[inline]
pub fn read_cr2() -> u64 { let value; unsafe { asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags)); } value }
#[inline]
pub fn read_cr3() -> Cr3 { let value; unsafe { asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags)); } Cr3(value) }
#[inline]
pub fn read_cr4() -> u64 { let value; unsafe { asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags)); } value }

/// # Safety
/// The new CR0 value must preserve paging/protection invariants required by the active execution environment.
pub unsafe fn write_cr0(value: u64) { asm!("mov cr0, {}", in(reg) value, options(nostack, preserves_flags)); }

/// # Safety
/// Loading CR3 switches the active page directory. Caller must guarantee all code, stack,
/// and interrupt handlers are mapped in the target root.
pub unsafe fn write_cr3(value: u64) {
    asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags));
}

/// # Safety
/// Flushes the TLB entry for the specified virtual address.
#[inline]
pub unsafe fn invlpg(addr: u64) {
    asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags));
}

pub const IA32_PAT: u32 = 0x277;
pub const IA32_ENERGY_PERF_BIAS: u32 = 0x1b0;

/// Configures the Page Attribute Table (PAT) to enable Write-Combining (WC)
/// for high-performance framebuffer rendering alongside standard Write-Back (WB).
/// PA0: WB (0x06), PA1: WC (0x01), PA2: UC- (0x07), PA3: UC (0x00)
pub unsafe fn initialize_pat() {
    const PAT_VALUE: u64 = 0x0007_0106_0007_0106;
    write_msr(IA32_PAT, PAT_VALUE);
}

/// Enforces maximum hardware performance policy on CPU cores.
/// Sets Energy Performance Bias to 0 (Performance profile, no power-saving throttling)
/// ensuring maximum Turbo Boost clocks and lowest latency.
pub unsafe fn enable_maximum_performance() {
    let max = core::arch::x86_64::__cpuid(0).eax;
    if max >= 6 {
        let leaf6 = core::arch::x86_64::__cpuid(6);
        if leaf6.ecx & (1 << 3) != 0 {
            write_msr(IA32_ENERGY_PERF_BIAS, 0);
        }
    }
}

/// # Safety
/// The new CR4 value must only enable features supported and correctly configured by the CPU and kernel.
pub unsafe fn write_cr4(value: u64) { asm!("mov cr4, {}", in(reg) value, options(nostack, preserves_flags)); }

/// # Safety
/// The MSR must be implemented and readable at the current privilege level.
pub unsafe fn read_msr(index: u32) -> u64 {
    let low: u32; let high: u32;
    asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nomem, nostack));
    ((high as u64) << 32) | low as u64
}

/// # Safety
/// The MSR must be implemented and writable at the current privilege level; invalid values may fault or destabilize the CPU.
pub unsafe fn write_msr(index: u32, value: u64) {
    asm!("wrmsr", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nomem, nostack));
}

const fn physical_width_from_cpuid_value(bits: u8) -> Option<u8> {
    if bits >= 32 && bits <= 52 { Some(bits) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging_mode_requires_long_mode_paging_and_pae() {
        let cr0_pg = 1 << 31;
        let cr4_pae = 1 << 5;
        let efer_lma = 1 << 10;
        assert_eq!(classify_paging_mode(0, cr4_pae, efer_lma), PagingMode::Unknown);
        assert_eq!(classify_paging_mode(cr0_pg, cr4_pae, efer_lma), PagingMode::FourLevel);
        assert_eq!(classify_paging_mode(cr0_pg, cr4_pae | (1 << 12), efer_lma), PagingMode::FiveLevel);
        assert_eq!(classify_paging_mode(cr0_pg, 0, efer_lma), PagingMode::Unknown);
    }

    #[test]
    fn unknown_physical_width_is_not_reported_as_a_valid_width() {
        assert_eq!(physical_width_from_cpuid_value(0), None);
        assert_eq!(physical_width_from_cpuid_value(53), None);
        assert_eq!(physical_width_from_cpuid_value(48), Some(48));
    }
}

/// # Safety
/// Port access is privileged hardware I/O; caller must own/configure the device.
pub unsafe fn out8(port: u16, value: u8) { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }

/// # Safety
/// Port access is privileged hardware I/O; caller must own/configure the device.
pub unsafe fn in8(port: u16) -> u8 { let value; asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags)); value }

/// # Safety
/// Port access is privileged hardware I/O; caller must own/configure the device.
pub unsafe fn out16(port: u16, value: u16) { asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)); }

/// # Safety
/// Port access is privileged hardware I/O; caller must own/configure the device.
pub unsafe fn in16(port: u16) -> u16 { let value; asm!("in ax, dx", in("dx") port, out("ax") value, options(nomem, nostack, preserves_flags)); value }

/// # Safety
/// Port access is privileged hardware I/O; caller must own/configure the device.
pub unsafe fn out32(port: u16, value: u32) { asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)); }

/// # Safety
/// Port access is privileged hardware I/O; caller must own/configure the device.
pub unsafe fn in32(port: u16) -> u32 { let value; asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack, preserves_flags)); value }
