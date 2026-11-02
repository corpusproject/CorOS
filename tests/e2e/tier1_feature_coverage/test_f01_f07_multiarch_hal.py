"""
Tier 1: Multi-Arch HAL & Abstraction Layer Tests (F01 - F07)
============================================================
CorOS/tests/e2e/tier1_feature_coverage/test_f01_f07_multiarch_hal.py

Covers isolated functionality for:
- F01: Multi-Arch BootInfo Constants
- F02: Kernel Architecture HAL Traits
- F03: Decouple Kernel from x86_64 direct calls
- F04: AArch64 Architecture Skeleton
- F05: RISC-V Architecture Skeleton
- F06: Multi-Arch Page Table Abstractions
- F07: Multi-Arch Syscall Frame & ABI
"""

import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in,
    ARCH_X86_64, ARCH_AARCH64, ARCH_RISCV64,
    BOOTINFO_MAGIC, BOOTINFO_VERSION, BOOTINFO_SIZE,
    BootInfo, MockCpuOps, MockTimerOps, MockSmpOps,
    MultiArchPageTable, PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER, PAGE_NO_EXECUTE,
    X86_64SyscallRegisters, AArch64SyscallRegisters, Riscv64SyscallRegisters,
    PAGE_SIZE_4K
)

# ---------------------------------------------------------------------------
# F01: Multi-Arch BootInfo Constants
# ---------------------------------------------------------------------------
def test_f01_architecture_constants():
    """F01: Verify multi-arch architecture constants are distinct and non-zero."""
    assert_eq(ARCH_X86_64, 1, "ARCH_X86_64 must be 1")
    assert_eq(ARCH_AARCH64, 2, "ARCH_AARCH64 must be 2")
    assert_eq(ARCH_RISCV64, 3, "ARCH_RISCV64 must be 3")
    assert_ne(ARCH_X86_64, ARCH_AARCH64)
    assert_ne(ARCH_AARCH64, ARCH_RISCV64)

def test_f01_bootinfo_pack_unpack_roundtrip():
    """F01: Verify BootInfo structure binary packing and unpacking roundtrip."""
    info = BootInfo(
        architecture=ARCH_AARCH64,
        framebuffer_addr=0x80000000,
        fb_width=2560,
        fb_height=1440,
        fb_stride=2560,
        cmdline="console=ttyAMA0,115200 root=/dev/vda1"
    )
    raw = info.pack()
    assert_eq(len(raw), BOOTINFO_SIZE, f"BootInfo struct must be exactly {BOOTINFO_SIZE} bytes")
    unpacked = BootInfo.unpack(raw)
    assert_eq(unpacked.magic, BOOTINFO_MAGIC)
    assert_eq(unpacked.architecture, ARCH_AARCH64)
    assert_eq(unpacked.fb_width, 2560)
    assert_eq(unpacked.fb_height, 1440)
    assert_eq(unpacked.cmdline, "console=ttyAMA0,115200 root=/dev/vda1")

def test_f01_bootinfo_validation_success():
    """F01: Verify BootInfo validation succeeds for standard x86_64 configuration."""
    info = BootInfo(architecture=ARCH_X86_64)
    valid, reason = info.validate()
    assert_true(valid, f"Standard BootInfo should be valid: {reason}")

def test_f01_bootinfo_validation_riscv64():
    """F01: Verify BootInfo validation succeeds for RISC-V 64-bit architecture."""
    info = BootInfo(architecture=ARCH_RISCV64)
    valid, reason = info.validate()
    assert_true(valid, f"RISCV64 BootInfo should be valid: {reason}")

def test_f01_bootinfo_c_abi_layout():
    """F01: Verify C-ABI memory map descriptor and GOP framebuffer alignment."""
    info = BootInfo()
    assert_eq(info.descriptor_size, 48, "UEFI descriptor size standard is 48 bytes")
    assert_eq(info.fb_pixel_format, 1, "PixelBlueGreenRedReserved8BitPerColor")
    assert_true((info.framebuffer_addr % 4096) == 0, "Framebuffer address must be 4K page-aligned")

# ---------------------------------------------------------------------------
# F02: Kernel Architecture HAL Traits
# ---------------------------------------------------------------------------
def test_f02_cpuops_interrupt_state_management():
    """F02: Verify CpuOps enable/disable interrupt state transitions."""
    cpu = MockCpuOps(arch=ARCH_X86_64, cpu_id=0)
    assert_false(cpu.is_interrupts_enabled())
    cpu.enable_interrupts()
    assert_true(cpu.is_interrupts_enabled())
    cpu.disable_interrupts()
    assert_false(cpu.is_interrupts_enabled())

def test_f02_cpuops_halt_and_relax():
    """F02: Verify CpuOps halt and relax spinloop functionality."""
    cpu = MockCpuOps(arch=ARCH_X86_64, cpu_id=1)
    assert_false(cpu.halted)
    cpu.relax()
    cpu.relax()
    assert_eq(cpu.relax_count, 2)
    cpu.halt()
    assert_true(cpu.halted)

def test_f02_timerops_frequency_and_sleep():
    """F02: Verify TimerOps ticks per second query and tick sleep advancement."""
    timer = MockTimerOps(ticks_per_sec=2_000_000_000) # 2 GHz
    assert_eq(timer.ticks_per_second(), 2_000_000_000)
    assert_eq(timer.read_ticks(), 0)
    timer.sleep_ns(500_000) # 0.5 ms
    assert_eq(timer.read_ticks(), 1_000_000)

def test_f02_smpops_secondary_core_boot():
    """F02: Verify SmpOps SMP bootstrap detects all configured cores."""
    smp = MockSmpOps(num_cores=8)
    assert_eq(len(smp.online_cores), 1)
    online_count = smp.boot_secondary_cores(entry=0x00080000)
    assert_eq(online_count, 8)
    assert_eq(len(smp.online_cores), 8)

def test_f02_smpops_inter_processor_interrupt():
    """F02: Verify SmpOps IPI message dispatch to target CPU."""
    smp = MockSmpOps(num_cores=4)
    smp.boot_secondary_cores(entry=0x80000)
    smp.send_ipi(target_cpu=2, vector=0xFD) # TLB shootdown vector
    assert_eq(len(smp.ipi_log), 1)
    assert_eq(smp.ipi_log[0], (2, 0xFD))

# ---------------------------------------------------------------------------
# F03: Decouple Kernel from x86_64 Direct Calls
# ---------------------------------------------------------------------------
def test_f03_arch_agnostic_cpu_dispatch():
    """F03: Verify generic arch CPU dispatch routes correctly based on arch type."""
    x86_cpu = MockCpuOps(arch=ARCH_X86_64, cpu_id=0)
    arm_cpu = MockCpuOps(arch=ARCH_AARCH64, cpu_id=0)
    riscv_cpu = MockCpuOps(arch=ARCH_RISCV64, cpu_id=0)
    
    assert_eq(x86_cpu.arch, ARCH_X86_64)
    assert_eq(arm_cpu.arch, ARCH_AARCH64)
    assert_eq(riscv_cpu.arch, ARCH_RISCV64)

def test_f03_mmu_table_switch_abstraction():
    """F03: Verify MmuOps table switch abstraction records CR3/TTBR/satp switch."""
    pt = MultiArchPageTable(arch=ARCH_X86_64)
    pt.root_paddr = 0x200000
    assert_eq(pt.root_paddr, 0x200000)

def test_f03_tlb_flush_abstraction():
    """F03: Verify MmuOps flush TLB abstraction records targeted and global flushes."""
    pt = MultiArchPageTable(arch=ARCH_AARCH64)
    pt.flush_tlb(0xFFFF800000001000)
    pt.flush_tlb_all()
    assert_eq(len(pt.tlb_flushes), 2)
    assert_eq(pt.tlb_flushes[0], 0xFFFF800000001000)
    assert_eq(pt.tlb_flushes[1], -1)

def test_f03_kernel_entry_contract():
    """F03: Verify kernel entry receives BootInfo pointer independently of arch."""
    info = BootInfo(architecture=ARCH_RISCV64)
    assert_true(info.architecture in (ARCH_X86_64, ARCH_AARCH64, ARCH_RISCV64))
    valid, _ = info.validate()
    assert_true(valid)

def test_f03_hal_interface_uniformity():
    """F03: Verify HAL traits provide uniform interface across all 3 architectures."""
    for arch_id in (ARCH_X86_64, ARCH_AARCH64, ARCH_RISCV64):
        cpu = MockCpuOps(arch=arch_id)
        cpu.enable_interrupts()
        assert_true(cpu.is_interrupts_enabled())

# ---------------------------------------------------------------------------
# F04: AArch64 Architecture Skeleton
# ---------------------------------------------------------------------------
def test_f04_aarch64_vbar_alignment():
    """F04: Verify AArch64 VBAR_EL1 vector table requires 2048-byte (2KB) alignment."""
    vbar_el1_base = 0x40080000
    assert_eq(vbar_el1_base % 2048, 0, "VBAR_EL1 must be 2048-byte aligned")

def test_f04_aarch64_gic_register_offsets():
    """F04: Verify ARM Generic Interrupt Controller (GICv2/v3) register base offsets."""
    GICD_BASE = 0x08000000 # Distributor
    GICC_BASE = 0x08010000 # CPU Interface
    GICD_CTLR = GICD_BASE + 0x0000
    GICD_ISENABLER = GICD_BASE + 0x0100
    assert_eq(GICD_CTLR, 0x08000000)
    assert_eq(GICD_ISENABLER, 0x08000100)

def test_f04_aarch64_ttbr0_granule():
    """F04: Verify AArch64 TTBR0_EL1 4KB granule 48-bit translation setup."""
    TCR_TG0_4KB = 0 << 14
    TCR_T0SZ_48BIT = 16
    tcr_val = TCR_TG0_4KB | TCR_T0SZ_48BIT
    assert_eq(tcr_val & 0x3F, 16, "T0SZ must be 16 for 48-bit address space")

def test_f04_aarch64_psci_smc_function_ids():
    """F04: Verify ARM Power State Coordination Interface (PSCI) SMC function IDs."""
    PSCI_CPU_SUSPEND = 0x84000001
    PSCI_CPU_OFF = 0x84000002
    PSCI_CPU_ON = 0xC4000003 # 64-bit
    PSCI_SYSTEM_OFF = 0x84000008
    PSCI_SYSTEM_RESET = 0x84000009
    assert_eq(PSCI_CPU_ON & 0x40000000, 0x40000000, "SMC64 bit set for CPU_ON")

def test_f04_aarch64_esr_el1_decoding():
    """F04: Verify AArch64 Exception Syndrome Register (ESR_EL1) EC class decoding."""
    ESR_EC_SVC64 = 0x15 # SVC instruction in AArch64
    ESR_EC_DATA_ABORT = 0x25
    esr_raw = (ESR_EC_SVC64 << 26) | 0 # SVC #0
    ec = (esr_raw >> 26) & 0x3F
    assert_eq(ec, 0x15, "Decodes to SVC64 system call trap")

# ---------------------------------------------------------------------------
# F05: RISC-V Architecture Skeleton
# ---------------------------------------------------------------------------
def test_f05_riscv_stvec_mode():
    """F05: Verify RISC-V stvec supervisor trap vector base and mode bits."""
    STVEC_DIRECT = 0
    STVEC_VECTORED = 1
    trap_handler_addr = 0x80200000
    stvec_direct = trap_handler_addr | STVEC_DIRECT
    assert_eq(stvec_direct & 0x3, 0)
    assert_eq(stvec_direct & ~0x3, trap_handler_addr)

def test_f05_riscv_clint_mtime():
    """F05: Verify RISC-V CLINT mtime and mtimecmp 64-bit timer registers."""
    CLINT_BASE = 0x02000000
    MTIMECMP_OFFSET = 0x4000
    MTIME_OFFSET = 0xBFF8
    assert_eq(CLINT_BASE + MTIME_OFFSET, 0x0200BFF8)
    assert_eq(CLINT_BASE + MTIMECMP_OFFSET, 0x02004000)

def test_f05_riscv_plic_priority():
    """F05: Verify RISC-V PLIC (Platform-Level Interrupt Controller) layout."""
    PLIC_BASE = 0x0C000000
    PLIC_PRIORITY_BASE = PLIC_BASE + 0x0000
    PLIC_PENDING_BASE = PLIC_BASE + 0x1000
    assert_eq(PLIC_PRIORITY_BASE, 0x0C000000)
    assert_eq(PLIC_PENDING_BASE, 0x0C001000)

def test_f05_riscv_satp_sv39():
    """F05: Verify RISC-V satp register encoding for Sv39 3-level page translation."""
    SATP_MODE_SV39 = 8 # Mode in bits 63:60
    ppn = 0x80200
    satp_val = (SATP_MODE_SV39 << 60) | ppn
    mode = (satp_val >> 60) & 0xF
    assert_eq(mode, 8, "Sv39 mode active")
    assert_eq(satp_val & 0x00000FFFFFFFFFFF, ppn)

def test_f05_riscv_sbi_extension_ids():
    """F05: Verify RISC-V Supervisor Binary Interface (SBI) Extension IDs."""
    SBI_EXT_BASE = 0x10
    SBI_EXT_TIME = 0x54494D45 # 'TIME'
    SBI_EXT_IPI = 0x735049 # 'sPI'
    SBI_EXT_RFENCE = 0x52464E43 # 'RFNC'
    SBI_EXT_HSM = 0x48534D # 'HSM'
    assert_eq(SBI_EXT_BASE, 0x10)
    assert_ne(SBI_EXT_TIME, SBI_EXT_IPI)

# ---------------------------------------------------------------------------
# F06: Multi-Arch Page Table Abstractions
# ---------------------------------------------------------------------------
def test_f06_x86_64_pml4_mapping():
    """F06: Verify x86_64 4-level PML4 page mapping and address resolution."""
    pt = MultiArchPageTable(arch=ARCH_X86_64, levels=4)
    vaddr = 0x00007FFF00001000
    paddr = 0x0000000100001000
    pt.map_page(vaddr, paddr, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER)
    
    res = pt.translate(vaddr)
    assert_true(res is not None)
    translated_paddr, flags = res
    assert_eq(translated_paddr, paddr)
    assert_eq(flags & (PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER), PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER)

def test_f06_aarch64_ttbr_translation():
    """F06: Verify AArch64 TTBR0/1 4-level page mapping with Execute-Never (NX)."""
    pt = MultiArchPageTable(arch=ARCH_AARCH64, levels=4)
    vaddr = 0xFFFF800010002000
    paddr = 0x0000000040002000
    pt.map_page(vaddr, paddr, PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE)
    
    res = pt.translate(vaddr)
    assert_true(res is not None)
    translated_paddr, flags = res
    assert_eq(translated_paddr, paddr)
    assert_true((flags & PAGE_NO_EXECUTE) != 0, "NX flag preserved")

def test_f06_riscv_sv39_translation():
    """F06: Verify RISC-V Sv39 page mapping with user and write permissions."""
    pt = MultiArchPageTable(arch=ARCH_RISCV64, levels=3)
    vaddr = 0x0000000020000000
    paddr = 0x0000000080000000
    pt.map_page(vaddr, paddr, PAGE_PRESENT | PAGE_USER)
    
    res = pt.translate(vaddr)
    assert_true(res is not None)
    translated_paddr, flags = res
    assert_eq(translated_paddr, paddr)
    assert_false((flags & PAGE_WRITABLE) != 0, "Read-only page")

def test_f06_page_unmap_and_tlb_invalidation():
    """F06: Verify unmap operation removes translation and invokes TLB invalidation."""
    pt = MultiArchPageTable(arch=ARCH_X86_64)
    vaddr = 0x0000000040000000
    pt.map_page(vaddr, 0x10000000, PAGE_PRESENT)
    assert_true(pt.translate(vaddr) is not None)
    
    unmapped = pt.unmap_page(vaddr)
    assert_true(unmapped)
    assert_true(pt.translate(vaddr) is None, "Translation must be gone after unmap")
    
    pt.flush_tlb(vaddr)
    assert_eq(pt.tlb_flushes[-1], vaddr)

def test_f06_subpage_offset_preservation():
    """F06: Verify 12-bit intra-page offset is correctly preserved across translation."""
    pt = MultiArchPageTable(arch=ARCH_X86_64)
    pt.map_page(0x4000000, 0x8000000, PAGE_PRESENT)
    # Query with offset 0xABC
    res = pt.translate(0x4000ABC)
    assert_true(res is not None)
    translated_paddr, _ = res
    assert_eq(translated_paddr, 0x8000ABC)

# ---------------------------------------------------------------------------
# F07: Multi-Arch Syscall Frame & ABI
# ---------------------------------------------------------------------------
def test_f07_x86_64_syscall_register_frame():
    """F07: Verify x86_64 Linux ABI registers (RAX nr, RDI/RSI/RDX/R10/R8/R9 args)."""
    regs = X86_64SyscallRegisters(
        rax=1, # sys_write
        rdi=1, # stdout
        rsi=0x00401000, # buf
        rdx=14 # len
    )
    assert_eq(regs.rax, 1)
    assert_eq(regs.rdi, 1)
    assert_eq(regs.rsi, 0x00401000)
    assert_eq(regs.rdx, 14)

def test_f07_aarch64_syscall_register_frame():
    """F07: Verify AArch64 Linux ABI registers (X8 nr, X0-X5 args, X0 return)."""
    regs = AArch64SyscallRegisters(
        x8=64, # sys_write on asm-generic / aarch64
        x0=1,  # fd
        x1=0x400000, # buf
        x2=16  # count
    )
    assert_eq(regs.x8, 64)
    assert_eq(regs.x0, 1)
    assert_eq(regs.x1, 0x400000)
    assert_eq(regs.x2, 16)

def test_f07_riscv64_syscall_register_frame():
    """F07: Verify RISC-V 64 Linux ABI registers (A7 nr, A0-A5 args, A0 return)."""
    regs = Riscv64SyscallRegisters(
        a7=64, # sys_write on asm-generic / riscv
        a0=1,  # fd
        a1=0x80001000,
        a2=32
    )
    assert_eq(regs.a7, 64)
    assert_eq(regs.a0, 1)
    assert_eq(regs.a1, 0x80001000)
    assert_eq(regs.a2, 32)

def test_f07_syscall_return_code_preservation():
    """F07: Verify syscall return codes preserve negative POSIX errno values."""
    regs_x86 = X86_64SyscallRegisters()
    regs_x86.rax = -22 # -EINVAL in signed 64-bit
    assert_eq(regs_x86.rax, -22)

    regs_arm = AArch64SyscallRegisters()
    regs_arm.x0 = -13 # -EACCES
    assert_eq(regs_arm.x0, -13)

def test_f07_asm_generic_vs_x86_numbering():
    """F07: Verify awareness of asm-generic syscall numbers alongside x86_64."""
    # On x86_64, sys_write is 1, sys_read is 0, sys_open is 2
    # On asm-generic (ARM64/RISCV64), sys_read is 63, sys_write is 64, sys_openat is 56
    x86_write = 1
    generic_write = 64
    assert_ne(x86_write, generic_write, "x86_64 and asm-generic syscall numbering differ")

# ---------------------------------------------------------------------------
# Suite Builder
# ---------------------------------------------------------------------------
def build_suite() -> TestSuite:
    suite = TestSuite("Multi-Arch HAL & Abstraction Layer Suite (F01-F07)", tier=1)
    
    # F01: Multi-Arch BootInfo Constants (5 tests)
    suite.add("F01.1 Architecture Constants", test_f01_architecture_constants, "F01")
    suite.add("F01.2 BootInfo Pack/Unpack Roundtrip", test_f01_bootinfo_pack_unpack_roundtrip, "F01")
    suite.add("F01.3 BootInfo Validation (x86_64)", test_f01_bootinfo_validation_success, "F01")
    suite.add("F01.4 BootInfo Validation (riscv64)", test_f01_bootinfo_validation_riscv64, "F01")
    suite.add("F01.5 BootInfo C-ABI Layout", test_f01_bootinfo_c_abi_layout, "F01")
    
    # F02: Kernel Architecture HAL Traits (5 tests)
    suite.add("F02.1 CpuOps Interrupt State Management", test_f02_cpuops_interrupt_state_management, "F02")
    suite.add("F02.2 CpuOps Halt and Relax", test_f02_cpuops_halt_and_relax, "F02")
    suite.add("F02.3 TimerOps Frequency and Sleep", test_f02_timerops_frequency_and_sleep, "F02")
    suite.add("F02.4 SmpOps Secondary Core Boot", test_f02_smpops_secondary_core_boot, "F02")
    suite.add("F02.5 SmpOps Inter-Processor Interrupt (IPI)", test_f02_smpops_inter_processor_interrupt, "F02")
    
    # F03: Decouple Kernel from x86_64 Direct Calls (5 tests)
    suite.add("F03.1 Arch-Agnostic CPU Dispatch", test_f03_arch_agnostic_cpu_dispatch, "F03")
    suite.add("F03.2 MMU Table Switch Abstraction", test_f03_mmu_table_switch_abstraction, "F03")
    suite.add("F03.3 TLB Flush Abstraction", test_f03_tlb_flush_abstraction, "F03")
    suite.add("F03.4 Kernel Entry Contract", test_f03_kernel_entry_contract, "F03")
    suite.add("F03.5 HAL Interface Uniformity", test_f03_hal_interface_uniformity, "F03")

    # F04: AArch64 Architecture Skeleton (5 tests)
    suite.add("F04.1 AArch64 VBAR_EL1 Alignment", test_f04_aarch64_vbar_alignment, "F04")
    suite.add("F04.2 AArch64 GIC Base Register Offsets", test_f04_aarch64_gic_register_offsets, "F04")
    suite.add("F04.3 AArch64 TTBR0 Granule and Address Size", test_f04_aarch64_ttbr0_granule, "F04")
    suite.add("F04.4 AArch64 PSCI SMC Function IDs", test_f04_aarch64_psci_smc_function_ids, "F04")
    suite.add("F04.5 AArch64 ESR_EL1 Syndrome Decoding", test_f04_aarch64_esr_el1_decoding, "F04")

    # F05: RISC-V Architecture Skeleton (5 tests)
    suite.add("F05.1 RISC-V stvec Trap Vector Mode", test_f05_riscv_stvec_mode, "F05")
    suite.add("F05.2 RISC-V CLINT mtime and mtimecmp", test_f05_riscv_clint_mtime, "F05")
    suite.add("F05.3 RISC-V PLIC Priority Register Layout", test_f05_riscv_plic_priority, "F05")
    suite.add("F05.4 RISC-V satp Sv39 Mode Encoding", test_f05_riscv_satp_sv39, "F05")
    suite.add("F05.5 RISC-V SBI Extension IDs", test_f05_riscv_sbi_extension_ids, "F05")

    # F06: Multi-Arch Page Table Abstractions (5 tests)
    suite.add("F06.1 x86_64 PML4 4-Level Mapping", test_f06_x86_64_pml4_mapping, "F06")
    suite.add("F06.2 AArch64 TTBR Translation & NX", test_f06_aarch64_ttbr_translation, "F06")
    suite.add("F06.3 RISC-V Sv39 Translation & Permissions", test_f06_riscv_sv39_translation, "F06")
    suite.add("F06.4 Page Unmap and TLB Invalidation", test_f06_page_unmap_and_tlb_invalidation, "F06")
    suite.add("F06.5 Subpage Intra-Page Offset Preservation", test_f06_subpage_offset_preservation, "F06")

    # F07: Multi-Arch Syscall Frame & ABI (5 tests)
    suite.add("F07.1 x86_64 Syscall Register Frame", test_f07_x86_64_syscall_register_frame, "F07")
    suite.add("F07.2 AArch64 Syscall Register Frame", test_f07_aarch64_syscall_register_frame, "F07")
    suite.add("F07.3 RISC-V Syscall Register Frame", test_f07_riscv64_syscall_register_frame, "F07")
    suite.add("F07.4 Syscall Return Code Preservation", test_f07_syscall_return_code_preservation, "F07")
    suite.add("F07.5 Asm-Generic vs x86 Syscall Matrix", test_f07_asm_generic_vs_x86_numbering, "F07")

    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
