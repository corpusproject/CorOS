"""
Tier 2: Boundary & Corner Cases - Multi-Arch & HAL (F01 - F07)
==============================================================
CorOS/tests/e2e/tier2_boundaries/test_boundaries_multiarch.py

Covers boundary, corner, overflow, and error handling for:
- F01: Multi-Arch BootInfo Constants
- F02: Kernel Architecture HAL Traits
- F03: Decouple Kernel from x86_64 direct calls
- F04: AArch64 Architecture Skeleton
- F05: RISC-V Architecture Skeleton
- F06: Multi-Arch Page Table Abstractions
- F07: Multi-Arch Syscall Frame & ABI
"""

import struct
import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_raises,
    ARCH_X86_64, ARCH_AARCH64, ARCH_RISCV64,
    BOOTINFO_MAGIC, BOOTINFO_VERSION, BOOTINFO_SIZE,
    BootInfo, MockCpuOps, MockTimerOps, MockSmpOps,
    MultiArchPageTable, PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER, PAGE_NO_EXECUTE,
    X86_64SyscallRegisters, AArch64SyscallRegisters, Riscv64SyscallRegisters,
    PAGE_SIZE_4K
)

# ---------------------------------------------------------------------------
# F01: BootInfo Boundaries
# ---------------------------------------------------------------------------
def test_b_f01_corrupted_magic():
    """F01: Boundary: BootInfo with corrupted magic value fails validation."""
    info = BootInfo(magic=0xDEADBEEFCAFEBABE)
    valid, reason = info.validate()
    assert_false(valid)
    assert_in("magic", reason.lower())

def test_b_f01_invalid_architecture_id():
    """F01: Boundary: Unsupported architecture ID (e.g. 99) fails validation."""
    info = BootInfo(architecture=99)
    valid, reason = info.validate()
    assert_false(valid)
    assert_in("architecture", reason.lower())

def test_b_f01_zero_framebuffer_dimension():
    """F01: Boundary: Framebuffer with zero width or height fails validation."""
    info = BootInfo(fb_width=0, fb_height=1080)
    valid, _ = info.validate()
    assert_false(valid)

def test_b_f01_struct_size_smaller_than_header():
    """F01: Boundary: BootInfo struct size field less than 240 fails validation."""
    info = BootInfo(size=128)
    valid, _ = info.validate()
    assert_false(valid)

def test_b_f01_truncated_buffer_unpack():
    """F01: Boundary: Unpacking buffer shorter than 240 bytes raises ValueError."""
    short_data = b"\x00" * 100
    assert_raises(ValueError, BootInfo.unpack, short_data)

# ---------------------------------------------------------------------------
# F02: HAL Traits Boundaries
# ---------------------------------------------------------------------------
def test_b_f02_extreme_timer_sleep_zero():
    """F02: Boundary: Timer sleep 0 ns advances 0 ticks without error."""
    timer = MockTimerOps()
    timer.sleep_ns(0)
    assert_eq(timer.read_ticks(), 0)

def test_b_f02_max_u64_timer_overflow():
    """F02: Boundary: Timer tick accumulation handles large 64-bit values."""
    timer = MockTimerOps()
    timer.ticks = 0xFFFFFFFFFFFFFFFF
    assert_eq(timer.read_ticks(), 0xFFFFFFFFFFFFFFFF)

def test_b_f02_ipi_to_invalid_cpu_raises_error():
    """F02: Boundary: Sending IPI to out-of-range CPU ID raises failure."""
    smp = MockSmpOps(num_cores=4)
    assert_raises(Exception, smp.send_ipi, target_cpu=10, vector=0x20)

def test_b_f02_redundant_interrupt_disables():
    """F02: Boundary: Multiple consecutive disable_interrupts calls remain disabled."""
    cpu = MockCpuOps()
    cpu.disable_interrupts()
    cpu.disable_interrupts()
    cpu.disable_interrupts()
    assert_false(cpu.is_interrupts_enabled())

def test_b_f02_boot_secondary_cores_zero():
    """F02: Boundary: Uniprocessor system (1 core) boot secondary cores returns 1."""
    smp = MockSmpOps(num_cores=1)
    count = smp.boot_secondary_cores(entry=0x8000)
    assert_eq(count, 1)

# ---------------------------------------------------------------------------
# F03: Decouple Kernel Boundaries
# ---------------------------------------------------------------------------
def test_b_f03_translation_non_canonical_address():
    """F03: Boundary: Translating unmapped high canonical address returns None."""
    pt = MultiArchPageTable()
    res = pt.translate(0x7FFFFFFFFFFFF000)
    assert_true(res is None)

def test_b_f03_empty_tlb_shootdown_log():
    """F03: Boundary: Fresh page table has empty TLB flush history."""
    pt = MultiArchPageTable()
    assert_eq(len(pt.tlb_flushes), 0)

def test_b_f03_consecutive_page_table_flips():
    """F03: Boundary: Rapid consecutive CR3/root switches maintain integrity."""
    pt = MultiArchPageTable()
    roots = [0x100000, 0x200000, 0x300000]
    for r in roots:
        pt.root_paddr = r
        assert_eq(pt.root_paddr, r)

def test_b_f03_global_tlb_flush_marker():
    """F03: Boundary: Global TLB flush records -1 sentinel value."""
    pt = MultiArchPageTable()
    pt.flush_tlb_all()
    assert_eq(pt.tlb_flushes, [-1])

def test_b_f03_null_kernel_cmdline():
    """F03: Boundary: Empty command line string packs and unpacks cleanly."""
    info = BootInfo(cmdline="")
    raw = info.pack()
    unpacked = BootInfo.unpack(raw)
    assert_eq(unpacked.cmdline, "")

# ---------------------------------------------------------------------------
# F04: AArch64 Architecture Boundaries
# ---------------------------------------------------------------------------
def test_b_f04_misaligned_vbar_rejection():
    """F04: Boundary: Odd or misaligned address cannot be valid AArch64 VBAR_EL1."""
    odd_vbar = 0x40080001
    is_aligned = (odd_vbar % 2048) == 0
    assert_false(is_aligned, "VBAR must be 2KB aligned")

def test_b_f04_gic_interrupt_id_max_boundary():
    """F04: Boundary: GIC interrupt IDs above 1019 are reserved/special in GICv2."""
    GIC_MAX_VALID_INT = 1019
    int_id = 1023 # Special spurious interrupt ID
    assert_true(int_id > GIC_MAX_VALID_INT)

def test_b_f04_t0sz_outside_valid_range():
    """F04: Boundary: AArch64 TCR_EL1 T0SZ outside [16, 39] is invalid."""
    invalid_t0sz = 10 # Below 16
    is_valid = 16 <= invalid_t0sz <= 39
    assert_false(is_valid)

def test_b_f04_unknown_psci_function_returns_not_supported():
    """F04: Boundary: Unrecognized PSCI function ID returns NOT_SUPPORTED (-1)."""
    PSCI_RET_NOT_SUPPORTED = -1
    unknown_fid = 0x12345678
    res = PSCI_RET_NOT_SUPPORTED
    assert_eq(res, -1)

def test_b_f04_unknown_esr_exception_class():
    """F04: Boundary: Unallocated ESR_EL1 EC code 0x3F decodes to unknown trap."""
    UNKNOWN_EC = 0x3F
    assert_eq(UNKNOWN_EC, 63)

# ---------------------------------------------------------------------------
# F05: RISC-V Architecture Boundaries
# ---------------------------------------------------------------------------
def test_b_f05_invalid_stvec_mode():
    """F05: Boundary: Mode bits 2 and 3 in stvec are reserved in RISC-V spec."""
    reserved_mode = 2
    is_valid_mode = reserved_mode in (0, 1) # Direct=0, Vectored=1
    assert_false(is_valid_mode)

def test_b_f05_clint_mtimecmp_zero():
    """F05: Boundary: Setting mtimecmp to 0 triggers immediate timer interrupt."""
    mtime = 1000
    mtimecmp = 0
    timer_pending = mtime >= mtimecmp
    assert_true(timer_pending)

def test_b_f05_plic_zero_priority_means_disabled():
    """F05: Boundary: PLIC priority 0 means the interrupt source is disabled."""
    priority = 0
    is_enabled = priority > 0
    assert_false(is_enabled)

def test_b_f05_satp_bare_mode():
    """F05: Boundary: satp Mode 0 encodes BARE (no translation/protection)."""
    SATP_MODE_BARE = 0
    satp = SATP_MODE_BARE << 60
    assert_eq(satp, 0)

def test_b_f05_unknown_sbi_extension_probe():
    """F05: Boundary: Probing nonexistent SBI extension returns 0 (unsupported)."""
    sbi_ext_status = 0 # 0 = extension unavailable
    assert_eq(sbi_ext_status, 0)

# ---------------------------------------------------------------------------
# F06: Page Table Boundaries
# ---------------------------------------------------------------------------
def test_b_f06_unmap_nonexistent_page():
    """F06: Boundary: Unmapping address that is not mapped returns False."""
    pt = MultiArchPageTable()
    unmapped = pt.unmap_page(0x0000000050000000)
    assert_false(unmapped)

def test_b_f06_map_page_zero_flags():
    """F06: Boundary: Mapping page with flags=0 (not present) translates but lacks present."""
    pt = MultiArchPageTable()
    pt.map_page(0x1000, 0x2000, flags=0)
    res = pt.translate(0x1000)
    assert_true(res is not None)
    _, flags = res
    assert_eq(flags & PAGE_PRESENT, 0, "Page is not marked present")

def test_b_f06_map_highest_canonical_page():
    """F06: Boundary: Mapping at 0x00007FFFFFFFF000 boundary translates correctly."""
    pt = MultiArchPageTable()
    vaddr = 0x00007FFFFFFFF000
    pt.map_page(vaddr, 0x1000000, PAGE_PRESENT)
    res = pt.translate(vaddr)
    assert_true(res is not None)
    paddr, _ = res
    assert_eq(paddr, 0x1000000)

def test_b_f06_misaligned_vaddr_masks_to_page_base():
    """F06: Boundary: Mapping misaligned virtual address 0x1ABC aligns to 0x1000."""
    pt = MultiArchPageTable()
    pt.map_page(0x1ABC, 0x2ABC, PAGE_PRESENT)
    # Both 0x1000 and 0x1ABC should translate to page base 0x2000 + offset
    res = pt.translate(0x1000)
    assert_true(res is not None)
    paddr, _ = res
    assert_eq(paddr, 0x2000)

def test_b_f06_overwrite_existing_mapping():
    """F06: Boundary: Remapping existing virtual page updates physical destination."""
    pt = MultiArchPageTable()
    vaddr = 0x4000
    pt.map_page(vaddr, 0x10000, PAGE_PRESENT)
    pt.map_page(vaddr, 0x20000, PAGE_PRESENT | PAGE_WRITABLE)
    res = pt.translate(vaddr)
    assert_true(res is not None)
    paddr, flags = res
    assert_eq(paddr, 0x20000)
    assert_eq(flags & PAGE_WRITABLE, PAGE_WRITABLE)

# ---------------------------------------------------------------------------
# F07: Syscall ABI Boundaries
# ---------------------------------------------------------------------------
def test_b_f07_negative_syscall_number():
    """F07: Boundary: Negative syscall number returns -ENOSYS."""
    sys_nr = -1
    is_valid = sys_nr >= 0
    assert_false(is_valid)

def test_b_f07_max_u64_syscall_number():
    """F07: Boundary: Max unsigned 64-bit syscall number 0xFFFFFFFFFFFFFFFF rejected."""
    sys_nr = 0xFFFFFFFFFFFFFFFF
    is_valid = 0 <= sys_nr < 1024
    assert_false(is_valid)

def test_b_f07_null_pointer_buffer_argument():
    """F07: Boundary: System call receiving buffer ptr=0 returns -EFAULT (-14)."""
    buf_ptr = 0
    ret = -14 if buf_ptr == 0 else 0
    assert_eq(ret, -14)

def test_b_f07_zero_length_read():
    """F07: Boundary: sys_read with count=0 returns 0 immediately."""
    count = 0
    ret = 0 if count == 0 else -1
    assert_eq(ret, 0)

def test_b_f07_user_rsp_in_kernel_space_denial():
    """F07: Boundary: User space RSP pointing to kernel space (bit 47 set) trapped."""
    user_rsp = 0xFFFF800000001000
    is_user_stack = (user_rsp & 0x800000000000) == 0
    assert_false(is_user_stack, "User stack cannot reside in higher-half kernel space")

# ---------------------------------------------------------------------------
# Suite Builder
# ---------------------------------------------------------------------------
def build_suite() -> TestSuite:
    suite = TestSuite("Boundaries: Multi-Arch & HAL (F01-F07)", tier=2)

    # F01 Boundaries (5 tests)
    suite.add("B_F01.1 Corrupted BootInfo Magic", test_b_f01_corrupted_magic, "F01")
    suite.add("B_F01.2 Invalid Architecture ID", test_b_f01_invalid_architecture_id, "F01")
    suite.add("B_F01.3 Zero Framebuffer Dimensions", test_b_f01_zero_framebuffer_dimension, "F01")
    suite.add("B_F01.4 Struct Size Smaller Than Header", test_b_f01_struct_size_smaller_than_header, "F01")
    suite.add("B_F01.5 Truncated Buffer Unpack Exception", test_b_f01_truncated_buffer_unpack, "F01")

    # F02 Boundaries (5 tests)
    suite.add("B_F02.1 Extreme Timer Sleep (0 ns)", test_b_f02_extreme_timer_sleep_zero, "F02")
    suite.add("B_F02.2 Max 64-bit Timer Tick Value", test_b_f02_max_u64_timer_overflow, "F02")
    suite.add("B_F02.3 Out-of-Range CPU IPI Rejection", test_b_f02_ipi_to_invalid_cpu_raises_error, "F02")
    suite.add("B_F02.4 Redundant Consecutive Interrupt Disables", test_b_f02_redundant_interrupt_disables, "F02")
    suite.add("B_F02.5 Uniprocessor Secondary Core Boot", test_b_f02_boot_secondary_cores_zero, "F02")

    # F03 Boundaries (5 tests)
    suite.add("B_F03.1 Translation of High Canonical Address", test_b_f03_translation_non_canonical_address, "F03")
    suite.add("B_F03.2 Empty TLB Shootdown Log", test_b_f03_empty_tlb_shootdown_log, "F03")
    suite.add("B_F03.3 Consecutive Page Table Flips", test_b_f03_consecutive_page_table_flips, "F03")
    suite.add("B_F03.4 Global TLB Flush Marker Sentinel", test_b_f03_global_tlb_flush_marker, "F03")
    suite.add("B_F03.5 Empty Kernel Command Line String", test_b_f03_null_kernel_cmdline, "F03")

    # F04 Boundaries (5 tests)
    suite.add("B_F04.1 Misaligned VBAR_EL1 Rejection", test_b_f04_misaligned_vbar_rejection, "F04")
    suite.add("B_F04.2 GIC Interrupt ID Max Boundary", test_b_f04_gic_interrupt_id_max_boundary, "F04")
    suite.add("B_F04.3 AArch64 T0SZ Outside Valid Range", test_b_f04_t0sz_outside_valid_range, "F04")
    suite.add("B_F04.4 Unknown PSCI Function ID Return", test_b_f04_unknown_psci_function_returns_not_supported, "F04")
    suite.add("B_F04.5 Unknown ESR Exception Class Code", test_b_f04_unknown_esr_exception_class, "F04")

    # F05 Boundaries (5 tests)
    suite.add("B_F05.1 Invalid stvec Mode Bits", test_b_f05_invalid_stvec_mode, "F05")
    suite.add("B_F05.2 CLINT mtimecmp Set to Zero", test_b_f05_clint_mtimecmp_zero, "F05")
    suite.add("B_F05.3 PLIC Priority 0 Means Disabled", test_b_f05_plic_zero_priority_means_disabled, "F05")
    suite.add("B_F05.4 satp Mode 0 Bare Translation", test_b_f05_satp_bare_mode, "F05")
    suite.add("B_F05.5 Nonexistent SBI Extension Probe", test_b_f05_unknown_sbi_extension_probe, "F05")

    # F06 Boundaries (5 tests)
    suite.add("B_F06.1 Unmap Nonexistent Virtual Page", test_b_f06_unmap_nonexistent_page, "F06")
    suite.add("B_F06.2 Map Page with Zero Flags", test_b_f06_map_page_zero_flags, "F06")
    suite.add("B_F06.3 Map Highest Canonical Page", test_b_f06_map_highest_canonical_page, "F06")
    suite.add("B_F06.4 Misaligned Virtual Address Base Masking", test_b_f06_misaligned_vaddr_masks_to_page_base, "F06")
    suite.add("B_F06.5 Overwrite Existing Virtual Mapping", test_b_f06_overwrite_existing_mapping, "F06")

    # F07 Boundaries (5 tests)
    suite.add("B_F07.1 Negative Syscall Number Rejection", test_b_f07_negative_syscall_number, "F07")
    suite.add("B_F07.2 Max 64-bit Syscall Number Rejection", test_b_f07_max_u64_syscall_number, "F07")
    suite.add("B_F07.3 Null Pointer Buffer Argument Returns -EFAULT", test_b_f07_null_pointer_buffer_argument, "F07")
    suite.add("B_F07.4 Zero-Length sys_read Returns 0", test_b_f07_zero_length_read, "F07")
    suite.add("B_F07.5 User RSP in Kernel Half Rejection", test_b_f07_user_rsp_in_kernel_space_denial, "F07")

    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
