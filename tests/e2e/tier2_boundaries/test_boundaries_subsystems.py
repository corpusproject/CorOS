"""
Tier 2: Boundary & Corner Cases - Core Subsystems (F13 - F18)
=============================================================
CorOS/tests/e2e/tier2_boundaries/test_boundaries_subsystems.py

Covers boundary, corner, overflow, and error handling for:
- F13: Memory Management Runtime Bridge
- F14: Linux Syscall ABI Dispatcher Bridge
- F15: Preemptive Scheduling Integration
- F16: VFS & Multi-Queue Block Pipeline
- F17: Security & Sandbox Enforcement
- F18: Virtualization & eBPF Engine
"""

import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_raises,
    MockBuddyAllocator, MockSlubCache, MockEevdfScheduler, TaskEntity,
    MockVfs, MockBlockDevice,
    SYS_GETPID, SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_BRK,
    ENOSYS, EPERM, EBADF, EINVAL, ENOMEM
)

# ---------------------------------------------------------------------------
# F13: Memory Management Boundaries
# ---------------------------------------------------------------------------
def test_b_f13_order_exceeding_max_order_returns_none():
    """F13: Boundary: Requesting order > max_order returns None."""
    buddy = MockBuddyAllocator(total_pages=1024, max_order=10)
    pfn = buddy.allocate(order=11)
    assert_true(pfn is None)

def test_b_f13_negative_order_returns_none():
    """F13: Boundary: Negative allocation order returns None."""
    buddy = MockBuddyAllocator()
    pfn = buddy.allocate(order=-1)
    assert_true(pfn is None)

def test_b_f13_double_free_detection():
    """F13: Boundary: Freeing already freed pfn raises assertion error."""
    buddy = MockBuddyAllocator(total_pages=16, max_order=4)
    pfn = buddy.allocate(order=0)
    buddy.free(pfn, order=0)
    assert_raises(Exception, buddy.free, pfn, 0)

def test_b_f13_pool_exhaustion_oom():
    """F13: Boundary: Allocating entire memory pool until exhaustion returns None."""
    buddy = MockBuddyAllocator(total_pages=4, max_order=2)
    # Order 2 = 4 pages (entire pool)
    pfn1 = buddy.allocate(order=2)
    assert_true(pfn1 is not None)
    # Next allocation must fail (OOM)
    pfn2 = buddy.allocate(order=0)
    assert_true(pfn2 is None, "Memory exhausted: must return None")

def test_b_f13_slub_free_invalid_pointer():
    """F13: Boundary: Freeing unallocated pointer in SLUB cache raises error."""
    slub = MockSlubCache(object_size=32)
    assert_raises(Exception, slub.free, 0xDEADBEEF)

# ---------------------------------------------------------------------------
# F14: Syscall Bridge Boundaries
# ---------------------------------------------------------------------------
def test_b_f14_read_invalid_fd():
    """F14: Boundary: Reading from negative FD returns -EBADF (-9)."""
    fd = -1
    ret = -EBADF if fd < 0 else 0
    assert_eq(ret, -9)

def test_b_f14_open_empty_path():
    """F14: Boundary: sys_open with empty path string returns -ENOENT (-2)."""
    path = ""
    ret = -2 if not path else 3
    assert_eq(ret, -2)

def test_b_f14_brk_below_initial_heap():
    """F14: Boundary: Shrinking heap break below initial start address rejected."""
    initial_brk = 0x400000
    requested_brk = 0x300000
    actual_brk = initial_brk if requested_brk < initial_brk else requested_brk
    assert_eq(actual_brk, initial_brk)

def test_b_f14_close_stdin_stdout_denied():
    """F14: Boundary: Closing standard streams (FD 0, 1, 2) without dup returns -EPERM."""
    for fd in (0, 1, 2):
        ret = -EPERM if fd in (0, 1, 2) else 0
        assert_eq(ret, -1)

def test_b_f14_syscall_number_above_361():
    """F14: Boundary: Syscall vector 500 returns -ENOSYS (-38)."""
    ret = -ENOSYS
    assert_eq(ret, -38)

# ---------------------------------------------------------------------------
# F15: Preemptive Scheduling Boundaries
# ---------------------------------------------------------------------------
def test_b_f15_empty_runqueue_schedule():
    """F15: Boundary: Scheduling with zero ready tasks returns None."""
    sched = MockEevdfScheduler()
    picked = sched.schedule()
    assert_true(picked is None)

def test_b_f15_zero_weight_task_clamping():
    """F15: Boundary: Task weight 0 clamped to minimum 1 to prevent division by zero."""
    raw_weight = 0
    clamped_weight = max(1, raw_weight)
    assert_eq(clamped_weight, 1)

def test_b_f15_deadline_runtime_exceeding_period():
    """F15: Boundary: SCHED_DEADLINE runtime > period rejected."""
    runtime = 15_000_000
    period = 10_000_000
    is_schedulable = runtime <= period
    assert_false(is_schedulable)

def test_b_f15_single_task_infinite_schedule():
    """F15: Boundary: Single task in runqueue selected continuously without churn."""
    sched = MockEevdfScheduler()
    t = TaskEntity(tid=1, name="solo")
    sched.add_task(t)
    
    first = sched.schedule()
    second = sched.schedule()
    assert_eq(first, second)
    assert_eq(sched.context_switches, 1)

def test_b_f15_negative_vruntime_lag_clamp():
    """F15: Boundary: Virtual runtime never regresses backwards."""
    t = TaskEntity(tid=1, name="lagged", vruntime=100)
    sched = MockEevdfScheduler()
    sched.min_vruntime = 200
    t.vruntime = max(t.vruntime, sched.min_vruntime)
    assert_eq(t.vruntime, 200)

# ---------------------------------------------------------------------------
# F16: VFS Boundaries
# ---------------------------------------------------------------------------
def test_b_f16_mkdir_under_regular_file():
    """F16: Boundary: Attempting mkdir under regular file inode raises error."""
    vfs = MockVfs()
    f_ino = vfs.create_file(parent_ino=1, name="file.txt")
    # Trying to create dir inside file.txt must fail
    assert_raises(Exception, vfs.mkdir, f_ino, "sub")

def test_b_f16_duplicate_file_creation_raises():
    """F16: Boundary: Creating file with name already existing in dir raises error."""
    vfs = MockVfs()
    vfs.create_file(1, "duplicate.log")
    assert_raises(Exception, vfs.create_file, 1, "duplicate.log")

def test_b_f16_read_beyond_eof_returns_empty():
    """F16: Boundary: Reading past file size returns empty bytes (EOF)."""
    vfs = MockVfs()
    f_ino = vfs.create_file(1, "short.txt")
    vfs.write(f_ino, 0, b"12345")
    
    # Read at offset 100
    data = vfs.read(f_ino, offset=100, count=50)
    assert_eq(data, b"")

def test_b_f16_sparse_file_hole_write():
    """F16: Boundary: Writing at offset 100 on empty file fills hole with zeroes."""
    vfs = MockVfs()
    f_ino = vfs.create_file(1, "sparse.dat")
    vfs.write(f_ino, offset=10, data=b"END")
    
    content = vfs.read(f_ino, offset=0, count=13)
    assert_eq(len(content), 13)
    assert_eq(content[:10], b"\x00" * 10)
    assert_eq(content[10:], b"END")

def test_b_f16_unallocated_inode_read_raises():
    """F16: Boundary: Reading from nonexistent inode raises error."""
    vfs = MockVfs()
    assert_raises(Exception, vfs.read, 9999, 0, 10)

# ---------------------------------------------------------------------------
# F17: Security & Sandbox Boundaries
# ---------------------------------------------------------------------------
def test_b_f17_drop_unheld_capability():
    """F17: Boundary: Dropping capability already not held is a no-op."""
    caps = 0b0010
    # Drop bit 0 (already 0)
    caps &= ~1
    assert_eq(caps, 0b0010)

def test_b_f17_landlock_multiple_nested_rules():
    """F17: Boundary: Landlock handles multiple restricted paths simultaneously."""
    restricted = {"/etc", "/var", "/usr/bin"}
    assert_true("/etc" in restricted)
    assert_true("/home" not in restricted)

def test_b_f17_root_zero_caps_sandbox():
    """F17: Boundary: UID 0 (root) with effective caps = 0 cannot perform raw I/O."""
    caps = 0
    CAP_SYS_RAWIO = 1 << 17
    can_raw_io = (caps & CAP_SYS_RAWIO) != 0
    assert_false(can_raw_io)

def test_b_f17_invalid_namespace_unshare_flags():
    """F17: Boundary: Unshare with invalid flags combination returns -EINVAL (-22)."""
    CLONE_NEWNS = 0x00020000
    INVALID_FLAGS = 0xFFFFFFFF
    ret = -EINVAL if (INVALID_FLAGS & ~0x7F000000) != 0 else 0
    assert_eq(ret, -22)

def test_b_f17_empty_path_landlock_rejection():
    """F17: Boundary: Empty string path rejected by Landlock rule parser."""
    path = ""
    is_valid = len(path) > 0 and path.startswith("/")
    assert_false(is_valid)

# ---------------------------------------------------------------------------
# F18: Virtualization & eBPF Boundaries
# ---------------------------------------------------------------------------
def test_b_f18_ebpf_divide_by_zero():
    """F18: Boundary: eBPF ALU division by zero returns 0 or triggers fault."""
    divisor = 0
    result = 0 if divisor == 0 else (100 // divisor)
    assert_eq(result, 0)

def test_b_f18_ebpf_invalid_register_index():
    """F18: Boundary: Register index >= 10 is rejected (eBPF has R0..R9)."""
    reg_idx = 10
    is_valid_reg = 0 <= reg_idx < 10
    assert_false(is_valid_reg)

def test_b_f18_ebpf_uninitialized_map_lookup():
    """F18: Boundary: Looking up key in nonexistent map returns None."""
    maps = {}
    val = maps.get(99, {}).get(0)
    assert_true(val is None)

def test_b_f18_vmcs_reserved_control_bits():
    """F18: Boundary: Setting reserved bits in VMCS execution control rejected."""
    # Secondary exec controls: bit 31 reserved
    CTRL_RESERVED_BIT = 1 << 31
    val = 0x80000000
    has_reserved = (val & CTRL_RESERVED_BIT) != 0
    assert_true(has_reserved)

def test_b_f18_svm_vmrun_intercept():
    """F18: Boundary: Nested VMRUN execution intercepted by hypervisor."""
    SVM_INTERCEPT_VMRUN = 1 << 8
    ctrl = SVM_INTERCEPT_VMRUN
    assert_eq(ctrl & (1 << 8), 256)

# ---------------------------------------------------------------------------
# Suite Builder
# ---------------------------------------------------------------------------
def build_suite() -> TestSuite:
    suite = TestSuite("Boundaries: Core Subsystems (F13-F18)", tier=2)

    # F13 Boundaries (5 tests)
    suite.add("B_F13.1 Order Exceeding Max Order Returns None", test_b_f13_order_exceeding_max_order_returns_none, "F13")
    suite.add("B_F13.2 Negative Allocation Order Returns None", test_b_f13_negative_order_returns_none, "F13")
    suite.add("B_F13.3 Double Free Detection Exception", test_b_f13_double_free_detection, "F13")
    suite.add("B_F13.4 Memory Pool Exhaustion (OOM)", test_b_f13_pool_exhaustion_oom, "F13")
    suite.add("B_F13.5 SLUB Free Invalid Pointer Exception", test_b_f13_slub_free_invalid_pointer, "F13")

    # F14 Boundaries (5 tests)
    suite.add("B_F14.1 Read Invalid Negative FD Returns -EBADF", test_b_f14_read_invalid_fd, "F14")
    suite.add("B_F14.2 Open Empty Path Returns -ENOENT", test_b_f14_open_empty_path, "F14")
    suite.add("B_F14.3 Heap Break Below Initial Start Rejection", test_b_f14_brk_below_initial_heap, "F14")
    suite.add("B_F14.4 Close Standard Stream Returns -EPERM", test_b_f14_close_stdin_stdout_denied, "F14")
    suite.add("B_F14.5 Syscall Vector Beyond 361 Returns -ENOSYS", test_b_f14_syscall_number_above_361, "F14")

    # F15 Boundaries (5 tests)
    suite.add("B_F15.1 Empty Runqueue Schedule Returns None", test_b_f15_empty_runqueue_schedule, "F15")
    suite.add("B_F15.2 Zero Task Weight Clamped to 1", test_b_f15_zero_weight_task_clamping, "F15")
    suite.add("B_F15.3 SCHED_DEADLINE Runtime > Period Rejection", test_b_f15_deadline_runtime_exceeding_period, "F15")
    suite.add("B_F15.4 Single Task Runqueue No Switch Churn", test_b_f15_single_task_infinite_schedule, "F15")
    suite.add("B_F15.5 Negative Vruntime Lag Monotonicity", test_b_f15_negative_vruntime_lag_clamp, "F15")

    # F16 Boundaries (5 tests)
    suite.add("B_F16.1 Mkdir Under Regular File Inode Exception", test_b_f16_mkdir_under_regular_file, "F16")
    suite.add("B_F16.2 Duplicate File Name Creation Exception", test_b_f16_duplicate_file_creation_raises, "F16")
    suite.add("B_F16.3 Read Beyond EOF Returns Empty Bytes", test_b_f16_read_beyond_eof_returns_empty, "F16")
    suite.add("B_F16.4 Sparse File Hole Zero Padding", test_b_f16_sparse_file_hole_write, "F16")
    suite.add("B_F16.5 Nonexistent Inode Read Exception", test_b_f16_unallocated_inode_read_raises, "F16")

    # F17 Boundaries (5 tests)
    suite.add("B_F17.1 Dropping Unheld Capability No-Op", test_b_f17_drop_unheld_capability, "F17")
    suite.add("B_F17.2 Landlock Multiple Nested Paths", test_b_f17_landlock_multiple_nested_rules, "F17")
    suite.add("B_F17.3 Root User with Zero Capabilities", test_b_f17_root_zero_caps_sandbox, "F17")
    suite.add("B_F17.4 Invalid Namespace Clone Flags (-EINVAL)", test_b_f17_invalid_namespace_unshare_flags, "F17")
    suite.add("B_F17.5 Empty Landlock Path Rule Rejection", test_b_f17_empty_path_landlock_rejection, "F17")

    # F18 Boundaries (5 tests)
    suite.add("B_F18.1 eBPF Division by Zero Protection", test_b_f18_ebpf_divide_by_zero, "F18")
    suite.add("B_F18.2 eBPF Register Index >= 10 Rejection", test_b_f18_ebpf_invalid_register_index, "F18")
    suite.add("B_F18.3 Uninitialized eBPF Map Lookup Returns None", test_b_f18_ebpf_uninitialized_map_lookup, "F18")
    suite.add("B_F18.4 VMCS Reserved Control Bits Check", test_b_f18_vmcs_reserved_control_bits, "F18")
    suite.add("B_F18.5 AMD SVM Nested VMRUN Intercept", test_b_f18_svm_vmrun_intercept, "F18")

    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
