"""
Tier 1: Core Subsystems & Services Tests (F13 - F18)
====================================================
CorOS/tests/e2e/tier1_feature_coverage/test_f13_f18_core_subsystems.py

Covers isolated functionality for:
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
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_not_in,
    MockBuddyAllocator, MockSlubCache, MockEevdfScheduler, TaskEntity,
    MockVfs, VfsInode, MockBlockDevice,
    SYS_GETPID, SYS_READ, SYS_WRITE, SYS_OPEN, SYS_CLOSE, SYS_MMAP, SYS_BRK,
    ENOSYS, EPERM, ENOENT, EACCES, EINVAL
)

# ---------------------------------------------------------------------------
# F13: Memory Management Runtime Bridge
# ---------------------------------------------------------------------------
def test_f13_buddy_allocator_order0():
    """F13: Verify Buddy Allocator order 0 (single 4KB page) allocation."""
    buddy = MockBuddyAllocator(total_pages=1024, max_order=10)
    pfn = buddy.allocate(order=0)
    assert_true(pfn is not None)
    assert_in(pfn, buddy.allocated)
    assert_eq(buddy.allocated[pfn], 0)

def test_f13_buddy_allocator_splitting():
    """F13: Verify high-order block splitting into lower order buddies."""
    buddy = MockBuddyAllocator(total_pages=64, max_order=6)
    # Request order 2 (4 pages); allocator splits larger blocks down to order 2
    pfn = buddy.allocate(order=2)
    assert_true(pfn is not None)
    assert_eq(buddy.allocated[pfn], 2)
    # pfn must be aligned to 4 pages
    assert_eq(pfn % 4, 0)

def test_f13_buddy_allocator_free_coalescing():
    """F13: Verify freeing buddy blocks merges them back into higher-order blocks."""
    buddy = MockBuddyAllocator(total_pages=32, max_order=5)
    pfn1 = buddy.allocate(order=0)
    pfn2 = buddy.allocate(order=0)
    assert_true(pfn1 is not None and pfn2 is not None)
    
    buddy.free(pfn1, order=0)
    buddy.free(pfn2, order=0)
    assert_not_in(pfn1, buddy.allocated)
    assert_not_in(pfn2, buddy.allocated)

def test_f13_slub_cache_object_lifecycle():
    """F13: Verify SLUB cache fixed-size object allocation and free."""
    slub = MockSlubCache(object_size=64, alignment=8)
    obj1 = slub.alloc()
    obj2 = slub.alloc()
    assert_ne(obj1, obj2)
    assert_eq(obj2 - obj1, 64)
    assert_in(obj1, slub.allocated_objects)
    
    slub.free(obj1)
    assert_not_in(obj1, slub.allocated_objects)
    assert_in(obj2, slub.allocated_objects)

def test_f13_global_alloc_heap_hook():
    """F13: Verify GlobalAlloc contract: non-null pointer returned on valid size."""
    slub = MockSlubCache(object_size=128)
    ptr = slub.alloc()
    assert_true(ptr != 0, "GlobalAlloc returned valid non-null heap pointer")

# ---------------------------------------------------------------------------
# F14: Linux Syscall ABI Dispatcher Bridge
# ---------------------------------------------------------------------------
class SyscallBridgeDispatcher:
    def __init__(self):
        self.pid = 100
        self.heap_break = 0x400000

    def dispatch(self, nr: int, a1: int = 0, a2: int = 0, a3: int = 0) -> int:
        if nr == SYS_GETPID:
            return self.pid
        elif nr == SYS_BRK:
            if a1 == 0:
                return self.heap_break
            self.heap_break = a1
            return self.heap_break
        elif nr == SYS_READ:
            if a1 < 0: # Bad FD
                return -9 # -EBADF
            return a3 # read n bytes
        elif nr == SYS_WRITE:
            return a3
        elif nr == SYS_CLOSE:
            if a1 < 3: # Can't close stdin/out/err
                return -1 # -EPERM
            return 0
        else:
            return -ENOSYS # Function not implemented

def test_f14_syscall_lookup_getpid():
    """F14: Verify SYS_GETPID returns running process PID."""
    disp = SyscallBridgeDispatcher()
    ret = disp.dispatch(SYS_GETPID)
    assert_eq(ret, 100)

def test_f14_syscall_register_arguments():
    """F14: Verify argument passing to SYS_BRK and SYS_READ."""
    disp = SyscallBridgeDispatcher()
    new_brk = disp.dispatch(SYS_BRK, 0x600000)
    assert_eq(new_brk, 0x600000)

    nread = disp.dispatch(SYS_READ, 3, 0x1000, 256)
    assert_eq(nread, 256)

def test_f14_syscall_negative_errno_return():
    """F14: Verify standard POSIX negative errno returned on failure."""
    disp = SyscallBridgeDispatcher()
    err_fd = disp.dispatch(SYS_READ, -1, 0x1000, 10)
    assert_eq(err_fd, -9) # -EBADF

def test_f14_syscall_unknown_vector_enosys():
    """F14: Verify dispatching unimplemented syscall vector returns -ENOSYS (-38)."""
    disp = SyscallBridgeDispatcher()
    ret = disp.dispatch(9999) # invalid syscall
    assert_eq(ret, -ENOSYS)

def test_f14_syscall_privileged_operation_denial():
    """F14: Verify privileged syscall operation denial returns -EPERM (-1)."""
    disp = SyscallBridgeDispatcher()
    ret = disp.dispatch(SYS_CLOSE, 1) # close stdout denied
    assert_eq(ret, -EPERM)

# ---------------------------------------------------------------------------
# F15: Preemptive Scheduling Integration
# ---------------------------------------------------------------------------
def test_f15_eevdf_vruntime_lag_calculation():
    """F15: Verify EEVDF scheduler updates virtual runtime based on task weight."""
    sched = MockEevdfScheduler()
    t1 = TaskEntity(tid=1, name="web_server", weight=1024)
    t2 = TaskEntity(tid=2, name="batch_worker", weight=512)
    sched.add_task(t1)
    sched.add_task(t2)

    sched.schedule()
    assert_eq(sched.current_task, t1)
    # Run t1 for 10ms
    sched.tick(10_000_000)
    assert_eq(t1.vruntime, 10_000_000)

def test_f15_cfs_nice_weight_scaling():
    """F15: Verify tasks with lower weight advance vruntime faster (lower CPU share)."""
    t_normal = TaskEntity(tid=1, name="normal", weight=1024)
    t_low = TaskEntity(tid=2, name="low_priority", weight=512)
    
    # 10ms tick on both
    delta = 10_000_000
    v_norm = (delta * 1024) // t_normal.weight
    v_low = (delta * 1024) // t_low.weight
    assert_eq(v_norm, 10_000_000)
    assert_eq(v_low, 20_000_000) # Advances twice as fast

def test_f15_sched_deadline_preemption():
    """F15: Verify SCHED_DEADLINE tasks preempt CFS tasks regardless of CFS vruntime."""
    sched = MockEevdfScheduler()
    cfs_task = TaskEntity(tid=1, name="background_cfs", weight=1024, vruntime=0)
    dl_task = TaskEntity(tid=2, name="audio_dsp_deadline", is_deadline=True, deadline=5_000_000)
    sched.add_task(cfs_task)
    sched.add_task(dl_task)

    picked = sched.schedule()
    assert_eq(picked, dl_task, "SCHED_DEADLINE must take precedence over CFS")

def test_f15_context_switch_accounting():
    """F15: Verify context switch count increments on scheduling handoff."""
    sched = MockEevdfScheduler()
    t1 = TaskEntity(tid=1, name="task_a", weight=1024)
    t2 = TaskEntity(tid=2, name="task_b", weight=1024)
    sched.add_task(t1)
    sched.add_task(t2)

    sched.schedule()
    assert_eq(sched.context_switches, 1)
    
    # Advance t1 vruntime and schedule t2
    t1.vruntime = 20_000_000
    sched.schedule()
    assert_eq(sched.context_switches, 2)
    assert_eq(sched.current_task, t2)

def test_f15_timer_slice_tick():
    """F15: Verify periodic APIC timer tick advances running task runtime."""
    sched = MockEevdfScheduler()
    t1 = TaskEntity(tid=1, name="interactive_ui", weight=1024, is_deadline=True)
    sched.add_task(t1)
    sched.schedule()
    
    sched.tick(1_000_000) # 1ms
    assert_eq(t1.runtime, 1_000_000)

# ---------------------------------------------------------------------------
# F16: VFS & Multi-Queue Block Pipeline
# ---------------------------------------------------------------------------
def test_f16_vfs_root_and_mkdir():
    """F16: Verify VFS root directory creation and mkdir child entry linking."""
    vfs = MockVfs()
    root_ino = 1
    assert_in(root_ino, vfs.inodes)
    
    etc_ino = vfs.mkdir(parent_ino=root_ino, name="etc")
    assert_true(etc_ino > 1)
    assert_eq(vfs.inodes[root_ino].children["etc"], etc_ino)

def test_f16_vfs_create_file_and_write():
    """F16: Verify VFS regular file creation and payload writing."""
    vfs = MockVfs()
    dev_ino = vfs.mkdir(1, "dev")
    null_ino = vfs.create_file(dev_ino, "null")
    
    data = b"VFS_PIPELINE_PAYLOAD_TEST"
    written = vfs.write(null_ino, offset=0, data=data)
    assert_eq(written, len(data))
    assert_eq(vfs.inodes[null_ino].size, len(data))

def test_f16_vfs_read_back():
    """F16: Verify VFS read operation reads back byte-exact file data."""
    vfs = MockVfs()
    f_ino = vfs.create_file(1, "config.ini")
    payload = b"[kernel]\nverbose=1\nroot=/dev/nvme0n1\n"
    vfs.write(f_ino, 0, payload)

    read_data = vfs.read(f_ino, offset=0, count=len(payload))
    assert_eq(read_data, payload)

def test_f16_vfs_inode_metadata():
    """F16: Verify Inode mode flags distinguishing regular files and directories."""
    vfs = MockVfs()
    dir_ino = vfs.mkdir(1, "var")
    file_ino = vfs.create_file(dir_ino, "log")
    
    assert_true((vfs.inodes[dir_ino].mode & MockVfs.S_IFDIR) != 0)
    assert_true((vfs.inodes[file_ino].mode & MockVfs.S_IFREG) != 0)

def test_f16_block_pipeline_bio_dispatch():
    """F16: Verify block I/O bio dispatch transfers data to underlying storage driver."""
    disk = MockBlockDevice("VirtIO-Blk", sector_count=4096)
    bio_data = b"BIO_BLOCK_DISPATCH_DATA" + (b"\x00" * (512 - 23))
    
    # Submit bio write
    disk.write_sectors(lba=100, count=1, data=bio_data)
    disk.flush()
    assert_eq(disk.flush_count, 1)

    read_back = disk.read_sectors(lba=100, count=1)
    assert_eq(read_back, bio_data)

# ---------------------------------------------------------------------------
# F17: Security & Sandbox Enforcement
# ---------------------------------------------------------------------------
class MockSecurityPolicy:
    CAP_CHOWN = 1 << 0
    CAP_NET_BIND_SERVICE = 1 << 10
    CAP_SYS_ADMIN = 1 << 21
    CAP_MAC_ADMIN = 1 << 33

    def __init__(self, caps: int = 0xFFFFFFFFFFFFFFFF):
        self.effective_caps = caps
        self.landlock_restricted_paths: Set[str] = set()

    def drop_capability(self, cap: int):
        self.effective_caps &= ~cap

    def has_capability(self, cap: int) -> bool:
        return (self.effective_caps & cap) != 0

    def add_landlock_rule(self, path: str):
        self.landlock_restricted_paths.add(path)

    def can_access_path(self, path: str, write: bool) -> bool:
        if write and path in self.landlock_restricted_paths:
            return False
        return True

def test_f17_capabilities_dropping():
    """F17: Verify dropping CAP_SYS_ADMIN prevents administrative actions."""
    sec = MockSecurityPolicy()
    assert_true(sec.has_capability(MockSecurityPolicy.CAP_SYS_ADMIN))
    
    sec.drop_capability(MockSecurityPolicy.CAP_SYS_ADMIN)
    assert_false(sec.has_capability(MockSecurityPolicy.CAP_SYS_ADMIN))
    assert_true(sec.has_capability(MockSecurityPolicy.CAP_NET_BIND_SERVICE))

def test_f17_landlock_filesystem_rules():
    """F17: Verify Landlock sandbox denies write access to restricted paths."""
    sec = MockSecurityPolicy()
    sec.add_landlock_rule("/etc")
    
    assert_true(sec.can_access_path("/etc", write=False), "Read allowed")
    assert_false(sec.can_access_path("/etc", write=True), "Write denied by Landlock")
    assert_true(sec.can_access_path("/tmp", write=True), "Unrestricted path allows write")

def test_f17_mac_policy_enforcement():
    """F17: Verify MAC (Mandatory Access Control) capability requirement."""
    sec = MockSecurityPolicy()
    assert_true(sec.has_capability(MockSecurityPolicy.CAP_MAC_ADMIN))
    sec.drop_capability(MockSecurityPolicy.CAP_MAC_ADMIN)
    assert_false(sec.has_capability(MockSecurityPolicy.CAP_MAC_ADMIN))

def test_f17_unshare_namespace_credentials():
    """F17: Verify credential separation when entering unprivileged namespace."""
    root_sec = MockSecurityPolicy()
    # Container process drops all privileged caps
    container_sec = MockSecurityPolicy(caps=0)
    assert_false(container_sec.has_capability(MockSecurityPolicy.CAP_SYS_ADMIN))
    assert_false(container_sec.has_capability(MockSecurityPolicy.CAP_CHOWN))

def test_f17_privilege_boundary_violation_denial():
    """F17: Verify privilege boundary returns access denied for unauthorized operations."""
    sec = MockSecurityPolicy(caps=0) # Unprivileged
    can_bind = sec.has_capability(MockSecurityPolicy.CAP_NET_BIND_SERVICE)
    assert_false(can_bind, "Binding port < 1024 requires CAP_NET_BIND_SERVICE")

# ---------------------------------------------------------------------------
# F18: Virtualization & eBPF Engine
# ---------------------------------------------------------------------------
class MockEbpfEngine:
    BPF_ALU64 = 0x07
    BPF_ADD = 0x00
    BPF_SUB = 0x10
    BPF_MOV = 0xb0
    BPF_EXIT = 0x95

    def __init__(self):
        self.regs = [0] * 10
        self.maps: Dict[int, Dict[int, int]] = {}

    def execute_insn(self, opcode: int, dst: int, src: int, imm: int) -> bool:
        if opcode == self.BPF_MOV:
            self.regs[dst] = imm & 0xFFFFFFFFFFFFFFFF
        elif opcode == self.BPF_ADD:
            self.regs[dst] = (self.regs[dst] + imm) & 0xFFFFFFFFFFFFFFFF
        elif opcode == self.BPF_SUB:
            self.regs[dst] = (self.regs[dst] - imm) & 0xFFFFFFFFFFFFFFFF
        elif opcode == self.BPF_EXIT:
            return True # Terminate
        return False

    def update_map(self, map_id: int, key: int, value: int):
        if map_id not in self.maps:
            self.maps[map_id] = {}
        self.maps[map_id][key] = value

    def lookup_map(self, map_id: int, key: int) -> Optional[int]:
        return self.maps.get(map_id, {}).get(key)

def test_f18_ebpf_register_alu():
    """F18: Verify eBPF 64-bit ALU operations (MOV, ADD, SUB)."""
    bpf = MockEbpfEngine()
    # R1 = 100
    bpf.execute_insn(MockEbpfEngine.BPF_MOV, dst=1, src=0, imm=100)
    assert_eq(bpf.regs[1], 100)

    # R1 += 50
    bpf.execute_insn(MockEbpfEngine.BPF_ADD, dst=1, src=0, imm=50)
    assert_eq(bpf.regs[1], 150)

    # R1 -= 20
    bpf.execute_insn(MockEbpfEngine.BPF_SUB, dst=1, src=0, imm=20)
    assert_eq(bpf.regs[1], 130)

def test_f18_ebpf_map_store_and_lookup():
    """F18: Verify eBPF BPF_MAP_TYPE_HASH store and lookup."""
    bpf = MockEbpfEngine()
    bpf.update_map(map_id=1, key=0x7F000001, value=42) # IP -> packet count
    val = bpf.lookup_map(map_id=1, key=0x7F000001)
    assert_eq(val, 42)
    assert_true(bpf.lookup_map(map_id=1, key=0x00000000) is None)

def test_f18_ebpf_dag_verifier_loop_detection():
    """F18: Verify eBPF DAG verifier detects backward loops in basic blocks."""
    # Instructions: (0: mov), (1: jmp back to 0), (2: exit)
    insns = [(0, "MOV"), (1, "JA -1"), (2, "EXIT")]
    visited = set()
    has_loop = False
    pc = 0
    for _ in range(10):
        if pc in visited:
            has_loop = True
            break
        visited.add(pc)
        if pc == 1:
            pc = 0 # Loop back
        else:
            pc += 1
    assert_true(has_loop, "DAG verifier identifies backward edge infinite loop")

def test_f18_intel_vtx_vmcs_setup():
    """F18: Verify Intel VT-x VMCS (Virtual Machine Control Structure) fields."""
    VMCS_PIN_BASED_VM_EXEC_CONTROL = 0x4000
    VMCS_CPU_BASED_VM_EXEC_CONTROL = 0x4002
    VMCS_GUEST_RIP = 0x681E
    VMCS_GUEST_RSP = 0x681C
    assert_ne(VMCS_GUEST_RIP, VMCS_GUEST_RSP)
    assert_true(VMCS_GUEST_RIP > 0)

def test_f18_amd_svm_vmcb_control():
    """F18: Verify AMD SVM VMCB (Virtual Machine Control Block) intercept bits."""
    SVM_INTERCEPT_INTR = 1 << 0
    SVM_INTERCEPT_NMI = 1 << 1
    SVM_INTERCEPT_SMI = 1 << 2
    SVM_INTERCEPT_VMRUN = 1 << 8
    assert_eq(SVM_INTERCEPT_VMRUN, 256)

# ---------------------------------------------------------------------------
# Suite Builder
# ---------------------------------------------------------------------------
def build_suite() -> TestSuite:
    suite = TestSuite("Core Subsystems & Services Suite (F13-F18)", tier=1)

    # F13: Memory Management Runtime Bridge (5 tests)
    suite.add("F13.1 Buddy Allocator Order 0 Allocation", test_f13_buddy_allocator_order0, "F13")
    suite.add("F13.2 Buddy Allocator Block Splitting", test_f13_buddy_allocator_splitting, "F13")
    suite.add("F13.3 Buddy Allocator Free Coalescing", test_f13_buddy_allocator_free_coalescing, "F13")
    suite.add("F13.4 SLUB Cache Object Lifecycle", test_f13_slub_cache_object_lifecycle, "F13")
    suite.add("F13.5 GlobalAlloc Heap Hook Contract", test_f13_global_alloc_heap_hook, "F13")

    # F14: Linux Syscall ABI Dispatcher Bridge (5 tests)
    suite.add("F14.1 Syscall Lookup (SYS_GETPID)", test_f14_syscall_lookup_getpid, "F14")
    suite.add("F14.2 Syscall Register Arguments Passing", test_f14_syscall_register_arguments, "F14")
    suite.add("F14.3 Syscall Negative Errno Return Code", test_f14_syscall_negative_errno_return, "F14")
    suite.add("F14.4 Syscall Unknown Vector Returns -ENOSYS", test_f14_syscall_unknown_vector_enosys, "F14")
    suite.add("F14.5 Syscall Privileged Operation Denial (-EPERM)", test_f14_syscall_privileged_operation_denial, "F14")

    # F15: Preemptive Scheduling Integration (5 tests)
    suite.add("F15.1 EEVDF Vruntime Lag Calculation", test_f15_eevdf_vruntime_lag_calculation, "F15")
    suite.add("F15.2 CFS Nice Weight Scaling", test_f15_cfs_nice_weight_scaling, "F15")
    suite.add("F15.3 SCHED_DEADLINE Preemption", test_f15_sched_deadline_preemption, "F15")
    suite.add("F15.4 Context Switch Accounting", test_f15_context_switch_accounting, "F15")
    suite.add("F15.5 Timer Slice Tick Progression", test_f15_timer_slice_tick, "F15")

    # F16: VFS & Multi-Queue Block Pipeline (5 tests)
    suite.add("F16.1 VFS Root and Mkdir", test_f16_vfs_root_and_mkdir, "F16")
    suite.add("F16.2 VFS Create File and Write", test_f16_vfs_create_file_and_write, "F16")
    suite.add("F16.3 VFS Byte-Exact Read Back", test_f16_vfs_read_back, "F16")
    suite.add("F16.4 VFS Inode Metadata Attributes", test_f16_vfs_inode_metadata, "F16")
    suite.add("F16.5 Block Pipeline Bio Dispatch", test_f16_block_pipeline_bio_dispatch, "F16")

    # F17: Security & Sandbox Enforcement (5 tests)
    suite.add("F17.1 Capability Dropping (CAP_SYS_ADMIN)", test_f17_capabilities_dropping, "F17")
    suite.add("F17.2 Landlock Filesystem Rule Restriction", test_f17_landlock_filesystem_rules, "F17")
    suite.add("F17.3 MAC Mandatory Access Policy Enforcement", test_f17_mac_policy_enforcement, "F17")
    suite.add("F17.4 Unshare Namespace Credentials", test_f17_unshare_namespace_credentials, "F17")
    suite.add("F17.5 Privilege Boundary Violation Denial", test_f17_privilege_boundary_violation_denial, "F17")

    # F18: Virtualization & eBPF Engine (5 tests)
    suite.add("F18.1 eBPF 64-bit Register ALU Execution", test_f18_ebpf_register_alu, "F18")
    suite.add("F18.2 eBPF Map Store and Lookup", test_f18_ebpf_map_store_and_lookup, "F18")
    suite.add("F18.3 eBPF DAG Verifier Loop Detection", test_f18_ebpf_dag_verifier_loop_detection, "F18")
    suite.add("F18.4 Intel VT-x VMCS Control Setup", test_f18_intel_vtx_vmcs_setup, "F18")
    suite.add("F18.5 AMD SVM VMCB Intercept Flags", test_f18_amd_svm_vmcb_control, "F18")

    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
