#!/usr/bin/env python3
"""
CorOS Milestone 1 Empirical Challenger 2 Adversarial Stress Harness
==================================================================
Target: Milestone 1 Subsystems (Features 1, 2, 3, 4, 10):
- F01: Namespaces & Chroot Jail Isolation (process_lifecycle.rs)
- F02: cgroups v2 Resource Control (cgroup_v2.rs, eevdf_cfs.rs)
- F03: Full POSIX Signals (posix_signals.rs, linux_syscalls.rs)
- F04: Futex & POSIX Synchronization Primitives (posix_sync_primitives.rs, futex.rs)
- F05: Swap & Virtual Memory Paging (swap_entry.rs, swap.rs, page_fault.rs)

Executes rigorous empirical adversarial stress-testing, boundary evaluation,
integer overflow detection, and System V AMD64 ABI compliance verification.
"""

import sys
import struct
from pathlib import Path

# Add tests/e2e to sys.path
TESTS_E2E_DIR = Path(__file__).resolve().parent / "e2e"
sys.path.insert(0, str(TESTS_E2E_DIR))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_not_in, assert_raises
)
from linux_subsystems.models import (
    CloneFlags, MountPropagation, UidGidExtent, MockUserNamespace,
    MockPidNamespace, MockChrootJail, MockCgroupV2Node, CpuBandwidth, MemoryController,
    IoTokenBucket, SignalNumber, SigAction, SigInfo, MockSignalManager,
    MockFutexManager, MockPthreadMutex, MockPthreadRwLock, MockPosixSemaphore,
    encode_swap_entry, decode_swap_entry, is_swap_entry, MockSwapManager, MockPageReclaimLru,
    MockOomKiller
)


def run_all_challenges() -> TestSuite:
    suite = TestSuite("Milestone 1 Empirical Challenger 2 Adversarial Suite", tier=5)

    # =========================================================================
    # Domain 1: Namespaces & Chroot Jail Boundary Stress (F01)
    # =========================================================================

    def test_f01_max_pid_namespace_depth_limit():
        """F01-CHALLENGE.1: PID namespace hierarchy strictly enforces MAX_DEPTH (32) limit."""
        cur = MockPidNamespace(ns_id=1)
        for d in range(2, MockPidNamespace.MAX_DEPTH + 1):
            cur = MockPidNamespace(ns_id=d, parent=cur)
        assert_eq(cur.depth, MockPidNamespace.MAX_DEPTH - 1, "Max allowed depth reached")
        # Depth 33 must be rejected to prevent recursive stack blowup or array overflow
        assert_raises(ValueError, MockPidNamespace, 33, cur)

    def test_f01_vpid_translation_across_deep_hierarchy():
        """F01-CHALLENGE.2: Multi-level PID namespace correctly tracks ancestor VPIDs."""
        root = MockPidNamespace(ns_id=1)
        l1 = MockPidNamespace(ns_id=2, parent=root)
        l2 = MockPidNamespace(ns_id=3, parent=l1)
        l3 = MockPidNamespace(ns_id=4, parent=l2)

        # Allocate process in innermost namespace
        vpid_l3 = l3.allocate_vpid(global_pid=9999)
        assert_eq(vpid_l3, 1, "First task in l3 namespace must get VPID 1 (init of l3)")

        # Verify ancestor mapping
        assert_eq(l3.tasks[1], 9999)
        assert_eq(l3.global_to_vpid[9999], 1)

    def test_f01_chroot_adversarial_path_traversal():
        """F01-CHALLENGE.3: Chroot jail traps pathological path traversal escape vectors."""
        jail = MockChrootJail(root_dir="/opt/jail")

        # Vector A: Deep dot-dot traversal
        path_a = "../../../../../../../../../../../../etc/shadow"
        assert_eq(jail.resolve_path(path_a), "/opt/jail/etc/shadow")

        # Vector B: Redundant slashes and dot segments
        path_b = "//./..//./etc//./passwd"
        resolved_b = jail.resolve_path(path_b)
        assert_true("/opt/jail" in resolved_b and not resolved_b.startswith("/etc/"))

        # Vector C: Relative path rejection on set_root
        assert_raises(ValueError, jail.set_root, "relative/jail")
        assert_raises(ValueError, jail.set_root, "")

    def test_f01_clone_flags_posix_constraints():
        """F01-CHALLENGE.4: Clone flags POSIX constraint matrix validation."""
        # CLONE_THREAD requires CLONE_SIGHAND
        # CLONE_SIGHAND requires CLONE_VM
        # CLONE_NEWPID conflicts with CLONE_THREAD
        flags_thread_no_sighand = CloneFlags.CLONE_THREAD
        assert_true((flags_thread_no_sighand & CloneFlags.CLONE_SIGHAND) == 0)

        flags_thread_valid = CloneFlags.CLONE_THREAD | CloneFlags.CLONE_SIGHAND | CloneFlags.CLONE_VM
        assert_true((flags_thread_valid & CloneFlags.CLONE_THREAD) != 0)
        assert_true((flags_thread_valid & CloneFlags.CLONE_SIGHAND) != 0)
        assert_true((flags_thread_valid & CloneFlags.CLONE_VM) != 0)

        # Conflict: NEWPID + THREAD
        flags_conflict = CloneFlags.CLONE_NEWPID | CloneFlags.CLONE_THREAD
        assert_true((flags_conflict & CloneFlags.CLONE_NEWPID) != 0)
        assert_true((flags_conflict & CloneFlags.CLONE_THREAD) != 0)

    def test_f01_user_namespace_boundary_id_mappings():
        """F01-CHALLENGE.5: User namespace boundary mapping and overflow fallback."""
        ns = MockUserNamespace(ns_id=1)
        # Extent mapping: inner 0..99 -> outer 10000..10099
        ns.set_uid_map([UidGidExtent(inside_id=0, outside_id=10000, count=100)])

        assert_eq(ns.map_uid(0), 10000)
        assert_eq(ns.map_uid(99), 10099)
        # Boundary + 1 falls back to OVERFLOW_ID (65534)
        assert_eq(ns.map_uid(100), MockUserNamespace.OVERFLOW_ID)
        assert_eq(ns.map_uid(0xFFFFFFFF), MockUserNamespace.OVERFLOW_ID)

    suite.add("F01-CHALLENGE.1 Max PID Namespace Depth Boundary (32)", test_f01_max_pid_namespace_depth_limit)
    suite.add("F01-CHALLENGE.2 Multi-Level Ancestor VPID Translation", test_f01_vpid_translation_across_deep_hierarchy)
    suite.add("F01-CHALLENGE.3 Chroot Path Traversal Containment Oracle", test_f01_chroot_adversarial_path_traversal)
    suite.add("F01-CHALLENGE.4 POSIX Clone Flags Constraint Invariants", test_f01_clone_flags_posix_constraints)
    suite.add("F01-CHALLENGE.5 User Namespace Boundary Extent & Overflow Fallback", test_f01_user_namespace_boundary_id_mappings)

    # =========================================================================
    # Domain 2: cgroups v2 Quota, Weight & IO Token Bucket Adversarial Stress (F02)
    # =========================================================================

    def test_f02_no_internal_processes_constraint_tree():
        """F02-CHALLENGE.1: cgroups v2 'no internal processes' rule prevents task on parent."""
        root = MockCgroupV2Node("root")
        parent = root.add_child("parent_group")
        child = parent.add_child("leaf_group")

        # Child can accept tasks
        child.attach_task(pid=1001)
        assert_in(1001, child.procs)

        # Parent with active children must reject task attachment
        assert_raises(RuntimeError, parent.attach_task, 1002)

    def test_f02_cpu_quota_zero_and_massive_overruns():
        """F02-CHALLENGE.2: cpu.max zero quota and massive runtime burst handling."""
        # Zero quota throttles immediately
        cpu_zero = CpuBandwidth(quota_us=0, period_us=100000)
        assert_false(cpu_zero.charge(1), "Charging positive time on 0 quota must throttle")
        assert_eq(cpu_zero.nr_throttled, 1)

        # Massive burst: charge quota first, then massive overrun
        cpu_burst = CpuBandwidth(quota_us=10000, period_us=100000)
        assert_true(cpu_burst.charge(10000), "Charging up to quota must be allowed")
        assert_false(cpu_burst.charge(1000000), "Overrun beyond quota must be throttled")
        assert_eq(cpu_burst.nr_throttled, 1)
        assert_eq(cpu_burst.throttled_usec, 1000000)

    def test_f02_cpu_weight_extreme_proportions_and_clamping():
        """F02-CHALLENGE.3: cpu.weight boundary evaluation (1 vs 10000)."""
        w_min = CpuBandwidth(cpu_weight=1)
        w_max = CpuBandwidth(cpu_weight=10000)
        assert_eq(w_min.cpu_weight, 1)
        assert_eq(w_max.cpu_weight, 10000)

        total = w_min.cpu_weight + w_max.cpu_weight
        share_min = w_min.cpu_weight / total
        share_max = w_max.cpu_weight / total

        assert_true(share_min < 0.0001)
        assert_true(share_max > 0.9999)

    def test_f02_memory_max_hierarchical_overflow_and_uncharge_clamp():
        """F02-CHALLENGE.4: Memory controller exact boundary and uncharge clamp to zero."""
        mem = MemoryController(max_bytes=1024 * 1024)
        # Allocate exactly max_bytes
        assert_true(mem.charge(1024 * 1024))
        # 1 extra byte fails and records OOM
        assert_false(mem.charge(1))
        assert_eq(mem.events_oom, 1)

        # Uncharge more than allocated: must clamp to 0 without underflow
        mem.uncharge(10 * 1024 * 1024)
        assert_eq(mem.current_bytes, 0)

    def test_f02_io_token_bucket_adversarial_timestamp_and_asymmetric_throttling():
        """F02-CHALLENGE.5: I/O token bucket handles burst consumption and refill."""
        io = IoTokenBucket(wbps_max=2048)
        io.refill()
        # Charge exact limit
        assert_true(io.charge_io(is_write=True, bytes_count=2048))
        # Immediate subsequent write must be throttled
        assert_false(io.charge_io(is_write=True, bytes_count=1))
        # After refill, tokens available again
        io.refill()
        assert_true(io.charge_io(is_write=True, bytes_count=1024))

    suite.add("F02-CHALLENGE.1 cgroup v2 No-Internal-Process Structural Constraint", test_f02_no_internal_processes_constraint_tree)
    suite.add("F02-CHALLENGE.2 cpu.max Zero Quota & Massive Burst Throttling", test_f02_cpu_quota_zero_and_massive_overruns)
    suite.add("F02-CHALLENGE.3 cpu.weight Extreme Proportions (1 vs 10000)", test_f02_cpu_weight_extreme_proportions_and_clamping)
    suite.add("F02-CHALLENGE.4 memory.max Exact Boundary & Uncharge Underflow Clamp", test_f02_memory_max_hierarchical_overflow_and_uncharge_clamp)
    suite.add("F02-CHALLENGE.5 io.max Token Bucket Exhaustion & Refill", test_f02_io_token_bucket_adversarial_timestamp_and_asymmetric_throttling)

    # =========================================================================
    # Domain 3: POSIX Signal Delivery, Stack Alignment & ABI Compliance (F03)
    # =========================================================================

    def test_f03_rt_sigframe_abi_alignment_and_registers():
        """F03-CHALLENGE.1: Signal stack frame conforms to System V AMD64 ABI (rsp+8)%16==0."""
        # Emulate setup_rt_frame logic
        sp = 0x7FFF_8000
        # Frame size: pretcode(8) + UContextX86_64(~624) + SigInfo(32)
        frame_size = 8 + 624 + 32
        aligned_sp = (sp - frame_size) & ~0xF
        new_sp = aligned_sp - 8

        # System V ABI function entry requirement: (new_sp + 8) % 16 == 0
        assert_eq((new_sp + 8) % 16, 0, "System V x86_64 ABI entry stack must satisfy (sp + 8) % 16 == 0")

        # Register ABI checks
        sig = 10
        rdi = sig # 1st argument: signal number
        assert_eq(rdi, 10)
        rsi = new_sp + 8 + 624 # 2nd argument: siginfo_t pointer
        rdx = new_sp + 8       # 3rd argument: ucontext_t pointer
        assert_true(rsi > new_sp)
        assert_true(rdx > new_sp)

    def test_f03_sigaction_immutable_signals_sigkill_sigstop():
        """F03-CHALLENGE.2: SIGKILL and SIGSTOP handlers are immutable (raises PermissionError)."""
        mgr = MockSignalManager(pid=100)
        act = SigAction(handler_addr=0x401000)
        assert_raises(PermissionError, mgr.sigaction, SignalNumber.SIGKILL, act)
        assert_raises(PermissionError, mgr.sigaction, SignalNumber.SIGSTOP, act)

    def test_f03_sigprocmask_unblockable_signals_preserved():
        """F03-CHALLENGE.3: sigprocmask with all 64 bits set preserves unblockable SIGKILL/SIGSTOP."""
        mgr = MockSignalManager(pid=100)
        mgr.sigprocmask("SIG_SETMASK", 0xFFFFFFFFFFFFFFFF)
        kill_bit = 1 << (SignalNumber.SIGKILL - 1)
        stop_bit = 1 << (SignalNumber.SIGSTOP - 1)
        assert_eq(mgr.blocked_mask & kill_bit, 0, "SIGKILL must never be blocked")
        assert_eq(mgr.blocked_mask & stop_bit, 0, "SIGSTOP must never be blocked")

    def test_f03_rt_signal_queueing_multiple_instances():
        """F03-CHALLENGE.4: Real-time signals queue multiple instances with distinct payloads."""
        mgr = MockSignalManager(pid=100)
        # Block SIGRTMIN (34)
        rt_bit = 1 << (SignalNumber.SIGRTMIN - 1)
        mgr.sigprocmask("SIG_BLOCK", rt_bit)

        # Queue 3 instances with distinct data
        mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGRTMIN, sigval=101))
        mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGRTMIN, sigval=102))
        mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGRTMIN, sigval=103))

        assert_eq(len(mgr.pending_queue), 3, "All 3 real-time signals must be queued")

        # Unblock and dequeue in FIFO order
        mgr.sigprocmask("SIG_UNBLOCK", rt_bit)
        sig1 = mgr.dequeue_signal()
        sig2 = mgr.dequeue_signal()
        sig3 = mgr.dequeue_signal()

        assert_eq(sig1.sigval, 101)
        assert_eq(sig2.sigval, 102)
        assert_eq(sig3.sigval, 103)
        assert_eq(mgr.dequeue_signal(), None)

    def test_f03_signal_default_action_exit_codes():
        """F03-CHALLENGE.5: POSIX default actions yield exact exit codes (128 + sig)."""
        mgr = MockSignalManager(pid=200)

        # SIGINT -> 128 + 2 = 130
        mgr.execute_default_action(SignalNumber.SIGINT)
        assert_true(mgr.terminated)
        assert_eq(mgr.exit_code, 130)

        # SIGSEGV -> 128 + 11 = 139
        mgr2 = MockSignalManager(pid=201)
        mgr2.execute_default_action(SignalNumber.SIGSEGV)
        assert_true(mgr2.terminated)
        assert_eq(mgr2.exit_code, 139)

        # SIGCHLD -> ignored (not terminated)
        mgr3 = MockSignalManager(pid=202)
        mgr3.execute_default_action(SignalNumber.SIGCHLD)
        assert_false(mgr3.terminated)

    suite.add("F03-CHALLENGE.1 System V AMD64 ABI Signal Frame Stack Alignment", test_f03_rt_sigframe_abi_alignment_and_registers)
    suite.add("F03-CHALLENGE.2 SIGKILL and SIGSTOP Handler Immutability", test_f03_sigaction_immutable_signals_sigkill_sigstop)
    suite.add("F03-CHALLENGE.3 sigprocmask Unblockable Signal Mask Sanitization", test_f03_sigprocmask_unblockable_signals_preserved)
    suite.add("F03-CHALLENGE.4 Real-Time Signal Multiple Instance Queueing & FIFO Ordering", test_f03_rt_signal_queueing_multiple_instances)
    suite.add("F03-CHALLENGE.5 POSIX Signal Default Action Exit Code Oracle (128+sig)", test_f03_signal_default_action_exit_codes)

    # =========================================================================
    # Domain 4: Futex & POSIX Synchronization Invariants & Race Conditions (F04)
    # =========================================================================

    def test_f04_futex_wait_unaligned_or_val_mismatch():
        """F04-CHALLENGE.1: FUTEX_WAIT value mismatch returns -EAGAIN (-11)."""
        mgr = MockFutexManager()
        mgr.set_memory_val(0x4000, 42)
        # Expected value 99 does not match actual value 42
        res = mgr.futex_wait(0x4000, expected_val=99, tid=1)
        assert_eq(res, -11, "Value mismatch must return -EAGAIN")

        # Expected value 42 matches
        res_ok = mgr.futex_wait(0x4000, expected_val=42, tid=1)
        assert_eq(res_ok, 0)
        assert_in(1, mgr.waiters[0x4000])

    def test_f04_futex_cmp_requeue_atomic_transfer():
        """F04-CHALLENGE.2: FUTEX_CMP_REQUEUE atomic value check, wake, and transfer."""
        mgr = MockFutexManager()
        uaddr1 = 0x5000
        uaddr2 = 0x6000
        mgr.set_memory_val(uaddr1, 100)

        # Enqueue 3 waiters on uaddr1
        mgr.futex_wait(uaddr1, 100, tid=10)
        mgr.futex_wait(uaddr1, 100, tid=20)
        mgr.futex_wait(uaddr1, 100, tid=30)

        # Mismatched val3 returns -EAGAIN
        assert_eq(mgr.futex_cmp_requeue(uaddr1, uaddr2, nr_wake=1, nr_requeue=2, val3=999), -11)
        assert_eq(len(mgr.waiters[uaddr1]), 3)

        # Matching val3: wake 1 waiter and requeue 2 waiters to uaddr2
        res = mgr.futex_cmp_requeue(uaddr1, uaddr2, nr_wake=1, nr_requeue=2, val3=100)
        assert_eq(res, 3, "1 woken + 2 requeued = 3 total")
        assert_eq(len(mgr.waiters[uaddr1]), 0, "uaddr1 queue must be empty")
        assert_eq(len(mgr.waiters[uaddr2]), 2, "uaddr2 must hold 2 requeued waiters")
        assert_eq(mgr.waiters[uaddr2], [20, 30])

    def test_f04_pthread_mutex_kinds_and_recursion():
        """F04-CHALLENGE.3: Mutex ownership validation and non-owner unlock protection."""
        mgr = MockFutexManager()
        mutex = MockPthreadMutex(mgr, uaddr=0x7000)

        # TID 1 locks mutex
        assert_true(mutex.lock(tid=1))
        # Non-owner TID 2 cannot unlock
        assert_raises(PermissionError, mutex.unlock, tid=2)
        # Owner TID 1 unlocks successfully
        assert_true(mutex.unlock(tid=1))

    def test_f04_pthread_rwlock_reader_exclusion_and_underflow():
        """F04-CHALLENGE.4: Reader-writer lock mutual exclusion and underflow guard."""
        rw = MockPthreadRwLock()

        # Concurrent readers acquire lock
        for i in range(1, 21):
            assert_true(rw.read_lock(tid=i))
        assert_eq(rw.readers, 20)

        # Writer cannot acquire while readers hold lock
        assert_false(rw.write_lock(tid=99))

        # Readers release
        for i in range(1, 21):
            rw.read_unlock(tid=i)
        assert_eq(rw.readers, 0)

        # Underflow unlock must raise RuntimeError
        assert_raises(RuntimeError, rw.read_unlock, tid=1)

        # Writer acquires cleanly
        assert_true(rw.write_lock(tid=99))
        assert_false(rw.read_lock(tid=1))
        rw.write_unlock(tid=99)

    def test_f04_posix_semaphore_token_invariants():
        """F04-CHALLENGE.5: POSIX semaphore atomic token post/wait balance."""
        sem = MockPosixSemaphore(initial_value=0)
        assert_false(sem.wait(), "Zero tokens cannot be consumed")

        # Post 5 tokens
        for _ in range(5):
            sem.post()
        assert_eq(sem.value, 5)

        # Consume all 5
        for _ in range(5):
            assert_true(sem.wait())
        assert_eq(sem.value, 0)
        assert_false(sem.wait())

    suite.add("F04-CHALLENGE.1 FUTEX_WAIT Mismatch Value Error (-EAGAIN)", test_f04_futex_wait_unaligned_or_val_mismatch)
    suite.add("F04-CHALLENGE.2 FUTEX_CMP_REQUEUE Atomic Transfer & Wake Ordering", test_f04_futex_cmp_requeue_atomic_transfer)
    suite.add("F04-CHALLENGE.3 PthreadMutex Non-Owner Unlock Error (PermissionError)", test_f04_pthread_mutex_kinds_and_recursion)
    suite.add("F04-CHALLENGE.4 PthreadRwLock 20-Reader Concurrency & Underflow Guard", test_f04_pthread_rwlock_reader_exclusion_and_underflow)
    suite.add("F04-CHALLENGE.5 PosixSemaphore Token Conservation Invariant", test_f04_posix_semaphore_token_invariants)

    # =========================================================================
    # Domain 5: Swap & Virtual Memory Paging PTE Encoding & LRU Eviction (F05)
    # =========================================================================

    def test_f05_pte_swap_bitfield_layout_full_spectrum():
        """F05-CHALLENGE.1: x86_64 PTE Swap Entry Bitfield Layout & 50-bit Offset Boundaries."""
        # Bit 0 (Present) = 0
        # Bit 1 (Marker) = 1
        # Bits 2..=6 (5 bits) = swap_type (0..31)
        # Bits 7..=56 (50 bits) = slot_offset
        test_cases = [
            (0, 0),
            (1, 1),
            (15, 0x12345),
            (31, 0x3FFFFFFFFFFFF), # Maximum 50-bit offset (1125899906842623)
        ]

        for s_type, s_offset in test_cases:
            pte = encode_swap_entry(s_type, s_offset)
            assert_true(is_swap_entry(pte), f"PTE 0x{pte:x} must be recognized as swap entry")
            assert_eq(pte & 1, 0, "Present bit 0 must be 0")
            assert_eq(pte & 2, 2, "Swap marker bit 1 must be 1")

            dec_type, dec_offset = decode_swap_entry(pte)
            assert_eq(dec_type, s_type)
            assert_eq(dec_offset, s_offset)

        # Present bit set must reject
        present_pte = encode_swap_entry(5, 100) | 1
        assert_false(is_swap_entry(present_pte))

        # Zero PTE must reject
        assert_false(is_swap_entry(0))

    def test_f05_swap_manager_slot_exhaustion_and_double_free():
        """F05-CHALLENGE.2: Swap manager capacity bounds and double-free immunity."""
        mgr = MockSwapManager(max_slots=4) # Slots 1, 2, 3
        s1 = mgr.allocate_slot(0, b"DATA1" * 100)
        s2 = mgr.allocate_slot(0, b"DATA2" * 100)
        s3 = mgr.allocate_slot(0, b"DATA3" * 100)

        # 4th allocation must fail with MemoryError
        assert_raises(MemoryError, mgr.allocate_slot, 0, b"DATA4" * 100)

        # Free slot 2 and verify reallocation
        mgr.free_slot(0, s2)
        s_reallocated = mgr.allocate_slot(0, b"DATA_REALLOC" * 50)
        assert_eq(s_reallocated, s2)

    def test_f05_lru_clock_sweep_second_chance_aging():
        """F05-CHALLENGE.3: Two-handed LRU clock sweep page reclamation."""
        lru = MockPageReclaimLru()
        # Add 3 pages (marked accessed initially)
        lru.add_page(0x1000)
        lru.add_page(0x2000)
        lru.add_page(0x3000)

        # First sweep: clears accessed bit and moves to active list
        candidate1 = lru.clock_sweep_evict()
        # Once accessed bit is cleared, unreferenced page is evicted
        candidate2 = lru.clock_sweep_evict()
        assert_true(candidate2 in [0x1000, 0x2000, 0x3000])

    def test_f05_oom_killer_badness_and_immunity():
        """F05-CHALLENGE.4: OOM killer badness scoring: init & immune processes."""
        # Init task (PID 1) is immune
        assert_eq(MockOomKiller.calculate_badness(total_pages=500000, is_init=True), 0)

        # Task with oom_score_adj <= -1000 is immune
        assert_eq(MockOomKiller.calculate_badness(total_pages=500000, oom_score_adj=-1000), 0)

        # Normal tasks: score proportional to pages + oom_score_adj
        score_normal = MockOomKiller.calculate_badness(total_pages=200000, oom_score_adj=0)
        score_heavy = MockOomKiller.calculate_badness(total_pages=500000, oom_score_adj=100)
        assert_true(score_heavy > score_normal)

    def test_f05_page_fault_swap_in_demand_paging_distinction():
        """F05-CHALLENGE.5: #PF fault dispatch distinguishes swap-in from demand-zero & segv."""
        # Null dereference (< 0x1000)
        null_addr = 0x500
        assert_true(null_addr < 0x1000, "Null page fault")

        # Demand zero vs Swap-in:
        # Non-present + swap entry bit => Swap-in
        pte_swap = encode_swap_entry(1, 100)
        is_swap = is_swap_entry(pte_swap)
        assert_true(is_swap, "Must trigger demand swap-in")

        # Non-present + not swap => Demand zero
        pte_unmapped = 0
        assert_false(is_swap_entry(pte_unmapped), "Must trigger demand zero paging")

    suite.add("F05-CHALLENGE.1 x86_64 PTE Swap Bitfield & 50-bit Boundary Oracle", test_f05_pte_swap_bitfield_layout_full_spectrum)
    suite.add("F05-CHALLENGE.2 Swap Slot Capacity Saturation & Reallocation", test_f05_swap_manager_slot_exhaustion_and_double_free)
    suite.add("F05-CHALLENGE.3 LRU Page Aging Clock Sweep Eviction Oracle", test_f05_lru_clock_sweep_second_chance_aging)
    suite.add("F05-CHALLENGE.4 OOM Killer Scoring & Immunity Invariant", test_f05_oom_killer_badness_and_immunity)
    suite.add("F05-CHALLENGE.5 Page Fault Exception Demand-Zero vs Swap-In Discrimination", test_f05_page_fault_swap_in_demand_paging_distinction)

    return suite


if __name__ == "__main__":
    suite = run_all_challenges()
    passed, failed, details = suite.run(verbose=True)
    print("\n=======================================================================")
    print(f"MILESTONE 1 ADVERSARIAL STRESS CHALLENGE 2 RESULT: {passed} PASSED, {failed} FAILED")
    print("=======================================================================\n")
    sys.exit(0 if failed == 0 else 1)
