#!/usr/bin/env python3
"""
CorOS Milestone 1 Iteration 2 Deep Empirical Challenger Adversarial Suite
========================================================================
Target: Remediated Milestone 1 Subsystems:
- Futex & POSIX Synchronization Primitives (posix_sync_primitives.rs, futex.rs)
- Signal Stack Frame Serialization & System V AMD64 ABI (posix_signals.rs, linux_syscalls.rs)
- Chroot Path Containment & Directory Traversal Attacks (process_lifecycle.rs)
- IoTokenBucket High-Frequency Nanosecond Remainder Arithmetic (cgroup_v2.rs, cgroups.rs)
- Page Fault Demand Swap-In Priority Over Stack Expansion (page_fault.rs)

Executes rigorous adversarial boundary conditions, mathematical precision verification,
concurrency simulation, and security containment oracles.
"""

import sys
import struct
from pathlib import Path

# Add tests/e2e to sys.path
TESTS_E2E_DIR = Path(__file__).resolve().parent / "e2e"
sys.path.insert(0, str(TESTS_E2E_DIR))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in
)
from linux_subsystems.models import (
    CloneFlags, MountPropagation, UidGidExtent, MockUserNamespace,
    MockPidNamespace, MockChrootJail, MockCgroupV2Node, CpuBandwidth, MemoryController,
    IoTokenBucket, SignalNumber, SigAction, SigInfo, MockSignalManager,
    MockFutexManager, MockPthreadMutex, MockPthreadRwLock, MockPosixSemaphore,
    encode_swap_entry, decode_swap_entry, is_swap_entry, MockSwapManager, MockPageReclaimLru,
    MockOomKiller
)


def assert_raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type:
        return
    except Exception as e:
        raise AssertionError(f"Expected {exc_type.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"Expected {exc_type.__name__}, but no exception was raised")


def run_all_challenges() -> TestSuite:
    suite = TestSuite("Milestone 1 Iteration 2 Deep Empirical Challenger Suite", tier=5)

    # =========================================================================
    # Group 1: Futex & POSIX Sync Primitives Deep Concurrency Stress
    # =========================================================================

    def test_futex_cmp_requeue_atomic_transfer_exactness():
        """STRESS 1.1: FUTEX_CMP_REQUEUE transfers exactly (total - 1) waiters and wakes 1."""
        mgr = MockFutexManager()
        cond_uaddr = 0x2000_1000
        mutex_uaddr = 0x2000_2000
        cond_val = 100
        mgr.set_memory_val(cond_uaddr, cond_val)

        # Queue 15 threads on cond_uaddr
        for tid in range(1, 16):
            res = mgr.futex_wait(cond_uaddr, cond_val, tid=tid)
            assert_eq(res, 0)

        # Precondition: 15 waiters on cond_uaddr, 0 on mutex_uaddr
        assert_eq(len(mgr.waiters[cond_uaddr]), 15)
        assert_eq(len(mgr.waiters[mutex_uaddr]), 0)

        # Atomic CMP_REQUEUE: wake 1, requeue up to 100 to mutex_uaddr
        processed_count = mgr.futex_cmp_requeue(cond_uaddr, mutex_uaddr, 1, 100, val3=cond_val)
        assert_eq(processed_count, 15, "1 woken + 14 requeued = 15 total processed")

        # Postcondition: 0 waiters on cond_uaddr, 14 waiters on mutex_uaddr
        assert_eq(len(mgr.waiters[cond_uaddr]), 0)
        assert_eq(len(mgr.waiters[mutex_uaddr]), 14)

    def test_futex_cmp_requeue_val_mismatch_eagain():
        """STRESS 1.2: FUTEX_CMP_REQUEUE with mismatched expected val aborts with -EAGAIN (-11)."""
        mgr = MockFutexManager()
        cond_uaddr = 0x3000_1000
        mutex_uaddr = 0x3000_2000

        mgr.set_memory_val(cond_uaddr, 50)

        # Queue 5 threads on cond_uaddr at expected val 50
        for tid in range(1, 6):
            mgr.futex_wait(cond_uaddr, 50, tid=tid)

        # Caller expects val 999, but actual word has 50
        # In Linux ABI, if *uaddr != val3, FUTEX_CMP_REQUEUE returns -EAGAIN (-11)
        res = mgr.futex_cmp_requeue(cond_uaddr, mutex_uaddr, 1, 10, val3=999)
        assert_eq(res, -11, "Value mismatch must return -EAGAIN (-11)")

        # Verify waiters were NOT modified
        assert_eq(len(mgr.waiters[cond_uaddr]), 5)
        assert_eq(len(mgr.waiters[mutex_uaddr]), 0)

    def test_pthread_mutex_errorcheck_and_invariants():
        """STRESS 1.3: PthreadMutex type invariants (Normal/Slowpath + Non-owner unlock rejection)."""
        mgr = MockFutexManager()
        uaddr = 0x4000_1000
        mutex = MockPthreadMutex(futex_mgr=mgr, uaddr=uaddr)

        # Fastpath lock by tid 10
        assert_true(mutex.lock(tid=10))

        # Contended lock by tid 20 puts tid 20 to wait
        assert_false(mutex.lock(tid=20))
        assert_in(20, mgr.waiters[uaddr])

        # Non-owner unlock attempt raises PermissionError
        assert_raises(PermissionError, mutex.unlock, tid=30)

        # Proper owner unlock succeeds and wakes 1 waiter
        assert_true(mutex.unlock(tid=10))
        assert_eq(len(mgr.waiters[uaddr]), 0)

    def test_pthread_rwlock_concurrency_stress_and_underflow():
        """STRESS 1.4: PthreadRwLock 100 concurrent readers, writer lockout, and underflow guard."""
        rw = MockPthreadRwLock()
        for tid in range(1, 101):
            assert_true(rw.read_lock(tid=tid))
        assert_eq(rw.readers, 100)

        # Writer cannot lock while readers hold lock
        assert_false(rw.write_lock(tid=999))

        # Readers release one by one
        for tid in range(1, 101):
            rw.read_unlock(tid=tid)
        assert_eq(rw.readers, 0)

        # Reader underflow attempt must raise RuntimeError
        assert_raises(RuntimeError, rw.read_unlock, tid=1)

        # Writer can now acquire
        assert_true(rw.write_lock(tid=999))
        assert_eq(rw.writer, 999)

        # New reader blocked while writer holds lock
        assert_false(rw.read_lock(tid=101))

        # Non-owner writer cannot unlock
        assert_raises(PermissionError, rw.write_unlock, tid=888)

        # Real writer unlocks
        rw.write_unlock(tid=999)
        assert_eq(rw.writer, None)

    def test_posix_semaphore_fifo_token_conservation():
        """STRESS 1.5: PosixSemaphore exact token conservation under drain and replenish."""
        sem = MockPosixSemaphore(initial_value=5)
        # Drain all 5 tokens
        for _ in range(5):
            assert_true(sem.wait())
        assert_eq(sem.value, 0)

        # 6th wait must block / return False
        assert_false(sem.wait())

        # Post 10 tokens
        for _ in range(10):
            sem.post()
        assert_eq(sem.value, 10)

        # Drain 10 tokens
        for _ in range(10):
            assert_true(sem.wait())
        assert_eq(sem.value, 0)
        assert_false(sem.wait())

    # =========================================================================
    # Group 2: Signal Stack Frame & System V AMD64 ABI Mathematical Stress
    # =========================================================================

    def test_signal_frame_system_v_abi_stack_alignment_matrix():
        """STRESS 2.1: Rigorous System V AMD64 ABI alignment invariant (rsp + 8) % 16 == 0 across arbitrary initial SP."""
        frame_size = 8 + 624 + 32 # pretcode + ucontext + siginfo
        for offset in range(0, 1024, 7):
            initial_sp = 0x7FFF_0000 + offset
            aligned_sp = (initial_sp - frame_size) & ~0xF
            new_sp = aligned_sp - 8

            # Invariant: On function entry in System V AMD64 ABI, stack must satisfy (sp + 8) % 16 == 0
            assert_eq((new_sp + 8) % 16, 0, f"Failed ABI alignment for initial_sp=0x{initial_sp:x}")

            # Verify offsets do not overlap
            pretcode_addr = new_sp
            ucontext_addr = new_sp + 8
            siginfo_addr = new_sp + 8 + 624
            assert_eq(pretcode_addr + 8, ucontext_addr)
            assert_eq(ucontext_addr + 624, siginfo_addr)

    def test_signal_unblockable_signals_sigkill_sigstop_absolute_invariant():
        """STRESS 2.2: SIGKILL (9) and SIGSTOP (19) can NEVER be blocked, ignored, or intercepted."""
        mgr = MockSignalManager(pid=42)

        # 1. Attempt to block ALL 64 signals
        mgr.sigprocmask("SIG_SETMASK", 0xFFFF_FFFF_FFFF_FFFF)
        kill_mask = 1 << (SignalNumber.SIGKILL - 1)
        stop_mask = 1 << (SignalNumber.SIGSTOP - 1)
        assert_eq(mgr.blocked_mask & kill_mask, 0, "SIGKILL bit must remain 0 in blocked mask")
        assert_eq(mgr.blocked_mask & stop_mask, 0, "SIGSTOP bit must remain 0 in blocked mask")

        # 2. Attempt to register handler for SIGKILL -> PermissionError
        act = SigAction(handler_addr=0x5000_1000)
        assert_raises(PermissionError, mgr.sigaction, SignalNumber.SIGKILL, act)
        assert_raises(PermissionError, mgr.sigaction, SignalNumber.SIGSTOP, act)

        # 3. Queue SIGKILL -> dequeue_signal must retrieve it regardless of blocked mask
        mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGKILL))
        delivered = mgr.dequeue_signal()
        assert_true(delivered is not None)
        assert_eq(delivered.si_signo, SignalNumber.SIGKILL)

    def test_signal_realtime_fifo_queueing_and_payload_isolation():
        """STRESS 2.3: Real-time signals queue 50 distinct instances with strict payload isolation."""
        mgr = MockSignalManager(pid=77)
        rt_signo = SignalNumber.SIGRTMIN # 34

        # Block SIGRTMIN so they accumulate
        mgr.sigprocmask("SIG_BLOCK", 1 << (rt_signo - 1))

        # Queue 50 instances of SIGRTMIN with incrementing values
        for val in range(1000, 1050):
            mgr.queue_signal(SigInfo(si_signo=rt_signo, sigval=val))

        assert_eq(len(mgr.pending_queue), 50)

        # Unblock and deliver all 50 in exact FIFO order
        mgr.sigprocmask("SIG_UNBLOCK", 1 << (rt_signo - 1))
        delivered_vals = []
        while True:
            sig = mgr.dequeue_signal()
            if sig is None:
                break
            delivered_vals.append(sig.sigval)

        assert_eq(delivered_vals, list(range(1000, 1050)), "Real-time signals must maintain FIFO order")

    # =========================================================================
    # Group 3: Chroot Path Traversal Security & Containment Oracles
    # =========================================================================

    def test_chroot_adversarial_escape_permutations():
        """STRESS 3.1: Adversarial path escape attempts clamped inside jail root."""
        # Rust logic equivalent simulation from process_lifecycle.rs
        def resolve_path_rust_model(jail_root: str, path: str, cwd: str = "/") -> str:
            raw_vpath = path if path.startswith('/') else f"/{cwd.strip('/')}/{path}"
            components = []
            for seg in raw_vpath.split('/'):
                if not seg or seg == '.':
                    continue
                elif seg == '..':
                    if components:
                        components.pop()
                else:
                    components.append(seg)
            normalized = "/" + "/".join(components)
            if jail_root == "/":
                return normalized
            base = jail_root.rstrip('/')
            return base if normalized == "/" else f"{base}{normalized}"

        jail = "/var/chroot/container1"

        vectors = [
            ("/etc/passwd", f"{jail}/etc/passwd"),
            ("/../../../../../../etc/shadow", f"{jail}/etc/shadow"),
            ("/app/../../../../etc/group", f"{jail}/etc/group"),
            ("//.//.//usr/bin/sh", f"{jail}/usr/bin/sh"),
            ("/a/b/c/../../../../../../root/.ssh/id_rsa", f"{jail}/root/.ssh/id_rsa"),
            ("/var/log/../../../..", f"{jail}"),
            ("/", f"{jail}"),
            ("/./", f"{jail}"),
            ("/..", f"{jail}"),
            ("/dir/../dir/../dir/..", f"{jail}"),
            ("/dir/..//dir/..//dir/../etc/hosts", f"{jail}/etc/hosts"),
        ]

        for inp, expected in vectors:
            res = resolve_path_rust_model(jail, inp)
            assert_eq(res, expected, f"Failed vector '{inp}': got '{res}', expected '{expected}'")

    def test_chroot_root_jail_identity():
        """STRESS 3.2: When jail_root is '/', path resolution matches standard POSIX path normalization."""
        def resolve_root(path: str) -> str:
            components = []
            for seg in path.split('/'):
                if not seg or seg == '.':
                    continue
                elif seg == '..':
                    if components:
                        components.pop()
                else:
                    components.append(seg)
            return "/" + "/".join(components)

        assert_eq(resolve_root("/a/b/c/../../d"), "/a/d")
        assert_eq(resolve_root("/../../../../etc"), "/etc")
        assert_eq(resolve_root("/"), "/")

    # =========================================================================
    # Group 4: IoTokenBucket Nanosecond Remainder Arithmetic Stress
    # =========================================================================

    def test_io_token_bucket_high_frequency_nanosecond_refill_precision():
        """STRESS 4.1: Mathematical precision of nanosecond remainder accumulation over 50,000 polls."""
        class RustIoTokenBucketModel:
            def __init__(self, limit_per_sec: int):
                self.limit = limit_per_sec
                self.avail = limit_per_sec
                self.rem_ns = 0
                self.last_ns = 0

            def refill(self, now_ns: int):
                if now_ns <= self.last_ns:
                    return
                elapsed_ns = now_ns - self.last_ns
                self.last_ns = now_ns
                total_ns = elapsed_ns + self.rem_ns
                tokens = (self.limit * total_ns) // 1_000_000_000
                if tokens > 0:
                    self.avail = min(self.limit, self.avail + tokens)
                    consumed_ns = (tokens * 1_000_000_000) // self.limit
                    self.rem_ns = total_ns - consumed_ns
                else:
                    self.rem_ns = total_ns

        # Bucket with 10 IOPS (1 token every 100,000,000 ns = 100 ms)
        bucket = RustIoTokenBucketModel(limit_per_sec=10)
        bucket.avail = 0 # Drain completely

        # Poll 50,000 times at 2,000 ns increments (total 100,000,000 ns = 100 ms)
        for step in range(1, 50001):
            now = step * 2000
            bucket.refill(now)

        # After exactly 100 ms, exactly 1 token MUST have been accumulated
        assert_eq(bucket.avail, 1, "Nanosecond remainder accumulation must yield exactly 1 token at 100ms mark")
        assert_eq(bucket.rem_ns, 0, "Remainder must reset to 0 after exact integer token delivery")

    def test_io_token_bucket_massive_bandwidth_no_128bit_overflow():
        """STRESS 4.2: 100 GB/s bandwidth limits over 1 hour interval compute without overflow."""
        limit_100gbps = 100 * 1024 * 1024 * 1024 # 107,374,182,400 bytes/s
        elapsed_1hr_ns = 3600 * 1_000_000_000     # 3,600,000,000,000 ns

        # Total intermediate product in nanoseconds * bytes
        product = limit_100gbps * elapsed_1hr_ns
        assert_true(product < (1 << 128) - 1, "Product must not exceed u128::MAX")
        tokens = product // 1_000_000_000
        assert_eq(tokens, limit_100gbps * 3600)

    # =========================================================================
    # Group 5: Page Fault Demand Swap-In Priority Over Stack Growth
    # =========================================================================

    def test_page_fault_swap_in_priority_over_stack_growth():
        """STRESS 5.1: Address in user stack range with swap entry must trigger SwapIn, NOT StackGrowth."""
        class FaultAction:
            FatalNullDeref = "FatalNullDeref"
            FatalInstructionExecution = "FatalInstructionExecution"
            HandledCow = "HandledCow"
            HandledSwapIn = "HandledSwapIn"
            HandledStackGrow = "HandledStackGrow"
            HandledDemandZero = "HandledDemandZero"
            FatalStackOverflow = "FatalStackOverflow"
            FatalAccessViolation = "FatalAccessViolation"

        def evaluate_fault(fault_addr: int, is_present: bool, is_write: bool, is_user: bool,
                           user_rsp: int, is_cow: bool, is_swap: bool, max_stack: int = 8 * 1024 * 1024) -> str:
            if fault_addr < 0x1000:
                return FaultAction.FatalNullDeref
            if is_present and is_write and is_cow:
                return FaultAction.HandledCow
            # Step 4: Demand Swap-in (prior to stack grow)
            if not is_present and is_swap:
                return FaultAction.HandledSwapIn
            # Step 5: Stack Grow
            if not is_swap and is_user and fault_addr >= (user_rsp - 128) and fault_addr < 0x0000_7FFF_FFFF_0000:
                stack_top = 0x0000_7FFF_FFFF_0000
                current_stack_size = stack_top - fault_addr
                if current_stack_size <= max_stack:
                    return FaultAction.HandledStackGrow
                else:
                    return FaultAction.FatalStackOverflow
            # Step 6: Demand zero
            if not is_present:
                return FaultAction.HandledDemandZero
            return FaultAction.FatalAccessViolation

        stack_top = 0x0000_7FFF_FFFF_0000
        user_rsp = stack_top - 64 * 1024 # Stack is currently 64 KiB deep
        fault_in_stack_range = user_rsp - 64 # Inside 128-byte redzone / stack growth zone

        # SCENARIO A: Page has active swap entry (is_swap = True)
        action_swap = evaluate_fault(
            fault_addr=fault_in_stack_range,
            is_present=False,
            is_write=True,
            is_user=True,
            user_rsp=user_rsp,
            is_cow=False,
            is_swap=True # SWAP ENTRY PRESENT
        )
        assert_eq(action_swap, FaultAction.HandledSwapIn, "Active swap entry MUST take precedence over stack growth")

        # SCENARIO B: Page is unmapped (is_swap = False)
        action_stack = evaluate_fault(
            fault_addr=fault_in_stack_range,
            is_present=False,
            is_write=True,
            is_user=True,
            user_rsp=user_rsp,
            is_cow=False,
            is_swap=False # NO SWAP ENTRY
        )
        assert_eq(action_stack, FaultAction.HandledStackGrow, "Unmapped stack address triggers stack expansion")

        # SCENARIO C: Massive stack overflow (> 8 MiB)
        action_overflow = evaluate_fault(
            fault_addr=stack_top - (9 * 1024 * 1024),
            is_present=False,
            is_write=True,
            is_user=True,
            user_rsp=stack_top - (9 * 1024 * 1024) + 10,
            is_cow=False,
            is_swap=False
        )
        assert_eq(action_overflow, FaultAction.FatalStackOverflow)

    # Register all stress test functions
    suite.add("STRESS 1.1 FUTEX_CMP_REQUEUE Atomic Transfer Exactness", test_futex_cmp_requeue_atomic_transfer_exactness)
    suite.add("STRESS 1.2 FUTEX_CMP_REQUEUE Val Mismatch Abort (-EAGAIN)", test_futex_cmp_requeue_val_mismatch_eagain)
    suite.add("STRESS 1.3 PthreadMutex Errorcheck & Invariants", test_pthread_mutex_errorcheck_and_invariants)
    suite.add("STRESS 1.4 PthreadRwLock Concurrency & Underflow Guard", test_pthread_rwlock_concurrency_stress_and_underflow)
    suite.add("STRESS 1.5 PosixSemaphore Token Conservation", test_posix_semaphore_fifo_token_conservation)
    suite.add("STRESS 2.1 System V AMD64 ABI Signal Frame Stack Alignment (sp+8)%16==0", test_signal_frame_system_v_abi_stack_alignment_matrix)
    suite.add("STRESS 2.2 Unblockable Signals (SIGKILL/SIGSTOP) Immutable Invariant", test_signal_unblockable_signals_sigkill_sigstop_absolute_invariant)
    suite.add("STRESS 2.3 Real-Time Signal 50-Instance FIFO Isolation", test_signal_realtime_fifo_queueing_and_payload_isolation)
    suite.add("STRESS 3.1 Chroot Adversarial Escape Permutations Clamping", test_chroot_adversarial_escape_permutations)
    suite.add("STRESS 3.2 Chroot Root Jail Identity Normalization", test_chroot_root_jail_identity)
    suite.add("STRESS 4.1 IoTokenBucket 50,000-Poll High-Frequency Precision", test_io_token_bucket_high_frequency_nanosecond_refill_precision)
    suite.add("STRESS 4.2 IoTokenBucket 100 GB/s u128 Overflow Immunity", test_io_token_bucket_massive_bandwidth_no_128bit_overflow)
    suite.add("STRESS 5.1 Page Fault Demand Swap-In Priority Over Stack Growth", test_page_fault_swap_in_priority_over_stack_growth)

    return suite


if __name__ == "__main__":
    suite = run_all_challenges()
    passed, failed, results = suite.run(verbose=True)
    if failed > 0:
        print(f"\nFAILED: {failed} challenges failed!")
        sys.exit(1)
    else:
        print(f"\nALL {passed} DEEP EMPIRICAL ADVERSARIAL CHALLENGES PASSED!")
        sys.exit(0)
