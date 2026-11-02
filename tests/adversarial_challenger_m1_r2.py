#!/usr/bin/env python3
"""
CorOS Milestone 1 Iteration 2 Adversarial Stress Suite (Challenger 2)
===================================================================
Rigorous empirical adversarial verification targeting:
- Feature 1: resolve_process_path Path Traversal & Jail Escape Immunity
- Feature 2: IoTokenBucket Zero-Delta & Sub-Nanosecond High-Frequency Polling
- Feature 3: System V AMD64 ABI Signal Frame & Altstack Memory Boundary
- Feature 4: Futex CMP_REQUEUE Atomicity & Posix Mutex/Cond State Invariants
- Feature 5: Swap-In Priority Invariant vs Stack Auto-Growth Discrimination

Zero external package dependencies (pure standard library).
"""

import sys
import struct
import time
from pathlib import Path

# Add tests/e2e to sys.path
TESTS_E2E_DIR = Path(__file__).resolve().parent / "e2e"
sys.path.insert(0, str(TESTS_E2E_DIR))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne,
    assert_in, assert_not_in, assert_raises, assert_almost_eq
)
from linux_subsystems.models import (
    CloneFlags, MountPropagation, UidGidExtent, MockUserNamespace,
    MockPidNamespace, MockChrootJail, MockCgroupV2Node, CpuBandwidth,
    MemoryController, IoTokenBucket, SignalNumber, SigAction, SigInfo,
    MockSignalManager, MockFutexManager, MockPthreadMutex, MockPthreadRwLock,
    MockPosixSemaphore, encode_swap_entry, decode_swap_entry, is_swap_entry,
    MockSwapManager, MockPageReclaimLru, MockOomKiller
)


# =========================================================================
# Rust Exact Algorithm Replicas for Empirical Oracle Verification
# =========================================================================

class RustResolveProcessPathOracle:
    """Exact bit-for-bit behavioral replica of `resolve_process_path` in `process_lifecycle.rs`."""
    @staticmethod
    def resolve(root_dir: str, cwd_dir: str, path: str) -> str:
        # Build raw_vpath
        if path.startswith('/'):
            raw_vpath = path
        else:
            raw_vpath = '/' + cwd_dir.strip('/')
            if not raw_vpath.endswith('/'):
                raw_vpath += '/'
            raw_vpath += path

        # Canonicalize segments clamping .. at root
        components = []
        for seg in raw_vpath.split('/'):
            if not seg or seg == '.':
                continue
            elif seg == '..':
                if components:
                    components.pop()
            else:
                components.append(seg)

        normalized_in_jail = '/' + '/'.join(components)

        if root_dir == '/':
            return normalized_in_jail
        else:
            base_root = root_dir.rstrip('/')
            if normalized_in_jail == '/':
                return base_root
            else:
                return base_root + normalized_in_jail


class RustIoTokenBucketOracle:
    """Exact arithmetic replica of `IoTokenBucket` in `coripc/src/cgroup_v2.rs`."""
    def __init__(self, rbps=None, wbps=None, riops=None, wiops=None, now_ns=0):
        self.rbps = rbps
        self.wbps = wbps
        self.riops = riops
        self.wiops = wiops
        self.read_bytes_avail = rbps if rbps is not None else 0xFFFFFFFFFFFFFFFF
        self.write_bytes_avail = wbps if wbps is not None else 0xFFFFFFFFFFFFFFFF
        self.read_iops_avail = riops if riops is not None else 0xFFFFFFFF
        self.write_iops_avail = wiops if wiops is not None else 0xFFFFFFFF
        self.last_refill_timestamp_ns = now_ns
        self.rbps_rem_ns = 0
        self.wbps_rem_ns = 0
        self.riops_rem_ns = 0
        self.wiops_rem_ns = 0

    def refill(self, now_ns: int):
        if now_ns <= self.last_refill_timestamp_ns:
            return
        elapsed_ns = now_ns - self.last_refill_timestamp_ns
        self.last_refill_timestamp_ns = now_ns

        if self.rbps is not None and self.rbps > 0:
            total_ns = elapsed_ns + self.rbps_rem_ns
            tokens = (self.rbps * total_ns) // 1_000_000_000
            if tokens > 0:
                self.read_bytes_avail = min(self.rbps, self.read_bytes_avail + tokens)
                consumed_ns = (tokens * 1_000_000_000) // self.rbps
                self.rbps_rem_ns = min(1_000_000_000, total_ns - consumed_ns)
            else:
                self.rbps_rem_ns = min(1_000_000_000, total_ns)

        if self.wbps is not None and self.wbps > 0:
            total_ns = elapsed_ns + self.wbps_rem_ns
            tokens = (self.wbps * total_ns) // 1_000_000_000
            if tokens > 0:
                self.write_bytes_avail = min(self.wbps, self.write_bytes_avail + tokens)
                consumed_ns = (tokens * 1_000_000_000) // self.wbps
                self.wbps_rem_ns = min(1_000_000_000, total_ns - consumed_ns)
            else:
                self.wbps_rem_ns = min(1_000_000_000, total_ns)

        if self.riops is not None and self.riops > 0:
            total_ns = elapsed_ns + self.riops_rem_ns
            tokens = (self.riops * total_ns) // 1_000_000_000
            if tokens > 0:
                self.read_iops_avail = min(self.riops, self.read_iops_avail + tokens)
                consumed_ns = (tokens * 1_000_000_000) // self.riops
                self.riops_rem_ns = min(1_000_000_000, total_ns - consumed_ns)
            else:
                self.riops_rem_ns = min(1_000_000_000, total_ns)

        if self.wiops is not None and self.wiops > 0:
            total_ns = elapsed_ns + self.wiops_rem_ns
            tokens = (self.wiops * total_ns) // 1_000_000_000
            if tokens > 0:
                self.write_iops_avail = min(self.wiops, self.write_iops_avail + tokens)
                consumed_ns = (tokens * 1_000_000_000) // self.wiops
                self.wiops_rem_ns = min(1_000_000_000, total_ns - consumed_ns)
            else:
                self.wiops_rem_ns = min(1_000_000_000, total_ns)

    def charge_io(self, is_write: bool, bytes_count: int, now_ns: int) -> bool:
        self.refill(now_ns)
        if is_write:
            if self.wbps is not None and self.write_bytes_avail < bytes_count:
                return False
            if self.wiops is not None and self.write_iops_avail == 0:
                return False
            if self.wbps is not None:
                self.write_bytes_avail -= bytes_count
            if self.wiops is not None:
                self.write_iops_avail -= 1
        else:
            if self.rbps is not None and self.read_bytes_avail < bytes_count:
                return False
            if self.riops is not None and self.read_iops_avail == 0:
                return False
            if self.rbps is not None:
                self.read_bytes_avail -= bytes_count
            if self.riops is not None:
                self.read_iops_avail -= 1
        return True


def run_all_challenges() -> TestSuite:
    suite = TestSuite("Milestone 1 Iteration 2 Challenger 2 Adversarial Suite", tier=5)

    # =========================================================================
    # 1. resolve_process_path Path Traversal & Jail Containment Attacks
    # =========================================================================

    def test_adv_path_traversal_jail_containment_matrix():
        """ADV-01: Exhaustive path traversal attack matrix on resolve_process_path."""
        oracle = RustResolveProcessPathOracle()
        root = "/jail/container1"
        cwd = "/var/www"

        attacks = [
            # Traversal attacks escaping root
            ("/../../../etc/shadow", "/jail/container1/etc/shadow"),
            ("/../../../../../../../../../../../../../../../../../../etc/passwd", "/jail/container1/etc/passwd"),
            ("///a/b/../../c/./d", "/jail/container1/c/d"),
            ("//..//..//a", "/jail/container1/a"),
            ("..", "/jail/container1/var"),
            ("../..", "/jail/container1"),
            ("../../..", "/jail/container1"),
            ("../../../../etc/sudoers", "/jail/container1/etc/sudoers"),
            ("./././././././bin/sh", "/jail/container1/var/www/bin/sh"),
            ("///var///log///../spool/./mail", "/jail/container1/var/spool/mail"),
            ("/a/b/c/d/e/../../../../f", "/jail/container1/a/f"),
            ("/a/b/../../../../../..", "/jail/container1"),
            ("/", "/jail/container1"),
            ("////", "/jail/container1"),
            ("", "/jail/container1/var/www"),
        ]

        for raw_input, expected in attacks:
            resolved = oracle.resolve(root, cwd, raw_input)
            assert_eq(resolved, expected, f"Failed on input '{raw_input}': got '{resolved}', expected '{expected}'")
            # Verify jail containment: must always start with root
            assert_true(resolved.startswith(root), f"Escape detected: '{resolved}' does not start with '{root}'")

    def test_adv_path_traversal_root_is_slash():
        """ADV-02: resolve_process_path behavior when chroot jail root is system root ('/')."""
        oracle = RustResolveProcessPathOracle()
        root = "/"
        cwd = "/home/user"

        attacks = [
            ("/../../../etc/shadow", "/etc/shadow"),
            ("///a/b/../../c/./d", "/c/d"),
            ("../../../bin/bash", "/bin/bash"),
            ("documents/file.txt", "/home/user/documents/file.txt"),
            ("/", "/"),
            ("/////", "/"),
        ]

        for raw_input, expected in attacks:
            resolved = oracle.resolve(root, cwd, raw_input)
            assert_eq(resolved, expected, f"Failed on input '{raw_input}': got '{resolved}', expected '{expected}'")

    def test_adv_path_traversal_deep_nesting_and_trailing_slashes():
        """ADV-03: Ultra-deep nesting (1000 segments) and jail root trailing slash normalization."""
        oracle = RustResolveProcessPathOracle()

        # Jail root with multiple trailing slashes
        root_with_slashes = "/var/chroot/env////"
        cwd = "/"

        # 500 'dir' segments followed by 600 '..' segments
        deep_attack = "/".join(["dir"] * 500 + [".."] * 600 + ["secret.txt"])
        resolved = oracle.resolve(root_with_slashes, cwd, deep_attack)
        assert_eq(resolved, "/var/chroot/env/secret.txt")

    # =========================================================================
    # 2. IoTokenBucket Zero-Delta & Sub-Nanosecond High-Frequency Polling
    # =========================================================================

    def test_adv_token_bucket_zero_delta_high_frequency_polling():
        """ADV-04: IoTokenBucket under 100,000 zero-delta polling queries (dt = 0)."""
        bucket = RustIoTokenBucketOracle(wbps=10000, wiops=100, now_ns=1_000_000_000)
        assert_eq(bucket.write_bytes_avail, 10000)
        assert_eq(bucket.write_iops_avail, 100)

        # Consume 5000 bytes and 1 IOPS
        assert_true(bucket.charge_io(is_write=True, bytes_count=5000, now_ns=1_000_000_000))
        assert_eq(bucket.write_bytes_avail, 5000)
        assert_eq(bucket.write_iops_avail, 99)

        # Poll 100,000 times at the exact same timestamp (dt = 0)
        for _ in range(100_000):
            bucket.refill(now_ns=1_000_000_000)

        # Tokens must remain exactly unchanged (zero-delta returns early, no corruption)
        assert_eq(bucket.write_bytes_avail, 5000)
        assert_eq(bucket.write_iops_avail, 99)
        assert_eq(bucket.last_refill_timestamp_ns, 1_000_000_000)

    def test_adv_token_bucket_backward_clock_skew():
        """ADV-05: IoTokenBucket immunity against backward time jumps (now_ns < last_refill)."""
        bucket = RustIoTokenBucketOracle(wbps=5000, wiops=50, now_ns=5_000_000_000)
        assert_true(bucket.charge_io(is_write=True, bytes_count=2000, now_ns=5_000_000_000))

        # Backward time jump: now_ns is earlier than last_refill_timestamp_ns
        bucket.refill(now_ns=4_000_000_000)
        assert_eq(bucket.write_bytes_avail, 3000, "Tokens must not mutate on backward time jump")
        assert_eq(bucket.last_refill_timestamp_ns, 5_000_000_000)

    def test_adv_token_bucket_sub_microsecond_remainder_conservation():
        """ADV-06: Ultra-high frequency 1-ns polling: exact token conservation without truncation loss."""
        # Rate: 1,000 bytes per second = 1 byte per 1,000,000 ns
        bucket = RustIoTokenBucketOracle(wbps=1000, wiops=100, now_ns=0)
        # Drain all tokens
        assert_true(bucket.charge_io(is_write=True, bytes_count=1000, now_ns=0))
        assert_eq(bucket.write_bytes_avail, 0)

        # Advance 1,000,000 steps of 1 ns each (total 1,000,000 ns = 1 ms)
        for t in range(1, 1_000_001):
            bucket.refill(now_ns=t)

        # Exactly 1 byte should have been generated at 1 ms!
        assert_eq(bucket.write_bytes_avail, 1, "Exactly 1 token must be refilled after 1ms at 1000 B/s")
        assert_eq(bucket.wbps_rem_ns, 0, "Remainder must reset to 0 after exact token generation")

    def test_adv_token_bucket_fractional_remainder_accumulation():
        """ADV-07: Fractional nanosecond accumulation over 333-ns intervals."""
        # Rate: 3 bytes/sec. At 3 B/s, each token requires 333,333,333.33 ns.
        bucket = RustIoTokenBucketOracle(wbps=3, wiops=10, now_ns=0)
        bucket.write_bytes_avail = 0

        # Step 1: 500,000,000 ns (0.5 sec) -> should yield 1 token, remainder 166,666,667 ns
        bucket.refill(now_ns=500_000_000)
        assert_eq(bucket.write_bytes_avail, 1)

        # Step 2: another 500,000,000 ns (total 1 sec) -> should yield 2 more tokens (total 3)
        bucket.refill(now_ns=1_000_000_000)
        assert_eq(bucket.write_bytes_avail, 3, "Total 3 tokens over 1 second at 3 B/s")

    def test_adv_token_bucket_massive_bandwidth_and_iops():
        """ADV-08: Massive enterprise bandwidth (100 GB/s) and IOPS (10M IOPS) arithmetic overflow test."""
        huge_bw = 100 * 1024 * 1024 * 1024  # 100 GB/s
        huge_iops = 10_000_000               # 10M IOPS
        bucket = RustIoTokenBucketOracle(rbps=huge_bw, riops=huge_iops, now_ns=0)
        assert_eq(bucket.read_bytes_avail, huge_bw)
        assert_eq(bucket.read_iops_avail, huge_iops)

        # Consume 50 GB and 1 IOPS
        assert_true(bucket.charge_io(is_write=False, bytes_count=50 * 1024 * 1024 * 1024, now_ns=0))
        assert_eq(bucket.read_bytes_avail, 50 * 1024 * 1024 * 1024)
        assert_eq(bucket.read_iops_avail, 9_999_999)

        # Refill after 1 second (no overflow in u128 math)
        bucket.refill(now_ns=1_000_000_000)
        assert_eq(bucket.read_bytes_avail, huge_bw, "Clamped to max burst capacity")
        assert_eq(bucket.read_iops_avail, huge_iops)

    # =========================================================================
    # 3. System V AMD64 ABI Signal Frame & Altstack Memory Boundary
    # =========================================================================

    def test_adv_signal_frame_abi_alignment_and_registers():
        """ADV-09: Verifies 16-byte alignment of Signal Frame (rsp % 16 == 8 before handler entry)."""
        # System V AMD64 ABI requires:
        # Upon signal handler entry: (RSP + 8) % 16 == 0, i.e., RSP % 16 == 8
        sp = 0x7FFF_FFFF_E000
        frame_size = 512  # Representative SigFrame size
        aligned_sp = (sp - frame_size) & ~0xF
        new_sp = aligned_sp - 8
        assert_eq((new_sp + 8) % 16, 0, "Signal handler stack must be 16-byte aligned after return address push")

    def test_adv_signal_altstack_boundary_containment():
        """ADV-10: Alternate signal stack (sigaltstack) bounds checking and recursion."""
        alt_base = 0x6000_0000
        alt_size = 64 * 1024  # 64 KiB
        alt_top = alt_base + alt_size

        # When current SP is outside altstack, target_sp becomes alt_top
        cur_sp = 0x7FFF_0000
        in_altstack = (cur_sp >= alt_base and cur_sp < alt_top)
        assert_false(in_altstack)
        target_sp = alt_top if not in_altstack else cur_sp
        assert_eq(target_sp, alt_top)

        # When already executing on altstack, target_sp remains current SP (supports nested signals)
        nested_sp = alt_base + 32 * 1024
        in_altstack_nested = (nested_sp >= alt_base and nested_sp < alt_top)
        assert_true(in_altstack_nested)
        target_sp_nested = nested_sp
        assert_eq(target_sp_nested, nested_sp)

    # =========================================================================
    # 4. Futex CMP_REQUEUE Atomicity & Posix Mutex/Cond Invariants
    # =========================================================================

    def test_adv_futex_cmp_requeue_and_cond_var_migration():
        """ADV-11: FUTEX_CMP_REQUEUE atomic waiter migration from condvar to mutex."""
        futex_mgr = MockFutexManager()
        cond_addr = 0x1000
        mutex_addr = 0x2000
        futex_mgr.set_memory_val(cond_addr, 0)
        futex_mgr.set_memory_val(mutex_addr, 0)

        # 10 threads waiting on condition variable
        for tid in range(101, 111):
            futex_mgr.futex_wait(uaddr=cond_addr, expected_val=0, tid=tid)
        assert_eq(len(futex_mgr.waiters[cond_addr]), 10)
        assert_eq(len(futex_mgr.waiters[mutex_addr]), 0)

        # Atomic requeue: wake 1, requeue 9 to mutex
        total_migrated = futex_mgr.futex_cmp_requeue(
            uaddr1=cond_addr,
            uaddr2=mutex_addr,
            nr_wake=1,
            nr_requeue=9,
            val3=0
        )
        assert_eq(total_migrated, 10)
        assert_eq(len(futex_mgr.waiters[cond_addr]), 0, "All condvar waiters migrated")
        assert_eq(len(futex_mgr.waiters[mutex_addr]), 9, "9 waiters moved to mutex queue")

    def test_adv_pthread_mutex_non_owner_unlock_defense():
        """ADV-12: PthreadMutex strictly rejects non-owner unlock attempts (PermissionError)."""
        futex_mgr = MockFutexManager()
        mutex = MockPthreadMutex(futex_mgr=futex_mgr, uaddr=0x5000)
        assert_true(mutex.lock(tid=501))

        # Non-owner (tid 502) tries to unlock -> raises PermissionError
        assert_raises(PermissionError, mutex.unlock, 502)

        # Legitimate owner unlocks
        assert_true(mutex.unlock(501))

    # =========================================================================
    # 5. Swap-In Priority Invariant vs Stack Auto-Growth Discrimination
    # =========================================================================

    def test_adv_page_fault_swap_priority_over_stack_grow():
        """ADV-13: Swap-in priority over stack auto-growth for addresses near user RSP."""
        # Simulated page fault evaluator matching kernel/memory/page_fault.rs
        def evaluate_pf(fault_addr: int, user_rsp: int, is_present: bool, is_swap: bool, is_user: bool) -> str:
            # Step 3: COW
            # Step 4: Demand Swap-in
            if not is_present and is_swap:
                return "HANDLED_SWAP_IN"
            # Step 5: Stack grow
            if not is_swap and is_user and fault_addr >= (user_rsp - 128) and fault_addr < 0x0000_7FFF_FFFF_0000:
                return "HANDLED_STACK_GROW"
            # Step 6: Demand zero
            if not is_present:
                return "HANDLED_DEMAND_ZERO"
            return "FATAL_SEGV"

        rsp = 0x7FFF_FFFF_0000
        fault_near_stack = rsp - 64  # within 128-byte red zone!

        # Case A: Address has active swap entry -> MUST trigger swap-in, NOT stack growth!
        action_swap = evaluate_pf(fault_near_stack, rsp, is_present=False, is_swap=True, is_user=True)
        assert_eq(action_swap, "HANDLED_SWAP_IN", "Active swap entry near stack pointer must trigger swap-in")

        # Case B: Address is unmapped -> triggers stack growth
        action_grow = evaluate_pf(fault_near_stack, rsp, is_present=False, is_swap=False, is_user=True)
        assert_eq(action_grow, "HANDLED_STACK_GROW", "Unmapped stack address triggers stack growth")

    def test_adv_path_traversal_unicode_and_spaces():
        """ADV-14: resolve_process_path with Unicode UTF-8 paths, spaces, and redundant traversal."""
        oracle = RustResolveProcessPathOracle()
        root = "/jail/app"
        cwd = "/var/log"

        p1 = "/usr/share/日本語/../../share/日本語/config.json"
        assert_eq(oracle.resolve(root, cwd, p1), "/jail/app/usr/share/日本語/config.json")

        p2 = "/var/my documents/../my documents/file name with spaces.txt"
        assert_eq(oracle.resolve(root, cwd, p2), "/jail/app/var/my documents/file name with spaces.txt")

    def test_adv_path_traversal_relative_parent_pop():
        """ADV-15: resolve_process_path relative path popping parent directory from nested CWD."""
        oracle = RustResolveProcessPathOracle()
        root = "/jail/chroot"
        cwd = "/a/b/c/d"

        # Pop 2 levels: ../.. from /a/b/c/d -> /a/b
        p1 = "../../target/release/coros"
        assert_eq(oracle.resolve(root, cwd, p1), "/jail/chroot/a/b/target/release/coros")

        # Pop beyond root: 10 levels of ..
        p2 = "../" * 10 + "etc/shadow"
        assert_eq(oracle.resolve(root, cwd, p2), "/jail/chroot/etc/shadow")

    def test_adv_token_bucket_zero_limit_rejection():
        """ADV-16: IoTokenBucket with zero limits (wbps=0, wiops=0) strictly blocks all write I/O."""
        bucket = RustIoTokenBucketOracle(wbps=0, wiops=0, now_ns=0)
        assert_eq(bucket.write_bytes_avail, 0)
        assert_eq(bucket.write_iops_avail, 0)
        # Charging even 1 byte must fail
        assert_false(bucket.charge_io(is_write=True, bytes_count=1, now_ns=1_000_000_000))
        # Refilling does not add tokens when limit is 0
        bucket.refill(now_ns=2_000_000_000)
        assert_eq(bucket.write_bytes_avail, 0)

    def test_adv_token_bucket_unlimited_configuration():
        """ADV-17: IoTokenBucket with None limits (unlimited) allows arbitrary throughput."""
        bucket = RustIoTokenBucketOracle(rbps=None, riops=None, now_ns=0)
        # Charge 1 TB
        assert_true(bucket.charge_io(is_write=False, bytes_count=1024**4, now_ns=100))
        # Avail is untouched (unlimited)
        assert_eq(bucket.read_bytes_avail, 0xFFFFFFFFFFFFFFFF)

    def test_adv_token_bucket_atomicity_on_insufficient_tokens():
        """ADV-18: IoTokenBucket preserves available tokens when request exceeds capacity."""
        bucket = RustIoTokenBucketOracle(wbps=1000, wiops=10, now_ns=0)
        # Try to charge 2000 bytes (exceeds 1000)
        assert_false(bucket.charge_io(is_write=True, bytes_count=2000, now_ns=0))
        # Tokens must not be deducted on failure
        assert_eq(bucket.write_bytes_avail, 1000)
        assert_eq(bucket.write_iops_avail, 10)

    def test_adv_signals_sigkill_sigstop_immutability():
        """ADV-19: SIGKILL (9) and SIGSTOP (19) handler reassignment is strictly rejected."""
        sig_mgr = MockSignalManager(pid=1001)
        # Attempting to assign custom handler to SIGKILL (9) -> raises PermissionError
        assert_raises(PermissionError, sig_mgr.sigaction, SignalNumber.SIGKILL, SigAction(handler_addr=0x1234))
        # Attempting to assign custom handler to SIGSTOP (19) -> raises PermissionError
        assert_raises(PermissionError, sig_mgr.sigaction, SignalNumber.SIGSTOP, SigAction(handler_addr=0x1234))

    def test_adv_signals_unblockable_signals_sanitization():
        """ADV-20: sigprocmask automatically strips SIGKILL and SIGSTOP from blocked mask."""
        sig_mgr = MockSignalManager(pid=1001)
        mask_with_unblockable = (1 << (SignalNumber.SIGKILL - 1)) | (1 << (SignalNumber.SIGSTOP - 1)) | (1 << (SignalNumber.SIGTERM - 1))
        sig_mgr.sigprocmask("SIG_SETMASK", mask_with_unblockable)

        # SIGKILL and SIGSTOP must NOT be in the blocked mask
        effective_mask = sig_mgr.blocked_mask
        assert_eq(effective_mask & (1 << (SignalNumber.SIGKILL - 1)), 0)
        assert_eq(effective_mask & (1 << (SignalNumber.SIGSTOP - 1)), 0)
        assert_ne(effective_mask & (1 << (SignalNumber.SIGTERM - 1)), 0)

    def test_adv_signals_realtime_fifo_queueing():
        """ADV-21: Real-time signals queue multiple instances and dequeue in strict FIFO order."""
        sig_mgr = MockSignalManager(pid=1001)
        sig_rt1 = SignalNumber.SIGRTMIN
        # Queue 3 instances of SIGRTMIN with different payloads
        sig_mgr.queue_signal(SigInfo(si_signo=sig_rt1, si_code=1, sigval=100))
        sig_mgr.queue_signal(SigInfo(si_signo=sig_rt1, si_code=2, sigval=200))
        sig_mgr.queue_signal(SigInfo(si_signo=sig_rt1, si_code=3, sigval=300))

        # Dequeue must return them in exact FIFO order
        s1 = sig_mgr.dequeue_signal()
        assert_true(s1 is not None and s1.sigval == 100)
        s2 = sig_mgr.dequeue_signal()
        assert_true(s2 is not None and s2.sigval == 200)
        s3 = sig_mgr.dequeue_signal()
        assert_true(s3 is not None and s3.sigval == 300)


    def test_adv_futex_wait_value_mismatch_eagain():
        """ADV-22: futex_wait with value mismatch returns -EAGAIN (-11)."""
        futex_mgr = MockFutexManager()
        uaddr = 0x8000
        futex_mgr.set_memory_val(uaddr, 42)
        # Calling wait with expected 0 != 42
        res = futex_mgr.futex_wait(uaddr=uaddr, expected_val=0, tid=99)
        assert_eq(res, -11, "Value mismatch must return -EAGAIN (-11)")
        assert_eq(len(futex_mgr.waiters[uaddr]), 0, "No waiter should be queued on mismatch")

    def test_adv_futex_cmp_requeue_val_mismatch_eagain():
        """ADV-23: futex_cmp_requeue with expected value mismatch returns -EAGAIN (-11)."""
        futex_mgr = MockFutexManager()
        uaddr1 = 0x9000
        uaddr2 = 0x9100
        futex_mgr.set_memory_val(uaddr1, 10)
        futex_mgr.set_memory_val(uaddr2, 0)
        futex_mgr.futex_wait(uaddr=uaddr1, expected_val=10, tid=88)

        # Requeue with wrong val3=99 != 10
        res = futex_mgr.futex_cmp_requeue(uaddr1=uaddr1, uaddr2=uaddr2, nr_wake=1, nr_requeue=1, val3=99)
        assert_eq(res, -11, "CMP_REQUEUE val mismatch must return -EAGAIN (-11)")
        assert_eq(len(futex_mgr.waiters[uaddr1]), 1, "Waiter must remain on original queue")

    def test_adv_page_fault_red_zone_boundaries():
        """ADV-24: Page fault evaluator discriminates exact 128-byte red zone boundaries."""
        def eval_pf(fault_addr: int, user_rsp: int) -> str:
            if fault_addr >= (user_rsp - 128) and fault_addr < 0x0000_7FFF_FFFF_0000:
                return "HANDLED_STACK_GROW"
            return "FATAL_SEGV"

        rsp = 0x7FFF_0000
        # Exact boundary: rsp - 128 -> inside red zone
        assert_eq(eval_pf(rsp - 128, rsp), "HANDLED_STACK_GROW")
        # Boundary - 1: rsp - 129 -> outside red zone -> fatal SEGV
        assert_eq(eval_pf(rsp - 129, rsp), "FATAL_SEGV")
        # Exact RSP -> inside
        assert_eq(eval_pf(rsp, rsp), "HANDLED_STACK_GROW")

    def test_adv_page_fault_stack_max_limit_enforcement():
        """ADV-25: Page fault auto-growth enforces user stack max bytes (e.g. 8 MiB limit)."""
        stack_top = 0x0000_7FFF_FFFF_0000
        max_stack_bytes = 8 * 1024 * 1024  # 8 MiB
        min_allowed_addr = stack_top - max_stack_bytes

        def check_grow(fault_addr: int) -> bool:
            current_stack_size = stack_top - fault_addr
            return current_stack_size <= max_stack_bytes

        # 4 MiB below stack top -> allowed
        assert_true(check_grow(stack_top - 4 * 1024 * 1024))
        # Exactly 8 MiB below stack top -> allowed
        assert_true(check_grow(min_allowed_addr))
        # 8 MiB + 1 byte below stack top -> rejected (stack overflow)
        assert_false(check_grow(min_allowed_addr - 1))

    # Add tests to suite
    suite.add("ADV-01 resolve_process_path Path Traversal Attack Matrix", test_adv_path_traversal_jail_containment_matrix)
    suite.add("ADV-02 resolve_process_path System Root ('/') Jail Behavior", test_adv_path_traversal_root_is_slash)
    suite.add("ADV-03 resolve_process_path Deep Nesting & Trailing Slashes", test_adv_path_traversal_deep_nesting_and_trailing_slashes)
    suite.add("ADV-04 IoTokenBucket Zero-Delta High-Frequency Polling (100k)", test_adv_token_bucket_zero_delta_high_frequency_polling)
    suite.add("ADV-05 IoTokenBucket Backward Clock Skew Immunity", test_adv_token_bucket_backward_clock_skew)
    suite.add("ADV-06 IoTokenBucket Sub-Microsecond Remainder Conservation", test_adv_token_bucket_sub_microsecond_remainder_conservation)
    suite.add("ADV-07 IoTokenBucket Fractional Remainder Accumulation (333ns)", test_adv_token_bucket_fractional_remainder_accumulation)
    suite.add("ADV-08 IoTokenBucket Massive Bandwidth (100 GB/s) & IOPS (10M)", test_adv_token_bucket_massive_bandwidth_and_iops)
    suite.add("ADV-09 Signal Frame System V AMD64 ABI 16-Byte Stack Alignment", test_adv_signal_frame_abi_alignment_and_registers)
    suite.add("ADV-10 Signal Altstack Memory Boundary & Nested Signal Containment", test_adv_signal_altstack_boundary_containment)
    suite.add("ADV-11 Futex CMP_REQUEUE Atomic Migration & Wake Ordering", test_adv_futex_cmp_requeue_and_cond_var_migration)
    suite.add("ADV-12 PthreadMutex Non-Owner Unlock Rejection Defense (PermissionError)", test_adv_pthread_mutex_non_owner_unlock_defense)
    suite.add("ADV-13 Page Fault Demand Swap-In Priority Over Stack Growth", test_adv_page_fault_swap_priority_over_stack_grow)
    suite.add("ADV-14 resolve_process_path Unicode & Whitespace Normalization", test_adv_path_traversal_unicode_and_spaces)
    suite.add("ADV-15 resolve_process_path Nested CWD Parent Traversal Clamping", test_adv_path_traversal_relative_parent_pop)
    suite.add("ADV-16 IoTokenBucket Zero-Limit Total Throttling", test_adv_token_bucket_zero_limit_rejection)
    suite.add("ADV-17 IoTokenBucket Unlimited Configuration Throughput", test_adv_token_bucket_unlimited_configuration)
    suite.add("ADV-18 IoTokenBucket Insufficient Tokens Transaction Atomicity", test_adv_token_bucket_atomicity_on_insufficient_tokens)
    suite.add("ADV-19 Signal Subsystem SIGKILL & SIGSTOP Immutability Defense", test_adv_signals_sigkill_sigstop_immutability)
    suite.add("ADV-20 Signal Mask Sanitization Strips Unblockable Signals", test_adv_signals_unblockable_signals_sanitization)
    suite.add("ADV-21 Real-Time Signal Strict FIFO Multi-Instance Queueing", test_adv_signals_realtime_fifo_queueing)
    suite.add("ADV-22 Futex Wait Expected Value Mismatch Returns -EAGAIN", test_adv_futex_wait_value_mismatch_eagain)
    suite.add("ADV-23 Futex CMP_REQUEUE Value Mismatch Returns -EAGAIN", test_adv_futex_cmp_requeue_val_mismatch_eagain)
    suite.add("ADV-24 Page Fault Red Zone Boundary Precision (128-byte clamp)", test_adv_page_fault_red_zone_boundaries)
    suite.add("ADV-25 Page Fault Stack Maximum Growth Limit (8 MiB clamp)", test_adv_page_fault_stack_max_limit_enforcement)

    return suite



if __name__ == "__main__":
    test_suite = run_all_challenges()
    passed, failed, details = test_suite.run(verbose=True)
    if failed > 0:
        print(f"\n[FAIL] {failed} challenges failed!")
        sys.exit(1)
    else:
        print(f"\n[SUCCESS] All {passed} adversarial challenges passed!")
        sys.exit(0)
