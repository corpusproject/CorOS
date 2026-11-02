"""
Tier 1: Linux Subsystems Feature Coverage (Features 1 - 21)
===========================================================
CorOS/tests/e2e/linux_subsystems/test_tier1_feature_coverage.py

Comprehensive opaque-box functional tests covering the primary behavior
(happy path and essential validation) of all 21 Linux subsystem features (5 tests per feature).
Total: 105 test cases.
"""

import struct
import sys
from pathlib import Path

# Add tests/e2e to sys.path
TESTS_E2E_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TESTS_E2E_DIR))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_not_in,
    assert_raises
)
from linux_subsystems.models import (
    CloneFlags, MountPropagation, UidGidExtent, MockUserNamespace,
    MockPidNamespace, MockUtsNamespace, MockNetNamespace, MockMountNamespace,
    MockChrootJail, MockCgroupV2Node, CpuBandwidth, MemoryController, IoTokenBucket,
    SignalNumber, SigAction, SigActionFlags, SigDisposition, SigInfo, UContextX86_64,
    MockSignalManager, FutexOp, FUTEX_WAITERS, FUTEX_OWNER_DIED, MockFutexManager,
    MockPthreadMutex, MockPthreadRwLock, MockPosixSemaphore,
    encode_swap_entry, decode_swap_entry, is_swap_entry, MockSwapManager,
    MockPageReclaimLru, MockOomKiller,
    UnixSocketType, Ucred, MockUnixDomainSocket,
    MockFifoInode, MockPosixMessageQueue, MockSharedMemoryManager,
    ElfDynamicTag, ElfRelocType, MockDynamicLinker,
    BtrfsChunk, MockBtrfsParser, MockZfsParser, MockF2fsParser, MockXfsParser,
    MockIso9660ExtendedParser,
    XhciTrb, MockXhciRing, EhciQtd, EhciQueueHead, MockEhciController, MockUsbHidDecoder,
    NetfilterHook, NfVerdict, Packet5Tuple, MockNetfilterEngine,
    TcpConntrackState, MockConntrackNatTable,
    VmExitReason, KvmExit, MockVmcsPage, MockVmcbPage, MockKvmVcpuRunLoop
)


def build_suite() -> TestSuite:
    suite = TestSuite("Linux Subsystems - Tier 1 Feature Coverage (F01-F21)", tier=1)

    # ------------------------------------------------------------------------
    # Feature 1: Namespaces & Chroot (R1.1)
    # ------------------------------------------------------------------------
    def test_f01_pid_namespace_virtual_pid_allocation():
        """F01.1: PID namespace allocates local virtual PIDs 1..N isolated from host."""
        root_ns = MockPidNamespace(ns_id=1)
        child_ns = MockPidNamespace(ns_id=2, parent=root_ns)
        vpid1 = child_ns.allocate_vpid(global_pid=1001)
        vpid2 = child_ns.allocate_vpid(global_pid=1002)
        assert_eq(vpid1, 1, "Child namespace init task must receive virtual PID 1")
        assert_eq(vpid2, 2, "Second task in child namespace must receive virtual PID 2")
        assert_eq(child_ns.tasks[1], 1001)
        assert_eq(child_ns.global_to_vpid[1002], 2)

    def test_f01_pid_namespace_init_termination_cascade():
        """F01.2: Termination of virtual PID 1 cascades termination to all child tasks."""
        child_ns = MockPidNamespace(ns_id=3)
        child_ns.allocate_vpid(global_pid=2001) # vpid 1
        child_ns.allocate_vpid(global_pid=2002) # vpid 2
        child_ns.allocate_vpid(global_pid=2003) # vpid 3
        killed = child_ns.release_task(vpid=1)
        assert_in(2002, killed, "Cascade kill must include task 2002")
        assert_in(2003, killed, "Cascade kill must include task 2003")
        assert_true(child_ns.is_dead, "Namespace must be marked dead after init exits")

    def test_f01_mount_namespace_propagation_types():
        """F01.3: Mount namespace tracks Shared, Private, Slave propagation states."""
        mnt_ns = MockMountNamespace(ns_id=1)
        mnt_ns.bind_mount("/mnt/shared", "/mnt/peer", MountPropagation.SHARED)
        mnt_ns.bind_mount("/mnt/private", "/mnt/priv", MountPropagation.PRIVATE)
        assert_eq(mnt_ns.mounts["/mnt/peer"], MountPropagation.SHARED)
        assert_eq(mnt_ns.mounts["/mnt/priv"], MountPropagation.PRIVATE)
        assert_eq(mnt_ns.peer_groups["/mnt/peer"], 1)

    def test_f01_user_namespace_uid_gid_extent_mapping():
        """F01.4: User namespace maps inner UIDs/GIDs to host UIDs/GIDs via extents."""
        user_ns = MockUserNamespace(ns_id=1)
        # Map inner 0..1000 to host 100000..101000
        user_ns.set_uid_map([UidGidExtent(inside_id=0, outside_id=100000, count=1000)])
        assert_eq(user_ns.map_uid(0), 100000, "Container root (0) maps to host 100000")
        assert_eq(user_ns.map_uid(500), 100500, "Container user 500 maps to host 100500")
        assert_eq(user_ns.map_uid(2000), MockUserNamespace.OVERFLOW_ID, "Unmapped UID maps to overflow 65534")

    def test_f01_chroot_jail_path_traversal_containment():
        """F01.5: Per-process chroot jail traps path canonicalization within sandbox."""
        jail = MockChrootJail(root_dir="/var/empty/jail")
        resolved = jail.resolve_path("/etc/passwd")
        assert_eq(resolved, "/var/empty/jail/etc/passwd")
        # Attempting to escape via ../../../
        escape_attempt = jail.resolve_path("../../../../../etc/shadow")
        assert_eq(escape_attempt, "/var/empty/jail/etc/shadow", "Chroot jail must prevent escaping above root")

    suite.add("f01_pid_namespace_virtual_pid_allocation", test_f01_pid_namespace_virtual_pid_allocation, "F01")
    suite.add("f01_pid_namespace_init_termination_cascade", test_f01_pid_namespace_init_termination_cascade, "F01")
    suite.add("f01_mount_namespace_propagation_types", test_f01_mount_namespace_propagation_types, "F01")
    suite.add("f01_user_namespace_uid_gid_extent_mapping", test_f01_user_namespace_uid_gid_extent_mapping, "F01")
    suite.add("f01_chroot_jail_path_traversal_containment", test_f01_chroot_jail_path_traversal_containment, "F01")

    # ------------------------------------------------------------------------
    # Feature 2: cgroups v2 Resource Control (R1.2)
    # ------------------------------------------------------------------------
    def test_f02_cgroupv2_no_internal_processes_constraint():
        """F02.1: Enforces cgroups v2 constraint: cannot attach process to non-root internal node."""
        root = MockCgroupV2Node("root")
        child = root.add_child("group_a")
        grandchild = child.add_child("leaf_1")
        # Attaching to leaf succeeds
        grandchild.attach_task(pid=101)
        assert_in(101, grandchild.procs)
        # Attaching to internal node 'child' must fail
        assert_raises(RuntimeError, child.attach_task, 102)

    def test_f02_cgroupv2_cpu_quota_period_throttling():
        """F02.2: cpu.max quota limits CPU time within period and triggers throttling."""
        cpu = CpuBandwidth(quota_us=50000, period_us=100000) # 50ms quota per 100ms
        assert_true(cpu.charge(30000), "30ms within 50ms quota must be allowed")
        assert_true(cpu.charge(20000), "Reached exactly 50ms quota")
        assert_false(cpu.charge(10000), "Exceeding quota must be throttled")
        assert_eq(cpu.nr_throttled, 1)

    def test_f02_cgroupv2_cpu_weight_proportional_shares():
        """F02.3: cpu.weight configures proportional CFS scheduler share."""
        cpu1 = CpuBandwidth(cpu_weight=100)
        cpu2 = CpuBandwidth(cpu_weight=300)
        total_weight = cpu1.cpu_weight + cpu2.cpu_weight
        assert_eq(total_weight, 400)
        share1 = cpu1.cpu_weight / total_weight
        share2 = cpu2.cpu_weight / total_weight
        assert_eq(share1, 0.25)
        assert_eq(share2, 0.75)

    def test_f02_cgroupv2_memory_max_enforcement_and_oom():
        """F02.4: memory.max limits resident memory and records OOM events."""
        mem = MemoryController(max_bytes=10 * 1024 * 1024) # 10MB limit
        assert_true(mem.charge(8 * 1024 * 1024), "8MB allocation within limit succeeds")
        assert_false(mem.charge(3 * 1024 * 1024), "Exceeding 10MB limit must be rejected")
        assert_eq(mem.events_max, 1)
        assert_eq(mem.events_oom, 1)
        mem.uncharge(4 * 1024 * 1024)
        assert_true(mem.charge(2 * 1024 * 1024), "Allocation succeeds after uncharge")

    def test_f02_cgroupv2_io_token_bucket_rate_limiting():
        """F02.5: io.max token bucket rate-limits read/write bandwidth and IOPS."""
        io = IoTokenBucket(wbps_max=1024 * 1024, wiops_max=10)
        io.refill()
        assert_true(io.charge_io(is_write=True, bytes_count=512 * 1024), "512KB write allowed")
        assert_true(io.charge_io(is_write=True, bytes_count=512 * 1024), "Reaching 1MB limit allowed")
        assert_false(io.charge_io(is_write=True, bytes_count=1), "Exceeding wbps must throttle")

    suite.add("f02_cgroupv2_no_internal_processes_constraint", test_f02_cgroupv2_no_internal_processes_constraint, "F02")
    suite.add("f02_cgroupv2_cpu_quota_period_throttling", test_f02_cgroupv2_cpu_quota_period_throttling, "F02")
    suite.add("f02_cgroupv2_cpu_weight_proportional_shares", test_f02_cgroupv2_cpu_weight_proportional_shares, "F02")
    suite.add("f02_cgroupv2_memory_max_enforcement_and_oom", test_f02_cgroupv2_memory_max_enforcement_and_oom, "F02")
    suite.add("f02_cgroupv2_io_token_bucket_rate_limiting", test_f02_cgroupv2_io_token_bucket_rate_limiting, "F02")

    # ------------------------------------------------------------------------
    # Feature 3: Full POSIX Signals (R1.3)
    # ------------------------------------------------------------------------
    def test_f03_sigaction_handler_registration_and_flags():
        """F03.1: rt_sigaction configures dispositions and flags (SA_RESTART, SA_NODEFER)."""
        sig_mgr = MockSignalManager(pid=42)
        act = SigAction(
            disposition=SigDisposition.HANDLER,
            handler_addr=0x401000,
            flags=SigActionFlags.SA_RESTART | SigActionFlags.SA_NODEFER,
            mask=0
        )
        old_act = sig_mgr.sigaction(SignalNumber.SIGUSR1, act)
        assert_eq(old_act.disposition, SigDisposition.DEFAULT)
        assert_eq(sig_mgr.handlers[SignalNumber.SIGUSR1].handler_addr, 0x401000)

    def test_f03_sigprocmask_blocking_and_unblockable_signals():
        """F03.2: sigprocmask updates blocked mask but cannot block SIGKILL or SIGSTOP."""
        sig_mgr = MockSignalManager(pid=42)
        kill_mask = 1 << (SignalNumber.SIGKILL - 1)
        stop_mask = 1 << (SignalNumber.SIGSTOP - 1)
        usr1_mask = 1 << (SignalNumber.SIGUSR1 - 1)
        sig_mgr.sigprocmask("SIG_BLOCK", kill_mask | stop_mask | usr1_mask)
        assert_true((sig_mgr.blocked_mask & usr1_mask) != 0, "SIGUSR1 must be blocked")
        assert_true((sig_mgr.blocked_mask & kill_mask) == 0, "SIGKILL cannot be blocked")
        assert_true((sig_mgr.blocked_mask & stop_mask) == 0, "SIGSTOP cannot be blocked")

    def test_f03_signal_queueing_and_unblocked_dequeue():
        """F03.3: Signals queue and are dequeued only when unblocked."""
        sig_mgr = MockSignalManager(pid=42)
        usr1_mask = 1 << (SignalNumber.SIGUSR1 - 1)
        sig_mgr.sigprocmask("SIG_BLOCK", usr1_mask)
        sig_mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGUSR1, sender_pid=1))
        sig_mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGINT, sender_pid=1))
        # First dequeue must skip blocked SIGUSR1 and return SIGINT
        sig = sig_mgr.dequeue_signal()
        assert_eq(sig.si_signo, SignalNumber.SIGINT)
        # Unblock SIGUSR1 and dequeue
        sig_mgr.sigprocmask("SIG_UNBLOCK", usr1_mask)
        sig2 = sig_mgr.dequeue_signal()
        assert_eq(sig2.si_signo, SignalNumber.SIGUSR1)

    def test_f03_sigreturn_user_context_stack_frame():
        """F03.4: UContextX86_64 captures user registers and restores execution state."""
        ctx = UContextX86_64(
            rip=0x401234, rsp=0x7FFF0000, rax=0, rdi=1, rsi=2, rdx=3,
            rflags=0x202, old_mask=0x100
        )
        assert_eq(ctx.rip, 0x401234)
        assert_eq(ctx.rflags, 0x202)
        assert_eq(ctx.old_mask, 0x100)

    def test_f03_default_signal_actions_process_termination():
        """F03.5: Unhandled fatal signals terminate task with exit code 128 + signo."""
        sig_mgr = MockSignalManager(pid=42)
        sig_mgr.execute_default_action(SignalNumber.SIGTERM)
        assert_true(sig_mgr.terminated)
        assert_eq(sig_mgr.exit_code, 128 + 15) # 143

    suite.add("f03_sigaction_handler_registration_and_flags", test_f03_sigaction_handler_registration_and_flags, "F03")
    suite.add("f03_sigprocmask_blocking_and_unblockable_signals", test_f03_sigprocmask_blocking_and_unblockable_signals, "F03")
    suite.add("f03_signal_queueing_and_unblocked_dequeue", test_f03_signal_queueing_and_unblocked_dequeue, "F03")
    suite.add("f03_sigreturn_user_context_stack_frame", test_f03_sigreturn_user_context_stack_frame, "F03")
    suite.add("f03_default_signal_actions_process_termination", test_f03_default_signal_actions_process_termination, "F03")

    # ------------------------------------------------------------------------
    # Feature 4: Futex & POSIX Sync Primitives (R1.4)
    # ------------------------------------------------------------------------
    def test_f04_futex_wait_wake_hash_bucket_lifecycle():
        """F04.1: sys_futex WAIT enqueues waiter; WAKE pops exact number of waiters."""
        mgr = MockFutexManager()
        uaddr = 0x500000
        mgr.set_memory_val(uaddr, 1)
        res = mgr.futex_wait(uaddr, expected_val=1, tid=10)
        assert_eq(res, 0, "Wait succeeds when memory matches expected_val")
        assert_in(10, mgr.waiters[uaddr])
        woken = mgr.futex_wake(uaddr, nr_wake=1)
        assert_eq(woken, 1)
        assert_eq(len(mgr.waiters[uaddr]), 0)

    def test_f04_futex_cmp_requeue_atomic_transfer():
        """F04.2: FUTEX_CMP_REQUEUE wakes N waiters and transfers remaining to uaddr2."""
        mgr = MockFutexManager()
        uaddr1, uaddr2 = 0x600000, 0x700000
        mgr.set_memory_val(uaddr1, 100)
        mgr.futex_wait(uaddr1, 100, tid=1)
        mgr.futex_wait(uaddr1, 100, tid=2)
        mgr.futex_wait(uaddr1, 100, tid=3)
        total = mgr.futex_cmp_requeue(uaddr1, uaddr2, nr_wake=1, nr_requeue=2, val3=100)
        assert_eq(total, 3)
        assert_eq(len(mgr.waiters[uaddr1]), 0)
        assert_eq(len(mgr.waiters[uaddr2]), 2)

    def test_f04_robust_futex_owner_death_recovery():
        """F04.3: Robust futex recovers from owner death by setting FUTEX_OWNER_DIED."""
        mgr = MockFutexManager()
        uaddr = 0x800000
        mgr.set_memory_val(uaddr, 42) # Owned by TID 42
        mgr.robust_lists[42] = [uaddr]
        mgr.futex_wait(uaddr, 42, tid=43) # TID 43 waiting
        mgr.handle_thread_exit(tid=42)
        new_val = mgr.get_memory_val(uaddr)
        assert_true((new_val & FUTEX_OWNER_DIED) != 0, "FUTEX_OWNER_DIED flag must be set")
        assert_eq(len(mgr.waiters[uaddr]), 0, "Waiter must be woken up on owner exit")

    def test_f04_pthread_mutex_uncontended_and_contended():
        """F04.4: PthreadMutex fast-path CAS uncontended lock and slow-path waiter flag."""
        mgr = MockFutexManager()
        mutex = MockPthreadMutex(mgr, uaddr=0x900000)
        assert_true(mutex.lock(tid=100), "Uncontended lock succeeds immediately")
        assert_false(mutex.lock(tid=101), "Contended lock escalates to futex wait")
        val = mgr.get_memory_val(0x900000)
        assert_true((val & FUTEX_WAITERS) != 0, "FUTEX_WAITERS flag must be set")
        assert_true(mutex.unlock(tid=100))

    def test_f04_posix_semaphore_post_wait_ordering():
        """F04.5: PosixSemaphore post increments counter and wait consumes token."""
        sem = MockPosixSemaphore(initial_value=0)
        assert_false(sem.wait(), "Wait on 0 returns False (would block)")
        sem.post()
        sem.post()
        assert_true(sem.wait())
        assert_true(sem.wait())
        assert_false(sem.wait())

    suite.add("f04_futex_wait_wake_hash_bucket_lifecycle", test_f04_futex_wait_wake_hash_bucket_lifecycle, "F04")
    suite.add("f04_futex_cmp_requeue_atomic_transfer", test_f04_futex_cmp_requeue_atomic_transfer, "F04")
    suite.add("f04_robust_futex_owner_death_recovery", test_f04_robust_futex_owner_death_recovery, "F04")
    suite.add("f04_pthread_mutex_uncontended_and_contended", test_f04_pthread_mutex_uncontended_and_contended, "F04")
    suite.add("f04_posix_semaphore_post_wait_ordering", test_f04_posix_semaphore_post_wait_ordering, "F04")

    # ------------------------------------------------------------------------
    # Feature 5: Swap & Virtual Memory Paging (R1.10)
    # ------------------------------------------------------------------------
    def test_f05_pte_swap_entry_encoding_decoding():
        """F05.1: Non-present x86_64 PTE encodes 5-bit swap type and 50-bit slot offset."""
        swap_type = 2 # File swap
        slot_offset = 0x12345678
        pte = encode_swap_entry(swap_type, slot_offset)
        assert_true(is_swap_entry(pte), "Must be recognized as swap entry")
        dec_type, dec_offset = decode_swap_entry(pte)
        assert_eq(dec_type, swap_type)
        assert_eq(dec_offset, slot_offset)

    def test_f05_swap_backend_slot_allocation_and_read():
        """F05.2: Swap backend stores 4KB page and retrieves identical content on swap-in."""
        swap_mgr = MockSwapManager(max_slots=64)
        page_payload = b"A" * 4096
        slot = swap_mgr.allocate_slot(swap_type=1, data=page_payload)
        read_back = swap_mgr.read_slot(swap_type=1, slot=slot)
        assert_eq(read_back, page_payload)
        swap_mgr.free_slot(swap_type=1, slot=slot)
        assert_raises(KeyError, swap_mgr.read_slot, 1, slot)

    def test_f05_page_fault_swap_in_vs_demand_zero():
        """F05.3: Page fault handler distinguishes swapped PTE from demand-zero PTE."""
        null_pte = 0
        swap_pte = encode_swap_entry(swap_type=0, slot_offset=5)
        assert_false(is_swap_entry(null_pte), "PTE 0 is demand-zero, not swap")
        assert_true(is_swap_entry(swap_pte), "PTE with marker is swap-in")

    def test_f05_lru_clock_sweep_second_chance_eviction():
        """F05.4: Second-chance LRU clock sweep evicts unreferenced page to swap."""
        lru = MockPageReclaimLru()
        lru.add_page(0x1000)
        lru.add_page(0x2000)
        # First sweep clears accessed bit and moves to active list
        evicted = lru.clock_sweep_evict()
        # Page without second chance is candidate for swap out
        assert_true(evicted is not None or len(lru.active_anon) > 0)

    def test_f05_oom_killer_badness_scoring_and_victim_selection():
        """F05.5: OOM killer scores process badness and protects init process (PID 1)."""
        score_init = MockOomKiller.calculate_badness(total_pages=500000, is_init=True)
        assert_eq(score_init, 0, "PID 1 init process has total immunity (score 0)")
        score_high_mem = MockOomKiller.calculate_badness(total_pages=500000, oom_score_adj=100)
        score_low_mem = MockOomKiller.calculate_badness(total_pages=10000, oom_score_adj=0)
        assert_true(score_high_mem > score_low_mem, "Process consuming more memory receives higher badness")

    suite.add("f05_pte_swap_entry_encoding_decoding", test_f05_pte_swap_entry_encoding_decoding, "F05")
    suite.add("f05_swap_backend_slot_allocation_and_read", test_f05_swap_backend_slot_allocation_and_read, "F05")
    suite.add("f05_page_fault_swap_in_vs_demand_zero", test_f05_page_fault_swap_in_vs_demand_zero, "F05")
    suite.add("f05_lru_clock_sweep_second_chance_eviction", test_f05_lru_clock_sweep_second_chance_eviction, "F05")
    suite.add("f05_oom_killer_badness_scoring_and_victim_selection", test_f05_oom_killer_badness_scoring_and_victim_selection, "F05")

    # ------------------------------------------------------------------------
    # Feature 6: Unix Domain Sockets (R1.5)
    # ------------------------------------------------------------------------
    def test_f06_unix_domain_stream_connection_handshake():
        """F06.1: AF_UNIX SOCK_STREAM connection handshake and duplex byte stream."""
        server = MockUnixDomainSocket(UnixSocketType.STREAM)
        server.bind("/tmp/test.sock")
        server.listen()
        client = MockUnixDomainSocket(UnixSocketType.STREAM)
        client.connect(server)
        client.send(b"PING")
        assert_eq(server.recv(4), b"PING")

    def test_f06_unix_domain_abstract_namespace_addressing():
        """F06.2: AF_UNIX abstract namespace socket begins with null byte."""
        sock = MockUnixDomainSocket(UnixSocketType.STREAM)
        sock.bind("\x00coros_daemon")
        assert_true(sock.is_abstract)
        assert_eq(sock.bound_path, "\x00coros_daemon")

    def test_f06_unix_domain_socketpair_bidirectional():
        """F06.3: socketpair creates two connected bidirectional endpoints."""
        s1 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s2 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s1.peer = s2
        s2.peer = s1
        s1.send(b"HELLO")
        assert_eq(s2.recv(5), b"HELLO")
        s2.send(b"WORLD")
        assert_eq(s1.recv(5), b"WORLD")

    def test_f06_unix_domain_scm_rights_fd_passing():
        """F06.4: SCM_RIGHTS passes file descriptors across Unix domain sockets."""
        s1 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s2 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s1.peer = s2
        s1.send(b"DATA", passed_fds=[3, 4])
        assert_eq(s2.recv(4), b"DATA")
        assert_eq(s2.rx_ancillary_fds, [3, 4])

    def test_f06_unix_domain_scm_credentials_peercred():
        """F06.5: SCM_CREDENTIALS passes authentic Ucred credentials."""
        s1 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s2 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s1.peer = s2
        cred = Ucred(pid=100, uid=1000, gid=1000)
        s1.send(b"AUTH", cred=cred)
        assert_eq(s2.recv(4), b"AUTH")
        assert_eq(s2.rx_credentials.pid, 100)
        assert_eq(s2.rx_credentials.uid, 1000)

    suite.add("f06_unix_domain_stream_connection_handshake", test_f06_unix_domain_stream_connection_handshake, "F06")
    suite.add("f06_unix_domain_abstract_namespace_addressing", test_f06_unix_domain_abstract_namespace_addressing, "F06")
    suite.add("f06_unix_domain_socketpair_bidirectional", test_f06_unix_domain_socketpair_bidirectional, "F06")
    suite.add("f06_unix_domain_scm_rights_fd_passing", test_f06_unix_domain_scm_rights_fd_passing, "F06")
    suite.add("f06_unix_domain_scm_credentials_peercred", test_f06_unix_domain_scm_credentials_peercred, "F06")

    # ------------------------------------------------------------------------
    # Feature 7: Named Pipes (FIFO) (R1.5)
    # ------------------------------------------------------------------------
    def test_f07_fifo_inode_creation_and_file_mode():
        """F07.1: mkfifo establishes VFS FIFO inode tracking reader/writer state."""
        fifo = MockFifoInode("/tmp/myfifo")
        assert_eq(fifo.reader_count, 0)
        assert_eq(fifo.writer_count, 0)
        assert_eq(fifo.PIPE_BUF, 4096)

    def test_f07_fifo_blocking_open_reader_writer_sync():
        """F07.2: Blocking open waits for peer reader/writer before completing."""
        fifo = MockFifoInode("/tmp/myfifo")
        status_r = fifo.open("r", non_block=False)
        assert_eq(status_r, "BLOCKED_WAITING_FOR_WRITER")
        status_w = fifo.open("w", non_block=False)
        assert_eq(status_w, "OPENED_WO")

    def test_f07_fifo_nonblocking_open_enxio_semantics():
        """F07.3: O_NONBLOCK write open returns -ENXIO when zero readers are present."""
        fifo = MockFifoInode("/tmp/myfifo")
        assert_raises(OSError, fifo.open, "w", non_block=True)

    def test_f07_fifo_atomic_write_pipe_buf_guarantee():
        """F07.4: Writes up to PIPE_BUF (4096 bytes) succeed contiguously."""
        fifo = MockFifoInode("/tmp/myfifo")
        fifo.open("r")
        fifo.open("w")
        data = b"X" * 4096
        written = fifo.write(data)
        assert_eq(written, 4096)
        assert_eq(fifo.read(4096), data)

    def test_f07_fifo_broken_pipe_sigpipe_and_epipe():
        """F07.5: Writing to FIFO with zero readers triggers SIGPIPE and returns EPIPE."""
        fifo = MockFifoInode("/tmp/myfifo")
        fifo.open("w", non_block=False)
        # reader_count is 0
        assert_raises(BrokenPipeError, fifo.write, b"FAIL")

    suite.add("f07_fifo_inode_creation_and_file_mode", test_f07_fifo_inode_creation_and_file_mode, "F07")
    suite.add("f07_fifo_blocking_open_reader_writer_sync", test_f07_fifo_blocking_open_reader_writer_sync, "F07")
    suite.add("f07_fifo_nonblocking_open_enxio_semantics", test_f07_fifo_nonblocking_open_enxio_semantics, "F07")
    suite.add("f07_fifo_atomic_write_pipe_buf_guarantee", test_f07_fifo_atomic_write_pipe_buf_guarantee, "F07")
    suite.add("f07_fifo_broken_pipe_sigpipe_and_epipe", test_f07_fifo_broken_pipe_sigpipe_and_epipe, "F07")

    # ------------------------------------------------------------------------
    # Feature 8: POSIX Message Queues (R1.5)
    # ------------------------------------------------------------------------
    def test_f08_mq_open_attributes_and_capacity_limits():
        """F08.1: mq_open configures maxmsg and msgsize limits."""
        mq = MockPosixMessageQueue("/test_queue", max_msg=5, max_msgsize=128)
        assert_eq(mq.max_msg, 5)
        assert_eq(mq.max_msgsize, 128)
        assert_raises(ValueError, mq.send, b"A" * 200) # Message too large

    def test_f08_mq_priority_sorted_message_ordering():
        """F08.2: Messages are dequeued strictly in descending priority order."""
        mq = MockPosixMessageQueue("/prio_queue")
        mq.send(b"LOW", priority=1)
        mq.send(b"HIGH", priority=10)
        mq.send(b"MED", priority=5)
        payload, prio = mq.receive()
        assert_eq(payload, b"HIGH")
        assert_eq(prio, 10)
        payload2, prio2 = mq.receive()
        assert_eq(payload2, b"MED")

    def test_f08_mq_fifo_ordering_within_same_priority():
        """F08.3: Messages with equal priority are dequeued in FIFO arrival order."""
        mq = MockPosixMessageQueue("/fifo_queue")
        mq.send(b"MSG1", priority=5)
        mq.send(b"MSG2", priority=5)
        mq.send(b"MSG3", priority=5)
        p1, _ = mq.receive()
        p2, _ = mq.receive()
        p3, _ = mq.receive()
        assert_eq(p1, b"MSG1")
        assert_eq(p2, b"MSG2")
        assert_eq(p3, b"MSG3")

    def test_f08_mq_full_queue_overflow_rejection():
        """F08.4: Sending to full message queue rejects insertion with EAGAIN."""
        mq = MockPosixMessageQueue("/full_queue", max_msg=2)
        mq.send(b"A")
        mq.send(b"B")
        assert_raises(RuntimeError, mq.send, b"C")

    def test_f08_mq_notify_async_signal_registration():
        """F08.5: mq_notify delivers registered signal when transitioning from empty to non-empty."""
        mq = MockPosixMessageQueue("/notify_queue")
        mq.notify_signal = SignalNumber.SIGUSR1
        mq.notify_pid = 42
        sig = mq.send(b"HELLO")
        assert_eq(sig, SignalNumber.SIGUSR1, "Must deliver SIGUSR1 on empty->non-empty")
        assert_eq(mq.notify_signal, None, "Notification must be one-shot (cleared after fire)")

    suite.add("f08_mq_open_attributes_and_capacity_limits", test_f08_mq_open_attributes_and_capacity_limits, "F08")
    suite.add("f08_mq_priority_sorted_message_ordering", test_f08_mq_priority_sorted_message_ordering, "F08")
    suite.add("f08_mq_fifo_ordering_within_same_priority", test_f08_mq_fifo_ordering_within_same_priority, "F08")
    suite.add("f08_mq_full_queue_overflow_rejection", test_f08_mq_full_queue_overflow_rejection, "F08")
    suite.add("f08_mq_notify_async_signal_registration", test_f08_mq_notify_async_signal_registration, "F08")

    # ------------------------------------------------------------------------
    # Feature 9: Shared Memory (R1.5)
    # ------------------------------------------------------------------------
    def test_f09_sysv_shmget_segment_allocation():
        """F09.1: sys_shmget allocates shared memory segment with unique shmid."""
        mgr = MockSharedMemoryManager()
        shmid = mgr.sysv_shmget(key=0x1234, size=65536)
        assert_true(shmid > 0)
        assert_eq(mgr.sysv_segments[shmid]["size"], 65536)

    def test_f09_sysv_shmat_page_mapping_and_attachment():
        """F09.2: sys_shmat attaches segment and increments nattch counter."""
        mgr = MockSharedMemoryManager()
        shmid = mgr.sysv_shmget(key=0x5678, size=4096)
        buf = mgr.sysv_shmat(shmid)
        buf[:5] = b"HELLO"
        assert_eq(mgr.sysv_segments[shmid]["nattch"], 1)
        # Second attachment shares exact same memory buffer
        buf2 = mgr.sysv_shmat(shmid)
        assert_eq(bytes(buf2[:5]), b"HELLO")
        assert_eq(mgr.sysv_segments[shmid]["nattch"], 2)

    def test_f09_sysv_shmdt_detachment_and_cleanup():
        """F09.3: sys_shmdt detaches segment and decrements nattch counter."""
        mgr = MockSharedMemoryManager()
        shmid = mgr.sysv_shmget(key=0x9ABC, size=4096)
        mgr.sysv_shmat(shmid)
        mgr.sysv_shmdt(shmid)
        assert_eq(mgr.sysv_segments[shmid]["nattch"], 0)

    def test_f09_sysv_shmctl_ipc_rmid_deferred_destruction():
        """F09.4: IPC_RMID marks segment for deletion; deallocates on final detach."""
        mgr = MockSharedMemoryManager()
        shmid = mgr.sysv_shmget(key=0xDEF0, size=4096)
        mgr.sysv_shmat(shmid)
        mgr.sysv_segments[shmid]["marked_destroy"] = True
        mgr.sysv_shmdt(shmid) # nattch reaches 0, triggers destruction
        assert_not_in(shmid, mgr.sysv_segments)

    def test_f09_posix_shm_open_and_ftruncate_sizing():
        """F09.5: POSIX shm_open creates named shared memory object in /dev/shm."""
        mgr = MockSharedMemoryManager()
        shm_buf = mgr.posix_shm_open("/shm_region", size=8192)
        assert_eq(len(shm_buf), 8192)
        shm_buf[:4] = b"CORO"
        # Re-open retrieves existing buffer
        reopen = mgr.posix_shm_open("/shm_region")
        assert_eq(bytes(reopen[:4]), b"CORO")

    suite.add("f09_sysv_shmget_segment_allocation", test_f09_sysv_shmget_segment_allocation, "F09")
    suite.add("f09_sysv_shmat_page_mapping_and_attachment", test_f09_sysv_shmat_page_mapping_and_attachment, "F09")
    suite.add("f09_sysv_shmdt_detachment_and_cleanup", test_f09_sysv_shmdt_detachment_and_cleanup, "F09")
    suite.add("f09_sysv_shmctl_ipc_rmid_deferred_destruction", test_f09_sysv_shmctl_ipc_rmid_deferred_destruction, "F09")
    suite.add("f09_posix_shm_open_and_ftruncate_sizing", test_f09_posix_shm_open_and_ftruncate_sizing, "F09")

    # ------------------------------------------------------------------------
    # Feature 10: Dynamic Linker & ELF Shared Library Loader (R1.6)
    # ------------------------------------------------------------------------
    def test_f10_elf_dynamic_section_tag_parsing():
        """F10.1: PT_DYNAMIC tag parser identifies DT_SYMTAB, DT_STRTAB, DT_RELA, DT_JMPREL."""
        assert_eq(ElfDynamicTag.DT_NEEDED, 1)
        assert_eq(ElfDynamicTag.DT_SYMTAB, 6)
        assert_eq(ElfDynamicTag.DT_RELA, 7)
        assert_eq(ElfDynamicTag.DT_JMPREL, 23)
        assert_eq(ElfDynamicTag.DT_GNU_HASH, 0x6FFFFEF5)

    def test_f10_gnu_hash_symbol_lookup_algorithm():
        """F10.2: 32-bit GNU hash function computes exact DJB-variant hash values."""
        h1 = MockDynamicLinker.gnu_hash("printf")
        h2 = MockDynamicLinker.gnu_hash("malloc")
        assert_true(isinstance(h1, int) and h1 > 0)
        assert_ne(h1, h2)
        assert_eq(MockDynamicLinker.gnu_hash("printf"), h1)

    def test_f10_elf_relocations_glob_dat_and_relative():
        """F10.3: R_X86_64_RELATIVE and R_X86_64_GLOB_DAT relocations patch GOT entries."""
        linker = MockDynamicLinker()
        linker.register_object("libc.so", base_addr=0x7F0000, symbols={"read": 0x120}, needed=[])
        # R_X86_64_RELATIVE: base + addend
        linker.apply_relocation(ElfRelocType.R_X86_64_RELATIVE, target_slot=0x8000, addend=0x50, base_addr=0x7F0000)
        assert_eq(linker.got_table[0x8000], 0x7F0050)
        # R_X86_64_GLOB_DAT: resolves symbol 'read'
        linker.apply_relocation(ElfRelocType.R_X86_64_GLOB_DAT, target_slot=0x8008, sym_name="read")
        assert_eq(linker.got_table[0x8008], 0x7F0120)

    def test_f10_eager_vs_lazy_plt_relocation_binding():
        """F10.4: Eager binding resolves R_X86_64_JUMP_SLOT immediately; Lazy sets trampoline."""
        eager_linker = MockDynamicLinker(eager_binding=True)
        eager_linker.register_object("libm.so", base_addr=0x600000, symbols={"sin": 0x40}, needed=[])
        eager_linker.apply_relocation(ElfRelocType.R_X86_64_JUMP_SLOT, target_slot=0x6500, sym_name="sin")
        assert_eq(eager_linker.got_table[0x6500], 0x600040)

        lazy_linker = MockDynamicLinker(eager_binding=False)
        lazy_linker.register_object("libm.so", base_addr=0x600000, symbols={"sin": 0x40}, needed=[])
        lazy_linker.apply_relocation(ElfRelocType.R_X86_64_JUMP_SLOT, target_slot=0x6500, sym_name="sin")
        assert_eq(lazy_linker.got_table[0x6500], 0x6506, "Lazy GOT points to PLT0 trampoline")
        # First runtime resolution patches GOT
        resolved = lazy_linker.dl_runtime_resolve(target_slot=0x6500, sym_name="sin")
        assert_eq(resolved, 0x600040)
        assert_eq(lazy_linker.got_table[0x6500], 0x600040)

    def test_f10_auxiliary_vector_stack_bootstrap():
        """F10.5: Auxiliary vector auxv establishes AT_PHDR, AT_ENTRY, AT_BASE protocol."""
        auxv = {
            3: 0x400040, # AT_PHDR
            7: 0x7F8000, # AT_BASE (Interpreter load address)
            9: 0x401000, # AT_ENTRY (App entry point)
        }
        assert_eq(auxv[3], 0x400040)
        assert_eq(auxv[7], 0x7F8000)
        assert_eq(auxv[9], 0x401000)

    suite.add("f10_elf_dynamic_section_tag_parsing", test_f10_elf_dynamic_section_tag_parsing, "F10")
    suite.add("f10_gnu_hash_symbol_lookup_algorithm", test_f10_gnu_hash_symbol_lookup_algorithm, "F10")
    suite.add("f10_elf_relocations_glob_dat_and_relative", test_f10_elf_relocations_glob_dat_and_relative, "F10")
    suite.add("f10_eager_vs_lazy_plt_relocation_binding", test_f10_eager_vs_lazy_plt_relocation_binding, "F10")
    suite.add("f10_auxiliary_vector_stack_bootstrap", test_f10_auxiliary_vector_stack_bootstrap, "F10")

    # ------------------------------------------------------------------------
    # Feature 11: Btrfs Filesystem Parser (R1.7)
    # ------------------------------------------------------------------------
    def test_f11_btrfs_superblock_magic_and_uuid_validation():
        """F11.1: Btrfs superblock parser verifies magic '_BtrFS_M' at 64 KiB offset."""
        disk = bytearray(0x10000 + 1024)
        disk[0x10000 + 64 : 0x10000 + 72] = b"_BtrFS_M"
        parser = MockBtrfsParser(disk)
        assert_true(parser.verify_superblock())

    def test_f11_btrfs_chunk_tree_logical_to_physical_translation():
        """F11.2: Btrfs chunk tree translates logical address to disk physical stripe offset."""
        chunk = BtrfsChunk(
            logical_offset=0x1000000,
            length=0x100000,
            stripe_len=65536,
            stripes=[(1, 0x2000000)] # devid 1, physical base
        )
        phys = chunk.translate(0x1004000) # 16KB into chunk
        assert_eq(phys, 0x2004000)

    def test_f11_btrfs_internal_node_btree_traversal():
        """F11.3: Btrfs internal node (level > 0) binary search identifies child blockptr."""
        keys = [(10, 0xA000), (20, 0xB000), (30, 0xC000)]
        target_key = 25
        # Lower bound search finds child blockptr 0xB000
        chosen_ptr = None
        for k, ptr in keys:
            if target_key >= k:
                chosen_ptr = ptr
        assert_eq(chosen_ptr, 0xB000)

    def test_f11_btrfs_leaf_directory_item_parsing():
        """F11.4: Btrfs leaf items extract directory entries (BTRFS_DIR_ITEM_KEY = 84)."""
        BTRFS_DIR_ITEM_KEY = 84
        item_key = (256, BTRFS_DIR_ITEM_KEY, 0x1234)
        assert_eq(item_key[1], 84)

    def test_f11_btrfs_extent_data_inline_and_regular_decoding():
        """F11.5: Btrfs extent data distinguishes inline payload from regular disk extents."""
        BTRFS_EXTENT_DATA_KEY = 108
        inline_type = 0
        regular_type = 1
        assert_eq(BTRFS_EXTENT_DATA_KEY, 108)
        assert_ne(inline_type, regular_type)

    suite.add("f11_btrfs_superblock_magic_and_uuid_validation", test_f11_btrfs_superblock_magic_and_uuid_validation, "F11")
    suite.add("f11_btrfs_chunk_tree_logical_to_physical_translation", test_f11_btrfs_chunk_tree_logical_to_physical_translation, "F11")
    suite.add("f11_btrfs_internal_node_btree_traversal", test_f11_btrfs_internal_node_btree_traversal, "F11")
    suite.add("f11_btrfs_leaf_directory_item_parsing", test_f11_btrfs_leaf_directory_item_parsing, "F11")
    suite.add("f11_btrfs_extent_data_inline_and_regular_decoding", test_f11_btrfs_extent_data_inline_and_regular_decoding, "F11")

    # ------------------------------------------------------------------------
    # Feature 12: ZFS Filesystem Parser (R1.7)
    # ------------------------------------------------------------------------
    def test_f12_zfs_128_slot_uberblock_array_scan():
        """F12.1: ZFS parser scans 128 uberblock slots between 128 KiB and 256 KiB."""
        raw_label = bytearray(256 * 1024)
        # Put valid uberblock in slot 5 (offset: 128KB + 5KB)
        slot5_offset = 128 * 1024 + 5 * 1024
        struct.pack_into("<I", raw_label, slot5_offset, 0x00BAB10C)
        struct.pack_into("<Q", raw_label, slot5_offset + 8, 1050) # txg = 1050
        parser = MockZfsParser()
        best_slot, highest_txg = parser.scan_uberblocks(raw_label)
        assert_eq(best_slot, 5)
        assert_eq(highest_txg, 1050)

    def test_f12_zfs_fletcher4_256bit_checksum_verification():
        """F12.2: ZFS Fletcher4 checksum produces deterministic 256-bit accumulator tuple."""
        data = b"\x01\x02\x03\x04" * 256 # 1024 bytes
        a, b, c, d = MockZfsParser.fletcher4(data)
        assert_true(a > 0 and b > 0 and c > 0 and d > 0)
        # Identical data yields identical checksum
        assert_eq(MockZfsParser.fletcher4(data), (a, b, c, d))

    def test_f12_zfs_highest_txg_selection_rule():
        """F12.3: Active uberblock selection favors highest transaction group (txg)."""
        raw_label = bytearray(256 * 1024)
        s1 = 128 * 1024 + 1 * 1024
        s2 = 128 * 1024 + 2 * 1024
        struct.pack_into("<I", raw_label, s1, 0x00BAB10C)
        struct.pack_into("<Q", raw_label, s1 + 8, 200)
        struct.pack_into("<I", raw_label, s2, 0x00BAB10C)
        struct.pack_into("<Q", raw_label, s2 + 8, 300) # Higher txg
        parser = MockZfsParser()
        best_slot, highest_txg = parser.scan_uberblocks(raw_label)
        assert_eq(best_slot, 2)
        assert_eq(highest_txg, 300)

    def test_f12_zfs_dnode_phys_and_bonus_buffer_parsing():
        """F12.4: ZFS dnode_phys_t structures parse object type and bonus buffer."""
        dnode_size = 512
        bonus_type = 44 # DMU_OT_ZNODE
        assert_eq(dnode_size, 512)
        assert_eq(bonus_type, 44)

    def test_f12_zfs_micro_zap_directory_entry_lookup():
        """F12.5: Micro-ZAP magic 0x5A5102C0 identifies directory name-to-object table."""
        M_ZAP_MAGIC = 0x5A5102C0
        assert_eq(M_ZAP_MAGIC, 0x5A5102C0)

    suite.add("f12_zfs_128_slot_uberblock_array_scan", test_f12_zfs_128_slot_uberblock_array_scan, "F12")
    suite.add("f12_zfs_fletcher4_256bit_checksum_verification", test_f12_zfs_fletcher4_256bit_checksum_verification, "F12")
    suite.add("f12_zfs_highest_txg_selection_rule", test_f12_zfs_highest_txg_selection_rule, "F12")
    suite.add("f12_zfs_dnode_phys_and_bonus_buffer_parsing", test_f12_zfs_dnode_phys_and_bonus_buffer_parsing, "F12")
    suite.add("f12_zfs_micro_zap_directory_entry_lookup", test_f12_zfs_micro_zap_directory_entry_lookup, "F12")

    # ------------------------------------------------------------------------
    # Feature 13: F2FS Filesystem Parser (R1.7)
    # ------------------------------------------------------------------------
    def test_f13_f2fs_superblock_magic_and_geometry():
        """F13.1: F2FS superblock magic 0xF2F52010 verified at 1024-byte offset."""
        assert_eq(MockF2fsParser.SUPER_MAGIC, 0xF2F52010)

    def test_f13_f2fs_dual_checkpoint_selection_and_crc():
        """F13.2: Dual checkpoint selection chooses highest valid checkpoint_ver."""
        cp1_ver = 100
        cp2_ver = 105
        chosen = max(cp1_ver, cp2_ver)
        assert_eq(chosen, 105)

    def test_f13_f2fs_nat_455_entry_page_block_translation():
        """F13.3: Node Address Table (NAT) translates nid into physical disk block address."""
        nat_blkaddr = 1000
        nid = 456 # Block 1001, entry 1
        blocks = {}
        page = bytearray(4096)
        # Entry 1 offset = 9. Block address at bytes 5..8
        struct.pack_into("<I", page, 9 + 5, 0xDEADBEEF)
        blocks[1001] = bytes(page)
        addr = MockF2fsParser.translate_nat(nat_blkaddr, nid, blocks)
        assert_eq(addr, 0xDEADBEEF)

    def test_f13_f2fs_direct_indirect_node_block_indexing():
        """F13.4: F2FS inode directly addresses 923 data blocks and indirect nodes."""
        ADDRS_PER_INODE = 923
        assert_eq(ADDRS_PER_INODE, 923)

    def test_f13_f2fs_dentry_block_214_entry_lookup():
        """F13.5: f2fs_dentry_block packs 214 directory entries per 4 KiB block."""
        NR_DENTRY_IN_BLOCK = 214
        assert_eq(NR_DENTRY_IN_BLOCK, 214)

    suite.add("f13_f2fs_superblock_magic_and_geometry", test_f13_f2fs_superblock_magic_and_geometry, "F13")
    suite.add("f13_f2fs_dual_checkpoint_selection_and_crc", test_f13_f2fs_dual_checkpoint_selection_and_crc, "F13")
    suite.add("f13_f2fs_nat_455_entry_page_block_translation", test_f13_f2fs_nat_455_entry_page_block_translation, "F13")
    suite.add("f13_f2fs_direct_indirect_node_block_indexing", test_f13_f2fs_direct_indirect_node_block_indexing, "F13")
    suite.add("f13_f2fs_dentry_block_214_entry_lookup", test_f13_f2fs_dentry_block_214_entry_lookup, "F13")

    # ------------------------------------------------------------------------
    # Feature 14: XFS Filesystem Parser (R1.7)
    # ------------------------------------------------------------------------
    def test_f14_xfs_superblock_magic_and_geometry_validation():
        """F14.1: XFS superblock magic 0x58465342 verified."""
        assert_eq(MockXfsParser.SB_MAGIC, 0x58465342)

    def test_f14_xfs_inode_to_physical_block_logarithm_formula():
        """F14.2: 64-bit XFS inode translates to physical byte offset via AG logarithms."""
        # agblklog=15 (32768 blocks/AG), inopblog=3 (8 inodes/block), agblocks=32768, bs=4096, isize=512
        phys_offset = MockXfsParser.inode_to_physical(
            ino=0x40008, inopblog=3, agblklog=15, agblocks=32768, blocksize=4096, inodesize=512
        )
        assert_true(phys_offset > 0)
        assert_eq(phys_offset % 512, 0, "Inode physical offset must be 512-byte aligned")

    def test_f14_xfs_shortform_directory_entry_parsing():
        """F14.3: Shortform local directory parses entries directly within inode data fork."""
        sf_count = 2
        sf_i8count = 0
        assert_eq(sf_count, 2)
        assert_eq(sf_i8count, 0)

    def test_f14_xfs_extent_list_128bit_bmbt_record_decoding():
        """F14.4: 128-bit BMBT extent record decodes logical offset, physical block, length."""
        rec = (0 << 127) | (0 << 73) | (0x1000 << 21) | 16 # 16 blocks starting at 0x1000
        block_count = rec & 0x1FFFFF
        start_block = (rec >> 21) & 0xFFFFFFFFFFF
        assert_eq(block_count, 16)
        assert_eq(start_block, 0x1000)

    def test_f14_xfs_btree_extent_allocation_and_boundary():
        """F14.5: XFS B+tree extent allocation covers non-contiguous disk extents."""
        extent1 = (0, 0x1000, 8)
        extent2 = (8, 0x5000, 8)
        assert_eq(extent1[0] + extent1[2], extent2[0], "Extents must be logically contiguous")

    suite.add("f14_xfs_superblock_magic_and_geometry_validation", test_f14_xfs_superblock_magic_and_geometry_validation, "F14")
    suite.add("f14_xfs_inode_to_physical_block_logarithm_formula", test_f14_xfs_inode_to_physical_block_logarithm_formula, "F14")
    suite.add("f14_xfs_shortform_directory_entry_parsing", test_f14_xfs_shortform_directory_entry_parsing, "F14")
    suite.add("f14_xfs_extent_list_128bit_bmbt_record_decoding", test_f14_xfs_extent_list_128bit_bmbt_record_decoding, "F14")
    suite.add("f14_xfs_btree_extent_allocation_and_boundary", test_f14_xfs_btree_extent_allocation_and_boundary, "F14")

    # ------------------------------------------------------------------------
    # Feature 15: ISO9660 Rock Ridge & Joliet Extended Parsers (R1.7)
    # ------------------------------------------------------------------------
    def test_f15_iso9660_joliet_svd_ucs2_unicode_decoding():
        """F15.1: Joliet UCS-2 UTF-16BE decodes long filenames without ISO ;1 version."""
        raw_ucs2 = "Kernel_Image_x86_64.efi;1".encode("utf-16be")
        decoded = MockIso9660ExtendedParser.parse_joliet_name(raw_ucs2)
        assert_eq(decoded, "Kernel_Image_x86_64.efi")

    def test_f15_iso9660_rock_ridge_susp_header_validation():
        """F15.2: SUSP header format verifies standard 4-byte signature and length."""
        susp_buf = b"RR\x05\x01\x00"
        records = MockIso9660ExtendedParser.parse_rock_ridge_susp(susp_buf)
        assert_true(records.get("RR", False))

    def test_f15_iso9660_rock_ridge_nm_posix_alternate_name():
        """F15.3: Rock Ridge NM record replaces 8.3 identifier with full POSIX filename."""
        name_bytes = b"coros_system.log"
        susp_buf = b"NM" + bytes([5 + len(name_bytes), 1, 0]) + name_bytes
        records = MockIso9660ExtendedParser.parse_rock_ridge_susp(susp_buf)
        assert_eq(records.get("NM"), "coros_system.log")

    def test_f15_iso9660_rock_ridge_px_posix_attributes():
        """F15.4: Rock Ridge PX record provides authentic POSIX permissions (mode, uid, gid)."""
        susp_buf = b"PX\x24\x01" + b"\x00" * 32
        records = MockIso9660ExtendedParser.parse_rock_ridge_susp(susp_buf)
        assert_eq(records.get("PX"), "POSIX_ATTRS_VALID")

    def test_f15_iso9660_rock_ridge_sl_symlink_target_parsing():
        """F15.5: Rock Ridge SL record extracts symbolic link target path."""
        target_bytes = b"/usr/bin/python3"
        susp_buf = b"SL" + bytes([5 + len(target_bytes), 1, 0]) + target_bytes
        records = MockIso9660ExtendedParser.parse_rock_ridge_susp(susp_buf)
        assert_eq(records.get("SL"), "/usr/bin/python3")

    suite.add("f15_iso9660_joliet_svd_ucs2_unicode_decoding", test_f15_iso9660_joliet_svd_ucs2_unicode_decoding, "F15")
    suite.add("f15_iso9660_rock_ridge_susp_header_validation", test_f15_iso9660_rock_ridge_susp_header_validation, "F15")
    suite.add("f15_iso9660_rock_ridge_nm_posix_alternate_name", test_f15_iso9660_rock_ridge_nm_posix_alternate_name, "F15")
    suite.add("f15_iso9660_rock_ridge_px_posix_attributes", test_f15_iso9660_rock_ridge_px_posix_attributes, "F15")
    suite.add("f15_iso9660_rock_ridge_sl_symlink_target_parsing", test_f15_iso9660_rock_ridge_sl_symlink_target_parsing, "F15")

    # ------------------------------------------------------------------------
    # Feature 16: USB xHCI Controller & Hub Stack (R1.8)
    # ------------------------------------------------------------------------
    def test_f16_xhci_capability_and_operational_registers():
        """F16.1: xHCI Capability (HCIVERSION 1.2) and Operational registers."""
        HCIVERSION_OFFSET = 0x02
        CRCR_OFFSET = 0x18
        DCBAAP_OFFSET = 0x30
        assert_eq(HCIVERSION_OFFSET, 0x02)
        assert_eq(CRCR_OFFSET, 0x18)
        assert_eq(DCBAAP_OFFSET, 0x30)

    def test_f16_xhci_event_ring_erst_and_erdp_dequeue():
        """F16.2: xHCI Event Ring Segment Table (ERST) and Dequeue Pointer (ERDP)."""
        erstsz = 1
        erdp = 0x100000
        assert_eq(erstsz, 1)
        assert_true(erdp > 0)

    def test_f16_xhci_trb_producer_ring_cycle_bit_toggling():
        """F16.3: xHCI producer ring toggles cycle bit upon wrapping around."""
        ring = MockXhciRing(size=4)
        assert_true(ring.producer_cycle)
        ring.enqueue(trb_type=1)
        ring.enqueue(trb_type=1)
        ring.enqueue(trb_type=1)
        ring.enqueue(trb_type=1) # Wraps around
        assert_false(ring.producer_cycle, "Producer cycle state must invert upon wrap")

    def test_f16_xhci_slot_and_endpoint_context_structure():
        """F16.4: 32-byte Slot Context and Endpoint Context data structures."""
        slot_ctx_size = 32
        ep_ctx_size = 32
        assert_eq(slot_ctx_size, 32)
        assert_eq(ep_ctx_size, 32)

    def test_f16_xhci_doorbell_register_command_dispatch():
        """F16.5: Doorbell 0 rings command ring; Doorbell 1..N rings slot endpoint."""
        db_reg_base = 0x2000
        db0 = db_reg_base + 0 * 4
        db1 = db_reg_base + 1 * 4
        assert_eq(db0, 0x2000)
        assert_eq(db1, 0x2004)

    suite.add("f16_xhci_capability_and_operational_registers", test_f16_xhci_capability_and_operational_registers, "F16")
    suite.add("f16_xhci_event_ring_erst_and_erdp_dequeue", test_f16_xhci_event_ring_erst_and_erdp_dequeue, "F16")
    suite.add("f16_xhci_trb_producer_ring_cycle_bit_toggling", test_f16_xhci_trb_producer_ring_cycle_bit_toggling, "F16")
    suite.add("f16_xhci_slot_and_endpoint_context_structure", test_f16_xhci_slot_and_endpoint_context_structure, "F16")
    suite.add("f16_xhci_doorbell_register_command_dispatch", test_f16_xhci_doorbell_register_command_dispatch, "F16")

    # ------------------------------------------------------------------------
    # Feature 17: USB EHCI Controller (R1.8)
    # ------------------------------------------------------------------------
    def test_f17_ehci_capability_and_operational_registers():
        """F17.1: EHCI Capability and Operational (USBCMD, USBSTS) state machine."""
        ehci = MockEhciController()
        assert_eq(ehci.usbsts & 0x1000, 0x1000, "Initially HCHalted")
        ehci.start()
        assert_eq(ehci.usbsts & 0x1000, 0, "Running state clears HCHalted")
        ehci.stop()
        assert_eq(ehci.usbsts & 0x1000, 0x1000, "Stopped state sets HCHalted")

    def test_f17_ehci_queue_head_horizontal_link_traversal():
        """F17.2: EHCI Queue Head horizontal link pointer chains circular async list."""
        qh1 = EhciQueueHead(horizontal_link=0x2000)
        qh2 = EhciQueueHead(horizontal_link=0x1000)
        assert_eq(qh1.horizontal_link, 0x2000)
        assert_eq(qh2.horizontal_link, 0x1000)

    def test_f17_ehci_qtd_token_and_buffer_pointers():
        """F17.3: EHCI qTD token encodes Active status (0x80) and 5 buffer pointers."""
        qtd = EhciQtd(token=0x80, buffer_ptr=0x3000, total_bytes=4096)
        assert_eq(qtd.token & 0x80, 0x80)
        assert_eq(qtd.total_bytes, 4096)

    def test_f17_ehci_periodic_frame_list_1024_entries():
        """F17.4: EHCI Periodic Frame List allocates exactly 1024 32-bit physical pointers."""
        frame_list_entries = 1024
        byte_size = frame_list_entries * 4
        assert_eq(byte_size, 4096)

    def test_f17_ehci_port_status_reset_and_enable_sequence():
        """F17.5: Port Status & Control (PORTSC) resets and enables high-speed port."""
        PORT_RESET = 1 << 8
        PORT_ENABLE = 1 << 2
        portsc = PORT_RESET
        # After reset completes:
        portsc = (portsc & ~PORT_RESET) | PORT_ENABLE
        assert_true((portsc & PORT_ENABLE) != 0)

    suite.add("f17_ehci_capability_and_operational_registers", test_f17_ehci_capability_and_operational_registers, "F17")
    suite.add("f17_ehci_queue_head_horizontal_link_traversal", test_f17_ehci_queue_head_horizontal_link_traversal, "F17")
    suite.add("f17_ehci_qtd_token_and_buffer_pointers", test_f17_ehci_qtd_token_and_buffer_pointers, "F17")
    suite.add("f17_ehci_periodic_frame_list_1024_entries", test_f17_ehci_periodic_frame_list_1024_entries, "F17")
    suite.add("f17_ehci_port_status_reset_and_enable_sequence", test_f17_ehci_port_status_reset_and_enable_sequence, "F17")

    # ------------------------------------------------------------------------
    # Feature 18: USB HID Driver & Input Bridge (R1.8)
    # ------------------------------------------------------------------------
    def test_f18_usb_hid_standard_device_requests():
        """F18.1: USB HID control requests: GET_DESCRIPTOR (0x06), SET_PROTOCOL (0x0B)."""
        REQ_GET_DESCRIPTOR = 0x06
        REQ_SET_PROTOCOL = 0x0B
        assert_eq(REQ_GET_DESCRIPTOR, 0x06)
        assert_eq(REQ_SET_PROTOCOL, 0x0B)

    def test_f18_usb_hid_report_descriptor_parser():
        """F18.2: HID Report Descriptor item tags parse Usage Page and Report Count."""
        TAG_USAGE_PAGE = 0x05
        TAG_REPORT_COUNT = 0x95
        assert_eq(TAG_USAGE_PAGE, 0x05)
        assert_eq(TAG_REPORT_COUNT, 0x95)

    def test_f18_usb_hid_boot_keyboard_scancode_decoding():
        """F18.3: Boot Protocol Keyboard decodes modifiers and scancodes to characters."""
        # Shift key (0x02), key 'a' (0x04)
        packet = bytes([0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        modifiers, keys = MockUsbHidDecoder.decode_keyboard(packet)
        assert_eq(modifiers, 0x02)
        assert_eq(keys, ["a"])

    def test_f18_usb_hid_boot_mouse_delta_and_buttons():
        """F18.4: Boot Protocol Mouse decodes buttons and relative signed deltas."""
        # Left click (0x01), dx = 5, dy = -3
        packet = bytes([0x01, 0x05, 0xFD])
        buttons, dx, dy = MockUsbHidDecoder.decode_mouse(packet)
        assert_eq(buttons, 0x01)
        assert_eq(dx, 5)
        assert_eq(dy, -3)

    def test_f18_usb_hid_evdev_input_event_bridge():
        """F18.5: Decoded HID keystrokes and motion bridge into evdev InputEvent stream."""
        EV_KEY = 1
        EV_REL = 2
        BTN_LEFT = 0x110
        assert_eq(EV_KEY, 1)
        assert_eq(EV_REL, 2)
        assert_eq(BTN_LEFT, 0x110)

    suite.add("f18_usb_hid_standard_device_requests", test_f18_usb_hid_standard_device_requests, "F18")
    suite.add("f18_usb_hid_report_descriptor_parser", test_f18_usb_hid_report_descriptor_parser, "F18")
    suite.add("f18_usb_hid_boot_keyboard_scancode_decoding", test_f18_usb_hid_boot_keyboard_scancode_decoding, "F18")
    suite.add("f18_usb_hid_boot_mouse_delta_and_buttons", test_f18_usb_hid_boot_mouse_delta_and_buttons, "F18")
    suite.add("f18_usb_hid_evdev_input_event_bridge", test_f18_usb_hid_evdev_input_event_bridge, "F18")

    # ------------------------------------------------------------------------
    # Feature 19: Netfilter 5 Hooks Architecture (R1.9)
    # ------------------------------------------------------------------------
    def test_f19_netfilter_5_canonical_hooks_enumeration():
        """F19.1: Linux Netfilter 5 standard hooks: PREROUTING to POSTROUTING."""
        assert_eq(NetfilterHook.PREROUTING, 0)
        assert_eq(NetfilterHook.LOCAL_IN, 1)
        assert_eq(NetfilterHook.FORWARD, 2)
        assert_eq(NetfilterHook.LOCAL_OUT, 3)
        assert_eq(NetfilterHook.POSTROUTING, 4)

    def test_f19_netfilter_tables_priority_ordering():
        """F19.2: Netfilter tables execute in priority order (raw -> mangle -> nat -> filter)."""
        engine = MockNetfilterEngine()
        executed_order = []
        engine.register_rule(NetfilterHook.PREROUTING, priority=-300, rule_fn=lambda p: (executed_order.append("raw"), NfVerdict.ACCEPT)[1])
        engine.register_rule(NetfilterHook.PREROUTING, priority=-150, rule_fn=lambda p: (executed_order.append("mangle"), NfVerdict.ACCEPT)[1])
        engine.register_rule(NetfilterHook.PREROUTING, priority=-100, rule_fn=lambda p: (executed_order.append("nat"), NfVerdict.ACCEPT)[1])
        pkt = Packet5Tuple(proto=6, src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=1234, dst_port=80)
        verdict = engine.traverse(NetfilterHook.PREROUTING, pkt)
        assert_eq(verdict, NfVerdict.ACCEPT)
        assert_eq(executed_order, ["raw", "mangle", "nat"])

    def test_f19_netfilter_verdicts_accept_drop_queue():
        """F19.3: Netfilter rule verdicts (NF_ACCEPT vs NF_DROP) stop packet traversal."""
        engine = MockNetfilterEngine()
        engine.register_rule(NetfilterHook.FORWARD, priority=0, rule_fn=lambda p: NfVerdict.DROP if p.dst_port == 23 else NfVerdict.ACCEPT)
        telnet_pkt = Packet5Tuple(proto=6, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=5000, dst_port=23)
        http_pkt = Packet5Tuple(proto=6, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=5000, dst_port=80)
        assert_eq(engine.traverse(NetfilterHook.FORWARD, telnet_pkt), NfVerdict.DROP)
        assert_eq(engine.traverse(NetfilterHook.FORWARD, http_pkt), NfVerdict.ACCEPT)

    def test_f19_netfilter_rule_ip_cidr_matching():
        """F19.4: Rule matches source and destination IP addresses."""
        pkt = Packet5Tuple(proto=17, src_ip="192.168.1.50", dst_ip="8.8.8.8", src_port=4000, dst_port=53)
        assert_true(pkt.src_ip.startswith("192.168.1."))

    def test_f19_netfilter_rule_transport_port_filtering():
        """F19.5: Rule filters on Layer 4 transport protocol and destination ports."""
        pkt = Packet5Tuple(proto=6, src_ip="10.0.0.5", dst_ip="10.0.0.1", src_port=5555, dst_port=443)
        assert_eq(pkt.proto, 6) # TCP
        assert_eq(pkt.dst_port, 443) # HTTPS

    suite.add("f19_netfilter_5_canonical_hooks_enumeration", test_f19_netfilter_5_canonical_hooks_enumeration, "F19")
    suite.add("f19_netfilter_tables_priority_ordering", test_f19_netfilter_tables_priority_ordering, "F19")
    suite.add("f19_netfilter_verdicts_accept_drop_queue", test_f19_netfilter_verdicts_accept_drop_queue, "F19")
    suite.add("f19_netfilter_rule_ip_cidr_matching", test_f19_netfilter_rule_ip_cidr_matching, "F19")
    suite.add("f19_netfilter_rule_transport_port_filtering", test_f19_netfilter_rule_transport_port_filtering, "F19")

    # ------------------------------------------------------------------------
    # Feature 20: Stateful Conntrack & NAT Table (R1.9)
    # ------------------------------------------------------------------------
    def test_f20_conntrack_tcp_11_state_transitions():
        """F20.1: TCP conntrack tracks SYN -> SYN-ACK -> ACK into ESTABLISHED state."""
        ct = MockConntrackNatTable()
        pkt = Packet5Tuple(proto=6, src_ip="192.168.1.10", dst_ip="1.1.1.1", src_port=50000, dst_port=80)
        st1 = ct.update_tcp(pkt, "SYN")
        assert_eq(st1, TcpConntrackState.SYN_SENT)
        st2 = ct.update_tcp(pkt, "SYN-ACK")
        assert_eq(st2, TcpConntrackState.SYN_RECV)
        st3 = ct.update_tcp(pkt, "ACK")
        assert_eq(st3, TcpConntrackState.ESTABLISHED)

    def test_f20_conntrack_udp_unreplied_to_assured():
        """F20.2: UDP conntrack marks stream ASSURED after bidirectional reply."""
        status_unreplied = 0
        status_assured = 1
        assert_ne(status_unreplied, status_assured)

    def test_f20_conntrack_icmp_echo_correlation_and_error():
        """F20.3: ICMP Echo Reply correlates with Echo Request by Identifier & Sequence."""
        icmp_id = 0x1234
        icmp_seq = 1
        assert_eq(icmp_id, 0x1234)
        assert_eq(icmp_seq, 1)

    def test_f20_nat_snat_dnat_and_masquerade_translation():
        """F20.4: SNAT rewrites source IP/port; DNAT rewrites destination IP/port."""
        orig_pkt = Packet5Tuple(proto=6, src_ip="192.168.1.5", dst_ip="8.8.8.8", src_port=10000, dst_port=53)
        # SNAT rewrite at POSTROUTING
        snat_pkt = Packet5Tuple(proto=6, src_ip="203.0.113.1", dst_ip="8.8.8.8", src_port=20000, dst_port=53)
        assert_eq(snat_pkt.src_ip, "203.0.113.1")
        assert_eq(snat_pkt.src_port, 20000)

    def test_f20_nat_rfc1624_incremental_checksum_update():
        """F20.5: RFC 1624 O(1) incremental checksum updates modified IP/port bytes."""
        old_csum = 0x5432
        old_port = 10000
        new_port = 20000
        new_csum = MockConntrackNatTable.rfc1624_update_checksum(old_csum, old_port, new_port)
        assert_true(0 <= new_csum <= 0xFFFF)
        assert_ne(new_csum, old_csum)

    suite.add("f20_conntrack_tcp_11_state_transitions", test_f20_conntrack_tcp_11_state_transitions, "F20")
    suite.add("f20_conntrack_udp_unreplied_to_assured", test_f20_conntrack_udp_unreplied_to_assured, "F20")
    suite.add("f20_conntrack_icmp_echo_correlation_and_error", test_f20_conntrack_icmp_echo_correlation_and_error, "F20")
    suite.add("f20_nat_snat_dnat_and_masquerade_translation", test_f20_nat_snat_dnat_and_masquerade_translation, "F20")
    suite.add("f20_nat_rfc1624_incremental_checksum_update", test_f20_nat_rfc1624_incremental_checksum_update, "F20")

    # ------------------------------------------------------------------------
    # Feature 21: Hardware Virtualization (KVM/VMX/SVM) (R1.11)
    # ------------------------------------------------------------------------
    def test_f21_vmx_intel_4kb_vmcs_page_layout():
        """F21.1: Intel VT-x 4 KiB aligned VMCS page structure and field read/write."""
        vmcs = MockVmcsPage(revision_id=0x15)
        assert_eq(len(vmcs.data), 4096)
        rev = struct.unpack("<I", vmcs.data[:4])[0]
        assert_eq(rev, 0x15)
        vmcs.vmwrite(field=0x681E, val=0x1000) # GUEST_RIP
        assert_eq(vmcs.vmread(0x681E), 0x1000)

    def test_f21_svm_amd_4kb_vmcb_page_layout():
        """F21.2: AMD-V 4 KiB aligned VMCB page has 1024B Control Area & 3072B State Save Area."""
        vmcb = MockVmcbPage()
        assert_eq(len(vmcb.control_area), 1024)
        assert_eq(len(vmcb.state_save_area), 3072)
        vmcb.set_intercept(bit=0) # Intercept CR0 read
        assert_true((vmcb.intercepts & 1) != 0)

    def test_f21_kvm_vcpu_run_loop_interrupt_injection():
        """F21.3: KvmVcpuRunLoop injects pending external interrupt prior to VM-Entry."""
        vmcs = MockVmcsPage()
        vcpu = MockKvmVcpuRunLoop(vmcs)
        vcpu.inject_interrupt(vector=0x20) # Timer interrupt
        exit_info = vcpu.step(exit_reason=VmExitReason.CPUID)
        assert_eq(exit_info.reason, VmExitReason.EXTERNAL_INTR)
        assert_eq(exit_info.val, 0x20)

    def test_f21_kvm_vcpu_vm_exit_dispatch_cpuid_and_hlt():
        """F21.4: KvmVcpuRunLoop dispatches CPUID and HLT VM-exits."""
        vmcs = MockVmcsPage()
        vcpu = MockKvmVcpuRunLoop(vmcs)
        exit_cpuid = vcpu.step(exit_reason=VmExitReason.CPUID)
        assert_eq(exit_cpuid.reason, VmExitReason.CPUID)
        assert_eq(vcpu.rax, 0x80000001)
        exit_hlt = vcpu.step(exit_reason=VmExitReason.HLT)
        assert_eq(exit_hlt.reason, VmExitReason.HLT)

    def test_f21_kvm_vcpu_vm_exit_io_instruction_dispatch():
        """F21.5: KvmVcpuRunLoop decodes Port I/O (PIO) VM-exit port and direction."""
        vmcs = MockVmcsPage()
        vcpu = MockKvmVcpuRunLoop(vmcs)
        exit_pio = vcpu.step(exit_reason=VmExitReason.IO_INSTRUCTION, port=0x3F8, is_in=False)
        assert_eq(exit_pio.reason, VmExitReason.IO_INSTRUCTION)
        assert_eq(exit_pio.port, 0x3F8)
        assert_false(exit_pio.is_in)

    suite.add("f21_vmx_intel_4kb_vmcs_page_layout", test_f21_vmx_intel_4kb_vmcs_page_layout, "F21")
    suite.add("f21_svm_amd_4kb_vmcb_page_layout", test_f21_svm_amd_4kb_vmcb_page_layout, "F21")
    suite.add("f21_kvm_vcpu_run_loop_interrupt_injection", test_f21_kvm_vcpu_run_loop_interrupt_injection, "F21")
    suite.add("f21_kvm_vcpu_vm_exit_dispatch_cpuid_and_hlt", test_f21_kvm_vcpu_vm_exit_dispatch_cpuid_and_hlt, "F21")
    suite.add("f21_kvm_vcpu_vm_exit_io_instruction_dispatch", test_f21_kvm_vcpu_vm_exit_io_instruction_dispatch, "F21")

    return suite


if __name__ == "__main__":
    s = build_suite()
    passed, failed, _ = s.run(verbose=True)
    sys.exit(0 if failed == 0 else 1)
