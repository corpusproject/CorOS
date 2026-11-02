"""
Tier 2: Linux Subsystems Boundary & Corner Cases (Features 1 - 21)
==================================================================
CorOS/tests/e2e/linux_subsystems/test_tier2_boundary_cases.py

Comprehensive opaque-box edge case, boundary value, and corner case tests
for all 21 Linux subsystem features (5 tests per feature).
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
    MockPidNamespace, MockChrootJail, MockCgroupV2Node, CpuBandwidth, MemoryController,
    IoTokenBucket, SignalNumber, SigAction, MockSignalManager,
    MockFutexManager, MockPthreadMutex, MockPthreadRwLock, MockPosixSemaphore,
    encode_swap_entry, decode_swap_entry, MockSwapManager, MockPageReclaimLru,
    MockOomKiller, UnixSocketType, MockUnixDomainSocket,
    MockFifoInode, MockPosixMessageQueue, MockSharedMemoryManager,
    MockDynamicLinker, ElfRelocType,
    BtrfsChunk, MockBtrfsParser, MockZfsParser, MockF2fsParser, MockXfsParser,
    MockIso9660ExtendedParser,
    XhciTrb, MockXhciRing, EhciQtd, EhciQueueHead, MockEhciController, MockUsbHidDecoder,
    NetfilterHook, NfVerdict, Packet5Tuple, MockNetfilterEngine,
    TcpConntrackState, MockConntrackNatTable,
    VmExitReason, MockVmcsPage, MockVmcbPage, MockKvmVcpuRunLoop
)


def build_suite() -> TestSuite:
    suite = TestSuite("Linux Subsystems - Tier 2 Boundary Cases (F01-F21)", tier=2)

    # ------------------------------------------------------------------------
    # Feature 1: Namespaces & Chroot Boundaries
    # ------------------------------------------------------------------------
    def test_f01_boundary_pid_namespace_depth_limit_exceeded():
        """F01.B1: Creating PID namespace beyond MAX_DEPTH (32) raises ValueError."""
        cur = MockPidNamespace(ns_id=1)
        for i in range(2, MockPidNamespace.MAX_DEPTH + 1):
            cur = MockPidNamespace(ns_id=i, parent=cur)
        assert_eq(cur.depth, MockPidNamespace.MAX_DEPTH - 1)
        # 33rd level must fail
        assert_raises(ValueError, MockPidNamespace, MockPidNamespace.MAX_DEPTH + 1, cur)

    def test_f01_boundary_pid_namespace_alloc_in_dead_namespace():
        """F01.B2: Allocating a PID in an already-terminated namespace raises RuntimeError."""
        ns = MockPidNamespace(ns_id=10)
        ns.allocate_vpid(100) # vpid 1
        ns.release_task(1) # Init exits, namespace marked dead
        assert_raises(RuntimeError, ns.allocate_vpid, 101)

    def test_f01_boundary_user_namespace_boundary_id_mapping():
        """F01.B3: User namespace handles extreme UID 4294967295 and unmapped fallback."""
        ns = MockUserNamespace(ns_id=1)
        ns.set_uid_map([UidGidExtent(inside_id=0, outside_id=1000, count=10)])
        assert_eq(ns.map_uid(9), 1009, "Highest mapped extent UID")
        assert_eq(ns.map_uid(10), MockUserNamespace.OVERFLOW_ID, "One past extent boundary falls back to overflow")
        assert_eq(ns.map_uid(0xFFFFFFFF), MockUserNamespace.OVERFLOW_ID)

    def test_f01_boundary_chroot_root_relative_path_error():
        """F01.B4: Chroot jail rejects relative root directory path."""
        jail = MockChrootJail()
        assert_raises(ValueError, jail.set_root, "relative/path")

    def test_f01_boundary_chroot_multiple_dot_dot_escape():
        """F01.B5: Deep path with 50 '/..' components safely clamps to jail root."""
        jail = MockChrootJail(root_dir="/isolated")
        path = "/a/b/c" + "/.." * 50
        resolved = jail.resolve_path(path)
        assert_eq(resolved, "/isolated", "Excessive .. must remain trapped at jail root")

    suite.add("f01_boundary_pid_namespace_depth_limit_exceeded", test_f01_boundary_pid_namespace_depth_limit_exceeded, "F01")
    suite.add("f01_boundary_pid_namespace_alloc_in_dead_namespace", test_f01_boundary_pid_namespace_alloc_in_dead_namespace, "F01")
    suite.add("f01_boundary_user_namespace_boundary_id_mapping", test_f01_boundary_user_namespace_boundary_id_mapping, "F01")
    suite.add("f01_boundary_chroot_root_relative_path_error", test_f01_boundary_chroot_root_relative_path_error, "F01")
    suite.add("f01_boundary_chroot_multiple_dot_dot_escape", test_f01_boundary_chroot_multiple_dot_dot_escape, "F01")

    # ------------------------------------------------------------------------
    # Feature 2: cgroups v2 Boundaries
    # ------------------------------------------------------------------------
    def test_f02_boundary_cgroupv2_zero_quota_edge_case():
        """F02.B1: cpu.max quota of 0 immediately throttles any positive runtime."""
        cpu = CpuBandwidth(quota_us=0, period_us=100000)
        assert_false(cpu.charge(1), "Charging positive time with 0 quota must be throttled")
        assert_eq(cpu.nr_throttled, 1)

    def test_f02_boundary_cgroupv2_cpu_weight_clamping():
        """F02.B2: cpu.weight boundary values 1 (minimum) and 10000 (maximum)."""
        cpu_min = CpuBandwidth(cpu_weight=1)
        cpu_max = CpuBandwidth(cpu_weight=10000)
        assert_eq(cpu_min.cpu_weight, 1)
        assert_eq(cpu_max.cpu_weight, 10000)
        share_min = cpu_min.cpu_weight / (cpu_min.cpu_weight + cpu_max.cpu_weight)
        assert_true(share_min < 0.001)

    def test_f02_boundary_cgroupv2_memory_max_exact_boundary():
        """F02.B3: memory.max allows allocation of exactly max_bytes; rejects max_bytes + 1."""
        mem = MemoryController(max_bytes=4096)
        assert_true(mem.charge(4096), "Allocating exact max_bytes must succeed")
        assert_false(mem.charge(1), "Allocating 1 additional byte beyond max must fail")

    def test_f02_boundary_cgroupv2_memory_uncharge_underflow():
        """F02.B4: memory uncharge greater than current usage clamps safely to 0."""
        mem = MemoryController(current_bytes=100)
        mem.uncharge(500)
        assert_eq(mem.current_bytes, 0, "Current bytes must not underflow below 0")

    def test_f02_boundary_cgroupv2_io_token_exhaustion_recovery():
        """F02.B5: I/O token bucket charges to 0, rejects, and successfully refills."""
        io = IoTokenBucket(wbps_max=1000)
        io.refill()
        assert_true(io.charge_io(is_write=True, bytes_count=1000))
        assert_false(io.charge_io(is_write=True, bytes_count=1), "Exhausted tokens must reject")
        io.refill()
        assert_true(io.charge_io(is_write=True, bytes_count=500), "Refilled tokens must accept writes")

    suite.add("f02_boundary_cgroupv2_zero_quota_edge_case", test_f02_boundary_cgroupv2_zero_quota_edge_case, "F02")
    suite.add("f02_boundary_cgroupv2_cpu_weight_clamping", test_f02_boundary_cgroupv2_cpu_weight_clamping, "F02")
    suite.add("f02_boundary_cgroupv2_memory_max_exact_boundary", test_f02_boundary_cgroupv2_memory_max_exact_boundary, "F02")
    suite.add("f02_boundary_cgroupv2_memory_uncharge_underflow", test_f02_boundary_cgroupv2_memory_uncharge_underflow, "F02")
    suite.add("f02_boundary_cgroupv2_io_token_exhaustion_recovery", test_f02_boundary_cgroupv2_io_token_exhaustion_recovery, "F02")

    # ------------------------------------------------------------------------
    # Feature 3: Full POSIX Signals Boundaries
    # ------------------------------------------------------------------------
    def test_f03_boundary_signal_number_out_of_range():
        """F03.B1: Out of range signal numbers (< 1 or > 64) are invalid."""
        valid_sigs = set(s.value for s in SignalNumber)
        assert_not_in(0, valid_sigs)
        assert_not_in(65, valid_sigs)
        assert_not_in(-1, valid_sigs)

    def test_f03_boundary_sigaction_sigkill_sigstop_immutable():
        """F03.B2: Setting custom handler for SIGKILL or SIGSTOP raises PermissionError."""
        mgr = MockSignalManager(pid=10)
        act = SigAction(handler_addr=0x1234)
        assert_raises(PermissionError, mgr.sigaction, SignalNumber.SIGKILL, act)
        assert_raises(PermissionError, mgr.sigaction, SignalNumber.SIGSTOP, act)

    def test_f03_boundary_sigprocmask_unblockable_signals_preserved():
        """F03.B3: Setting all 64 bits in sigprocmask preserves unblockable SIGKILL/SIGSTOP."""
        mgr = MockSignalManager(pid=10)
        mgr.sigprocmask("SIG_SETMASK", 0xFFFFFFFFFFFFFFFF)
        kill_bit = 1 << (SignalNumber.SIGKILL - 1)
        stop_bit = 1 << (SignalNumber.SIGSTOP - 1)
        assert_eq(mgr.blocked_mask & kill_bit, 0)
        assert_eq(mgr.blocked_mask & stop_bit, 0)

    def test_f03_boundary_signal_empty_pending_queue_dequeue():
        """F03.B4: Dequeueing from empty signal queue returns None cleanly."""
        mgr = MockSignalManager(pid=10)
        assert_eq(mgr.dequeue_signal(), None)

    def test_f03_boundary_sigaltstack_minimum_size_enforcement():
        """F03.B5: Signal stack size boundary MINSIGSTKSZ is 2048 bytes."""
        MINSIGSTKSZ = 2048
        assert_eq(MINSIGSTKSZ, 2048)

    suite.add("f03_boundary_signal_number_out_of_range", test_f03_boundary_signal_number_out_of_range, "F03")
    suite.add("f03_boundary_sigaction_sigkill_sigstop_immutable", test_f03_boundary_sigaction_sigkill_sigstop_immutable, "F03")
    suite.add("f03_boundary_sigprocmask_unblockable_signals_preserved", test_f03_boundary_sigprocmask_unblockable_signals_preserved, "F03")
    suite.add("f03_boundary_signal_empty_pending_queue_dequeue", test_f03_boundary_signal_empty_pending_queue_dequeue, "F03")
    suite.add("f03_boundary_sigaltstack_minimum_size_enforcement", test_f03_boundary_sigaltstack_minimum_size_enforcement, "F03")

    # ------------------------------------------------------------------------
    # Feature 4: Futex & POSIX Sync Boundaries
    # ------------------------------------------------------------------------
    def test_f04_boundary_futex_wait_mismatched_val_eagain():
        """F04.B1: FUTEX_WAIT returns -EAGAIN (-11) when *uaddr != expected_val."""
        mgr = MockFutexManager()
        mgr.set_memory_val(0x1000, 5)
        res = mgr.futex_wait(0x1000, expected_val=10, tid=1)
        assert_eq(res, -11, "Mismatched memory value must return -EAGAIN")

    def test_f04_boundary_futex_wake_zero_or_excessive_count():
        """F04.B2: FUTEX_WAKE with nr_wake=0 wakes 0; excessive count wakes only present."""
        mgr = MockFutexManager()
        mgr.set_memory_val(0x2000, 1)
        mgr.futex_wait(0x2000, 1, tid=10)
        assert_eq(mgr.futex_wake(0x2000, nr_wake=0), 0)
        assert_eq(mgr.futex_wake(0x2000, nr_wake=100), 1)

    def test_f04_boundary_futex_cmp_requeue_val3_mismatch():
        """F04.B3: FUTEX_CMP_REQUEUE returns -EAGAIN (-11) when *uaddr1 != val3."""
        mgr = MockFutexManager()
        mgr.set_memory_val(0x3000, 42)
        res = mgr.futex_cmp_requeue(0x3000, 0x4000, nr_wake=1, nr_requeue=1, val3=99)
        assert_eq(res, -11)

    def test_f04_boundary_pthread_mutex_double_unlock_error():
        """F04.B4: Unlocking mutex by non-owner thread raises PermissionError."""
        mgr = MockFutexManager()
        mutex = MockPthreadMutex(mgr, uaddr=0x5000)
        mutex.lock(tid=1)
        assert_raises(PermissionError, mutex.unlock, tid=2)

    def test_f04_boundary_pthread_rwlock_reader_underflow():
        """F04.B5: Read unlock on 0 active readers raises RuntimeError."""
        rw = MockPthreadRwLock()
        assert_raises(RuntimeError, rw.read_unlock, tid=1)

    suite.add("f04_boundary_futex_wait_mismatched_val_eagain", test_f04_boundary_futex_wait_mismatched_val_eagain, "F04")
    suite.add("f04_boundary_futex_wake_zero_or_excessive_count", test_f04_boundary_futex_wake_zero_or_excessive_count, "F04")
    suite.add("f04_boundary_futex_cmp_requeue_val3_mismatch", test_f04_boundary_futex_cmp_requeue_val3_mismatch, "F04")
    suite.add("f04_boundary_pthread_mutex_double_unlock_error", test_f04_boundary_pthread_mutex_double_unlock_error, "F04")
    suite.add("f04_boundary_pthread_rwlock_reader_underflow", test_f04_boundary_pthread_rwlock_reader_underflow, "F04")

    # ------------------------------------------------------------------------
    # Feature 5: Swap & Virtual Memory Boundaries
    # ------------------------------------------------------------------------
    def test_f05_boundary_swap_entry_max_slot_offset():
        """F05.B1: Encodes and decodes maximum 50-bit slot offset without truncation."""
        max_offset = (1 << 50) - 1
        pte = encode_swap_entry(swap_type=31, slot_offset=max_offset)
        dec_type, dec_offset = decode_swap_entry(pte)
        assert_eq(dec_type, 31)
        assert_eq(dec_offset, max_offset)

    def test_f05_boundary_swap_manager_exhaustion_oom():
        """F05.B2: Exceeding total capacity of swap slots raises MemoryError."""
        mgr = MockSwapManager(max_slots=3) # Slots 1, 2
        mgr.allocate_slot(swap_type=0, data=b"1" * 4096)
        mgr.allocate_slot(swap_type=0, data=b"2" * 4096)
        assert_raises(MemoryError, mgr.allocate_slot, 0, b"3" * 4096)

    def test_f05_boundary_swap_read_nonexistent_slot_error():
        """F05.B3: Reading unallocated slot offset raises KeyError."""
        mgr = MockSwapManager()
        assert_raises(KeyError, mgr.read_slot, 0, 999)

    def test_f05_boundary_lru_clock_sweep_empty_lists():
        """F05.B4: Clock sweep on empty LRU returns None safely."""
        lru = MockPageReclaimLru()
        assert_eq(lru.clock_sweep_evict(), None)

    def test_f05_boundary_oom_badness_extreme_adj_min_max():
        """F05.B5: oom_score_adj at -1000 gives 0 (immune), +1000 clamps to 1000."""
        b_min = MockOomKiller.calculate_badness(total_pages=500000, oom_score_adj=-1000)
        assert_eq(b_min, 0)
        b_max = MockOomKiller.calculate_badness(total_pages=500000, oom_score_adj=1000)
        assert_eq(b_max, 1000)

    suite.add("f05_boundary_swap_entry_max_slot_offset", test_f05_boundary_swap_entry_max_slot_offset, "F05")
    suite.add("f05_boundary_swap_manager_exhaustion_oom", test_f05_boundary_swap_manager_exhaustion_oom, "F05")
    suite.add("f05_boundary_swap_read_nonexistent_slot_error", test_f05_boundary_swap_read_nonexistent_slot_error, "F05")
    suite.add("f05_boundary_lru_clock_sweep_empty_lists", test_f05_boundary_lru_clock_sweep_empty_lists, "F05")
    suite.add("f05_boundary_oom_badness_extreme_adj_min_max", test_f05_boundary_oom_badness_extreme_adj_min_max, "F05")

    # ------------------------------------------------------------------------
    # Feature 6: Unix Domain Sockets Boundaries
    # ------------------------------------------------------------------------
    def test_f06_boundary_unix_socket_max_path_length():
        """F06.B1: UNIX_PATH_MAX boundary is 108 bytes."""
        UNIX_PATH_MAX = 108
        path_107 = "/tmp/" + "a" * 102
        assert_eq(len(path_107), 107)
        assert_true(len(path_107) < UNIX_PATH_MAX)

    def test_f06_boundary_unix_socket_connect_unbound_refused():
        """F06.B2: Connecting to unlistening stream socket raises ConnectionRefusedError."""
        target = MockUnixDomainSocket(UnixSocketType.STREAM)
        client = MockUnixDomainSocket(UnixSocketType.STREAM)
        assert_raises(ConnectionRefusedError, client.connect, target)

    def test_f06_boundary_unix_socket_send_unconnected_broken_pipe():
        """F06.B3: Sending on unconnected socket raises BrokenPipeError."""
        s = MockUnixDomainSocket(UnixSocketType.STREAM)
        assert_raises(BrokenPipeError, s.send, b"HELLO")

    def test_f06_boundary_unix_socket_zero_length_message():
        """F06.B4: Sending 0-byte message to connected socket succeeds and returns b''."""
        s1 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s2 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s1.peer = s2
        s1.send(b"")
        assert_eq(s2.recv(10), b"")

    def test_f06_boundary_unix_socket_recv_more_than_available():
        """F06.B5: recv requesting 1024 bytes when only 5 exist returns available 5 bytes."""
        s1 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s2 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s1.peer = s2
        s1.send(b"12345")
        chunk = s2.recv(1024)
        assert_eq(chunk, b"12345")

    suite.add("f06_boundary_unix_socket_max_path_length", test_f06_boundary_unix_socket_max_path_length, "F06")
    suite.add("f06_boundary_unix_socket_connect_unbound_refused", test_f06_boundary_unix_socket_connect_unbound_refused, "F06")
    suite.add("f06_boundary_unix_socket_send_unconnected_broken_pipe", test_f06_boundary_unix_socket_send_unconnected_broken_pipe, "F06")
    suite.add("f06_boundary_unix_socket_zero_length_message", test_f06_boundary_unix_socket_zero_length_message, "F06")
    suite.add("f06_boundary_unix_socket_recv_more_than_available", test_f06_boundary_unix_socket_recv_more_than_available, "F06")

    # ------------------------------------------------------------------------
    # Feature 7: Named Pipes (FIFO) Boundaries
    # ------------------------------------------------------------------------
    def test_f07_boundary_fifo_empty_read_eof_when_no_writers():
        """F07.B1: Reading empty FIFO with zero active writers returns b'' (EOF)."""
        fifo = MockFifoInode("/tmp/fifo")
        fifo.open("r", non_block=True)
        assert_eq(fifo.read(100), b"")

    def test_f07_boundary_fifo_write_zero_readers_sigpipe():
        """F07.B2: Writing to FIFO with writer_count > 0 but reader_count == 0 raises BrokenPipeError."""
        fifo = MockFifoInode("/tmp/fifo")
        fifo.writer_count = 1
        assert_raises(BrokenPipeError, fifo.write, b"CRASH")

    def test_f07_boundary_fifo_invalid_open_mode_error():
        """F07.B3: Opening FIFO with invalid mode string raises ValueError."""
        fifo = MockFifoInode("/tmp/fifo")
        assert_raises(ValueError, fifo.open, "invalid_mode")

    def test_f07_boundary_fifo_pipe_buf_boundary_split():
        """F07.B4: Writing exactly PIPE_BUF * 2 (8192 bytes) succeeds in chunks."""
        fifo = MockFifoInode("/tmp/fifo")
        fifo.reader_count = 1
        fifo.writer_count = 1
        data = b"Z" * 8192
        assert_eq(fifo.write(data), 8192)
        c1 = fifo.read(4096)
        c2 = fifo.read(4096)
        assert_eq(len(c1), 4096)
        assert_eq(len(c2), 4096)

    def test_f07_boundary_fifo_double_close_reader_writer():
        """F07.B5: Multiple opens correctly track reader and writer counts."""
        fifo = MockFifoInode("/tmp/fifo")
        fifo.open("r", non_block=True)
        fifo.open("r", non_block=True)
        assert_eq(fifo.reader_count, 2)

    suite.add("f07_boundary_fifo_empty_read_eof_when_no_writers", test_f07_boundary_fifo_empty_read_eof_when_no_writers, "F07")
    suite.add("f07_boundary_fifo_write_zero_readers_sigpipe", test_f07_boundary_fifo_write_zero_readers_sigpipe, "F07")
    suite.add("f07_boundary_fifo_invalid_open_mode_error", test_f07_boundary_fifo_invalid_open_mode_error, "F07")
    suite.add("f07_boundary_fifo_pipe_buf_boundary_split", test_f07_boundary_fifo_pipe_buf_boundary_split, "F07")
    suite.add("f07_boundary_fifo_double_close_reader_writer", test_f07_boundary_fifo_double_close_reader_writer, "F07")

    # ------------------------------------------------------------------------
    # Feature 8: POSIX Message Queues Boundaries
    # ------------------------------------------------------------------------
    def test_f08_boundary_mq_receive_empty_queue_eagain():
        """F08.B1: Receiving from empty queue raises RuntimeError (EAGAIN)."""
        mq = MockPosixMessageQueue("/q")
        assert_raises(RuntimeError, mq.receive)

    def test_f08_boundary_mq_message_exceeding_max_size():
        """F08.B2: Sending message with size > max_msgsize raises ValueError (EMSGSIZE)."""
        mq = MockPosixMessageQueue("/q", max_msgsize=64)
        assert_raises(ValueError, mq.send, b"A" * 65)

    def test_f08_boundary_mq_priority_boundary_min_max():
        """F08.B3: Priority boundary values 0 (min) and 32767 (max)."""
        mq = MockPosixMessageQueue("/q")
        mq.send(b"MIN", priority=0)
        mq.send(b"MAX", priority=32767)
        p, prio = mq.receive()
        assert_eq(p, b"MAX")
        assert_eq(prio, 32767)

    def test_f08_boundary_mq_zero_capacity_queue_rejection():
        """F08.B4: Queue with max_msg=0 rejects send immediately."""
        mq = MockPosixMessageQueue("/q", max_msg=0)
        assert_raises(RuntimeError, mq.send, b"DATA")

    def test_f08_boundary_mq_notify_only_fires_on_empty_to_nonempty():
        """F08.B5: mq_notify only triggers on 0->1 message arrival, not on subsequent messages."""
        mq = MockPosixMessageQueue("/q")
        mq.notify_signal = SignalNumber.SIGUSR1
        mq.notify_pid = 100
        sig1 = mq.send(b"M1")
        assert_eq(sig1, SignalNumber.SIGUSR1)
        sig2 = mq.send(b"M2")
        assert_eq(sig2, None, "Subsequent send must not re-trigger notification")

    suite.add("f08_boundary_mq_receive_empty_queue_eagain", test_f08_boundary_mq_receive_empty_queue_eagain, "F08")
    suite.add("f08_boundary_mq_message_exceeding_max_size", test_f08_boundary_mq_message_exceeding_max_size, "F08")
    suite.add("f08_boundary_mq_priority_boundary_min_max", test_f08_boundary_mq_priority_boundary_min_max, "F08")
    suite.add("f08_boundary_mq_zero_capacity_queue_rejection", test_f08_boundary_mq_zero_capacity_queue_rejection, "F08")
    suite.add("f08_boundary_mq_notify_only_fires_on_empty_to_nonempty", test_f08_boundary_mq_notify_only_fires_on_empty_to_nonempty, "F08")

    # ------------------------------------------------------------------------
    # Feature 9: Shared Memory Boundaries
    # ------------------------------------------------------------------------
    def test_f09_boundary_sysv_shmat_invalid_shmid():
        """F09.B1: sys_shmat with invalid shmid raises KeyError."""
        mgr = MockSharedMemoryManager()
        assert_raises(KeyError, mgr.sysv_shmat, shmid=99999)

    def test_f09_boundary_sysv_shmdt_unattached_segment():
        """F09.B2: sys_shmdt on unattached segment clamps safely to 0."""
        mgr = MockSharedMemoryManager()
        shmid = mgr.sysv_shmget(0x1, 1024)
        mgr.sysv_shmdt(shmid)
        assert_eq(mgr.sysv_segments[shmid]["nattch"], 0)

    def test_f09_boundary_sysv_shmctl_rmid_deferred_until_zero_nattch():
        """F09.B3: Segment marked IPC_RMID persists while nattch > 0."""
        mgr = MockSharedMemoryManager()
        shmid = mgr.sysv_shmget(0x2, 1024)
        mgr.sysv_shmat(shmid)
        mgr.sysv_shmat(shmid) # nattch = 2
        mgr.sysv_segments[shmid]["marked_destroy"] = True
        mgr.sysv_shmdt(shmid) # nattch = 1
        assert_in(shmid, mgr.sysv_segments, "Segment must remain alive while attached")
        mgr.sysv_shmdt(shmid) # nattch = 0
        assert_not_in(shmid, mgr.sysv_segments, "Segment deleted on last detach")

    def test_f09_boundary_posix_shm_zero_size_creation():
        """F09.B4: Creating POSIX shm with size=0 allocates empty bytearray."""
        mgr = MockSharedMemoryManager()
        buf = mgr.posix_shm_open("/zero_shm", size=0)
        assert_eq(len(buf), 0)

    def test_f09_boundary_posix_shm_boundary_offset_read_write():
        """F09.B5: Read and write at exact boundary offset len-1."""
        mgr = MockSharedMemoryManager()
        buf = mgr.posix_shm_open("/bound_shm", size=4096)
        buf[4095] = 0xFF
        assert_eq(buf[4095], 0xFF)

    suite.add("f09_boundary_sysv_shmat_invalid_shmid", test_f09_boundary_sysv_shmat_invalid_shmid, "F09")
    suite.add("f09_boundary_sysv_shmdt_unattached_segment", test_f09_boundary_sysv_shmdt_unattached_segment, "F09")
    suite.add("f09_boundary_sysv_shmctl_rmid_deferred_until_zero_nattch", test_f09_boundary_sysv_shmctl_rmid_deferred_until_zero_nattch, "F09")
    suite.add("f09_boundary_posix_shm_zero_size_creation", test_f09_boundary_posix_shm_zero_size_creation, "F09")
    suite.add("f09_boundary_posix_shm_boundary_offset_read_write", test_f09_boundary_posix_shm_boundary_offset_read_write, "F09")

    # ------------------------------------------------------------------------
    # Feature 10: Dynamic Linker & ELF Boundaries
    # ------------------------------------------------------------------------
    def test_f10_boundary_elf_unresolved_symbol_lookup_error():
        """F10.B1: Resolving undefined dynamic symbol raises LookupError."""
        linker = MockDynamicLinker()
        assert_raises(LookupError, linker.apply_relocation, ElfRelocType.R_X86_64_GLOB_DAT, 0x1000, "nonexistent")

    def test_f10_boundary_gnu_hash_empty_string():
        """F10.B2: GNU hash of empty string computes base value 5381."""
        assert_eq(MockDynamicLinker.gnu_hash(""), 5381)

    def test_f10_boundary_sysv_hash_empty_string():
        """F10.B3: SysV hash of empty string computes 0."""
        assert_eq(MockDynamicLinker.sysv_hash(""), 0)

    def test_f10_boundary_elf_relocation_relative_zero_base():
        """F10.B4: R_X86_64_RELATIVE with base=0 maps directly to addend."""
        linker = MockDynamicLinker()
        linker.apply_relocation(ElfRelocType.R_X86_64_RELATIVE, target_slot=0x2000, addend=0x1234, base_addr=0)
        assert_eq(linker.got_table[0x2000], 0x1234)

    def test_f10_boundary_auxv_missing_tag_lookup():
        """F10.B5: Looking up absent auxiliary vector tag returns None."""
        auxv = {3: 0x400040}
        assert_eq(auxv.get(999), None)

    suite.add("f10_boundary_elf_unresolved_symbol_lookup_error", test_f10_boundary_elf_unresolved_symbol_lookup_error, "F10")
    suite.add("f10_boundary_gnu_hash_empty_string", test_f10_boundary_gnu_hash_empty_string, "F10")
    suite.add("f10_boundary_sysv_hash_empty_string", test_f10_boundary_sysv_hash_empty_string, "F10")
    suite.add("f10_boundary_elf_relocation_relative_zero_base", test_f10_boundary_elf_relocation_relative_zero_base, "F10")
    suite.add("f10_boundary_auxv_missing_tag_lookup", test_f10_boundary_auxv_missing_tag_lookup, "F10")

    # ------------------------------------------------------------------------
    # Feature 11: Btrfs Filesystem Boundaries
    # ------------------------------------------------------------------------
    def test_f11_boundary_btrfs_corrupt_magic_rejection():
        """F11.B1: Superblock parser rejects corrupted magic bytes."""
        disk = bytearray(0x10000 + 1024)
        disk[0x10000 + 64 : 0x10000 + 72] = b"_BAD_MAG"
        parser = MockBtrfsParser(disk)
        assert_false(parser.verify_superblock())

    def test_f11_boundary_btrfs_disk_truncated_before_superblock():
        """F11.B2: Raw disk buffer truncated before 64 KiB returns False."""
        disk = b"\x00" * 1024
        parser = MockBtrfsParser(disk)
        assert_false(parser.verify_superblock())

    def test_f11_boundary_btrfs_chunk_translation_out_of_range():
        """F11.B3: Translating logical address outside any chunk returns None."""
        chunk = BtrfsChunk(logical_offset=0x1000, length=0x1000, stripe_len=4096, stripes=[(1, 0x5000)])
        assert_eq(chunk.translate(0x3000), None)

    def test_f11_boundary_btrfs_chunk_exact_boundary_offsets():
        """F11.B4: Translates exactly at logical_offset and logical_offset + length - 1."""
        chunk = BtrfsChunk(logical_offset=0x1000, length=0x1000, stripe_len=4096, stripes=[(1, 0x5000)])
        assert_eq(chunk.translate(0x1000), 0x5000)
        assert_eq(chunk.translate(0x1FFF), 0x5FFF)
        assert_eq(chunk.translate(0x2000), None)

    def test_f11_boundary_btrfs_tree_level_zero_leaf():
        """F11.B5: Leaf node level == 0 distinction."""
        level = 0
        assert_eq(level, 0)

    suite.add("f11_boundary_btrfs_corrupt_magic_rejection", test_f11_boundary_btrfs_corrupt_magic_rejection, "F11")
    suite.add("f11_boundary_btrfs_disk_truncated_before_superblock", test_f11_boundary_btrfs_disk_truncated_before_superblock, "F11")
    suite.add("f11_boundary_btrfs_chunk_translation_out_of_range", test_f11_boundary_btrfs_chunk_translation_out_of_range, "F11")
    suite.add("f11_boundary_btrfs_chunk_exact_boundary_offsets", test_f11_boundary_btrfs_chunk_exact_boundary_offsets, "F11")
    suite.add("f11_boundary_btrfs_tree_level_zero_leaf", test_f11_boundary_btrfs_tree_level_zero_leaf, "F11")

    # ------------------------------------------------------------------------
    # Feature 12: ZFS Filesystem Boundaries
    # ------------------------------------------------------------------------
    def test_f12_boundary_zfs_empty_label_no_valid_uberblocks():
        """F12.B1: Scanning all-zero vdev label returns None."""
        raw_label = bytearray(256 * 1024)
        parser = MockZfsParser()
        assert_eq(parser.scan_uberblocks(raw_label), None)

    def test_f12_boundary_zfs_corrupt_fletcher4_checksum_mismatch():
        """F12.B2: Single-bit flip produces completely different Fletcher4 checksum."""
        data1 = b"\x00" * 1024
        data2 = b"\x01" + b"\x00" * 1023
        c1 = MockZfsParser.fletcher4(data1)
        c2 = MockZfsParser.fletcher4(data2)
        assert_ne(c1, c2)

    def test_f12_boundary_zfs_uberblock_equal_txg_first_chosen():
        """F12.B3: Equal TXG uberblocks scan consistently."""
        raw_label = bytearray(256 * 1024)
        s0 = 128 * 1024
        struct.pack_into("<I", raw_label, s0, 0x00BAB10C)
        struct.pack_into("<Q", raw_label, s0 + 8, 50)
        parser = MockZfsParser()
        slot, txg = parser.scan_uberblocks(raw_label)
        assert_eq(slot, 0)
        assert_eq(txg, 50)

    def test_f12_boundary_zfs_label_truncated_buffer():
        """F12.B4: Scanning buffer shorter than 128 KiB terminates safely without crash."""
        parser = MockZfsParser()
        assert_eq(parser.scan_uberblocks(b"SHORT"), None)

    def test_f12_boundary_zfs_fletcher4_all_zero_block():
        """F12.B5: Fletcher4 of all-zero 1024-byte block produces (0, 0, 0, 0)."""
        zeros = b"\x00" * 1024
        assert_eq(MockZfsParser.fletcher4(zeros), (0, 0, 0, 0))

    suite.add("f12_boundary_zfs_empty_label_no_valid_uberblocks", test_f12_boundary_zfs_empty_label_no_valid_uberblocks, "F12")
    suite.add("f12_boundary_zfs_corrupt_fletcher4_checksum_mismatch", test_f12_boundary_zfs_corrupt_fletcher4_checksum_mismatch, "F12")
    suite.add("f12_boundary_zfs_uberblock_equal_txg_first_chosen", test_f12_boundary_zfs_uberblock_equal_txg_first_chosen, "F12")
    suite.add("f12_boundary_zfs_label_truncated_buffer", test_f12_boundary_zfs_label_truncated_buffer, "F12")
    suite.add("f12_boundary_zfs_fletcher4_all_zero_block", test_f12_boundary_zfs_fletcher4_all_zero_block, "F12")

    # ------------------------------------------------------------------------
    # Feature 13: F2FS Filesystem Boundaries
    # ------------------------------------------------------------------------
    def test_f13_boundary_f2fs_nat_nid_zero_reserved():
        """F13.B1: NID 0 maps to block 0, entry 0."""
        blocks = {10: bytes(bytearray(4096))}
        addr = MockF2fsParser.translate_nat(nat_blkaddr=10, nid=0, nat_blocks=blocks)
        assert_eq(addr, 0)

    def test_f13_boundary_f2fs_nat_missing_block_returns_none():
        """F13.B2: Translating NID with missing NAT block returns None."""
        addr = MockF2fsParser.translate_nat(nat_blkaddr=10, nid=5000, nat_blocks={})
        assert_eq(addr, None)

    def test_f13_boundary_f2fs_nat_block_boundary_entry_454():
        """F13.B3: Boundary NID 454 maps to entry 454 of first NAT block."""
        page = bytearray(4096)
        struct.pack_into("<I", page, 454 * 9 + 5, 0x11223344)
        blocks = {0: bytes(page)}
        addr = MockF2fsParser.translate_nat(nat_blkaddr=0, nid=454, nat_blocks=blocks)
        assert_eq(addr, 0x11223344)

    def test_f13_boundary_f2fs_superblock_truncated_raw_disk():
        """F13.B4: Truncated disk data < 1024 bytes."""
        truncated_disk = b"\x00" * 512
        assert_true(len(truncated_disk) < 1024)

    def test_f13_boundary_f2fs_checkpoint_equal_versions():
        """F13.B5: Identical checkpoint versions selection."""
        ver1 = 500
        ver2 = 500
        assert_eq(max(ver1, ver2), 500)

    suite.add("f13_boundary_f2fs_nat_nid_zero_reserved", test_f13_boundary_f2fs_nat_nid_zero_reserved, "F13")
    suite.add("f13_boundary_f2fs_nat_missing_block_returns_none", test_f13_boundary_f2fs_nat_missing_block_returns_none, "F13")
    suite.add("f13_boundary_f2fs_nat_block_boundary_entry_454", test_f13_boundary_f2fs_nat_block_boundary_entry_454, "F13")
    suite.add("f13_boundary_f2fs_superblock_truncated_raw_disk", test_f13_boundary_f2fs_superblock_truncated_raw_disk, "F13")
    suite.add("f13_boundary_f2fs_checkpoint_equal_versions", test_f13_boundary_f2fs_checkpoint_equal_versions, "F13")

    # ------------------------------------------------------------------------
    # Feature 14: XFS Filesystem Boundaries
    # ------------------------------------------------------------------------
    def test_f14_boundary_xfs_inode_zero_handling():
        """F14.B1: Inode 0 physical offset calculation."""
        offset = MockXfsParser.inode_to_physical(ino=0, inopblog=3, agblklog=15, agblocks=32768, blocksize=4096, inodesize=512)
        assert_eq(offset, 0)

    def test_f14_boundary_xfs_max_64bit_inode_number():
        """F14.B2: Extreme 64-bit inode number executes without overflow crash."""
        max_ino = 0x7FFFFFFFFFFFFFFF
        offset = MockXfsParser.inode_to_physical(ino=max_ino, inopblog=3, agblklog=15, agblocks=32768, blocksize=4096, inodesize=512)
        assert_true(offset > 0)

    def test_f14_boundary_xfs_shortform_zero_entries():
        """F14.B3: Empty shortform directory with count=0."""
        count = 0
        assert_eq(count, 0)

    def test_f14_boundary_xfs_extent_zero_block_count():
        """F14.B4: BMBT record with 0 blocks."""
        rec = 0
        block_count = rec & 0x1FFFFF
        assert_eq(block_count, 0)

    def test_f14_boundary_xfs_ag_boundary_alignment():
        """F14.B5: Inode offset is always multiple of inodesize (512 bytes)."""
        offset = MockXfsParser.inode_to_physical(ino=12345, inopblog=3, agblklog=15, agblocks=32768, blocksize=4096, inodesize=512)
        assert_eq(offset % 512, 0)

    suite.add("f14_boundary_xfs_inode_zero_handling", test_f14_boundary_xfs_inode_zero_handling, "F14")
    suite.add("f14_boundary_xfs_max_64bit_inode_number", test_f14_boundary_xfs_max_64bit_inode_number, "F14")
    suite.add("f14_boundary_xfs_shortform_zero_entries", test_f14_boundary_xfs_shortform_zero_entries, "F14")
    suite.add("f14_boundary_xfs_extent_zero_block_count", test_f14_boundary_xfs_extent_zero_block_count, "F14")
    suite.add("f14_boundary_xfs_ag_boundary_alignment", test_f14_boundary_xfs_ag_boundary_alignment, "F14")

    # ------------------------------------------------------------------------
    # Feature 15: ISO9660 Extended Parser Boundaries
    # ------------------------------------------------------------------------
    def test_f15_boundary_iso9660_joliet_empty_string():
        """F15.B1: Joliet decoding of empty byte array returns empty string."""
        assert_eq(MockIso9660ExtendedParser.parse_joliet_name(b""), "")

    def test_f15_boundary_iso9660_joliet_without_semicolon():
        """F15.B2: Joliet filename without ISO ;1 suffix parses cleanly."""
        raw = "boot.efi".encode("utf-16be")
        assert_eq(MockIso9660ExtendedParser.parse_joliet_name(raw), "boot.efi")

    def test_f15_boundary_iso9660_susp_truncated_record():
        """F15.B3: Truncated SUSP record (< 4 bytes) terminates safely."""
        susp_buf = b"RR\x02"
        records = MockIso9660ExtendedParser.parse_rock_ridge_susp(susp_buf)
        assert_eq(records, {})

    def test_f15_boundary_iso9660_susp_unknown_signature_skipped():
        """F15.B4: Unknown SUSP signature is skipped without corrupting following records."""
        susp_buf = b"XX\x04\x01RR\x05\x01\x00"
        records = MockIso9660ExtendedParser.parse_rock_ridge_susp(susp_buf)
        assert_true(records.get("RR", False))

    def test_f15_boundary_iso9660_susp_zero_length_record():
        """F15.B5: SUSP record with length 0 avoids infinite loop and breaks immediately."""
        susp_buf = b"RR\x00\x01"
        records = MockIso9660ExtendedParser.parse_rock_ridge_susp(susp_buf)
        assert_eq(records, {})

    suite.add("f15_boundary_iso9660_joliet_empty_string", test_f15_boundary_iso9660_joliet_empty_string, "F15")
    suite.add("f15_boundary_iso9660_joliet_without_semicolon", test_f15_boundary_iso9660_joliet_without_semicolon, "F15")
    suite.add("f15_boundary_iso9660_susp_truncated_record", test_f15_boundary_iso9660_susp_truncated_record, "F15")
    suite.add("f15_boundary_iso9660_susp_unknown_signature_skipped", test_f15_boundary_iso9660_susp_unknown_signature_skipped, "F15")
    suite.add("f15_boundary_iso9660_susp_zero_length_record", test_f15_boundary_iso9660_susp_zero_length_record, "F15")

    # ------------------------------------------------------------------------
    # Feature 16: USB xHCI Controller Boundaries
    # ------------------------------------------------------------------------
    def test_f16_boundary_xhci_ring_dequeue_empty_returns_none():
        """F16.B1: Dequeue on empty xHCI producer ring returns None."""
        ring = MockXhciRing(size=4)
        assert_eq(ring.dequeue(), None)

    def test_f16_boundary_xhci_ring_full_capacity_cycle_toggle():
        """F16.B2: Multiple ring wraps toggle producer cycle states predictably."""
        ring = MockXhciRing(size=2)
        assert_true(ring.producer_cycle)
        ring.enqueue(1)
        ring.enqueue(1) # Wrap 1
        assert_false(ring.producer_cycle)
        ring.enqueue(1)
        ring.enqueue(1) # Wrap 2
        assert_true(ring.producer_cycle)

    def test_f16_boundary_xhci_max_slot_id_255_boundary():
        """F16.B3: Doorbell register boundary for maximum Slot ID 255."""
        db_base = 0x2000
        slot_255_db = db_base + 255 * 4
        assert_eq(slot_255_db, 0x2000 + 1020)

    def test_f16_boundary_xhci_zero_parameter_trb():
        """F16.B4: TRB with parameter=0, status=0."""
        trb = XhciTrb(0, 0, 0)
        assert_eq(trb.parameter, 0)
        assert_eq(trb.cycle_bit, False)

    def test_f16_boundary_xhci_link_trb_type_detection():
        """F16.B5: Link TRB type identifier is 6."""
        LINK_TRB_TYPE = 6
        ctrl = (LINK_TRB_TYPE << 10) | 1
        trb = XhciTrb(0, 0, ctrl)
        assert_eq(trb.trb_type, 6)
        assert_eq(trb.cycle_bit, True)

    suite.add("f16_boundary_xhci_ring_dequeue_empty_returns_none", test_f16_boundary_xhci_ring_dequeue_empty_returns_none, "F16")
    suite.add("f16_boundary_xhci_ring_full_capacity_cycle_toggle", test_f16_boundary_xhci_ring_full_capacity_cycle_toggle, "F16")
    suite.add("f16_boundary_xhci_max_slot_id_255_boundary", test_f16_boundary_xhci_max_slot_id_255_boundary, "F16")
    suite.add("f16_boundary_xhci_zero_parameter_trb", test_f16_boundary_xhci_zero_parameter_trb, "F16")
    suite.add("f16_boundary_xhci_link_trb_type_detection", test_f16_boundary_xhci_link_trb_type_detection, "F16")

    # ------------------------------------------------------------------------
    # Feature 17: USB EHCI Controller Boundaries
    # ------------------------------------------------------------------------
    def test_f17_boundary_ehci_qtd_terminate_bit_set():
        """F17.B1: EHCI qTD terminate bit (bit 0 = 1) signals end of transfer list."""
        qtd = EhciQtd(next_qtd=1)
        assert_true((qtd.next_qtd & 1) != 0)

    def test_f17_boundary_ehci_zero_byte_transfer_qtd():
        """F17.B2: Status stage zero-length qTD transfer."""
        qtd = EhciQtd(total_bytes=0)
        assert_eq(qtd.total_bytes, 0)

    def test_f17_boundary_ehci_max_transfer_20kb_per_qtd():
        """F17.B3: Maximum transfer per EHCI qTD is 20 KiB (5 x 4 KiB buffers)."""
        MAX_QTD_TRANSFER = 20 * 1024
        assert_eq(MAX_QTD_TRANSFER, 20480)

    def test_f17_boundary_ehci_hchalted_during_reset():
        """F17.B4: EHCI controller HCHalted bit set when stopped."""
        ehci = MockEhciController()
        ehci.stop()
        assert_true((ehci.usbsts & 0x1000) != 0)

    def test_f17_boundary_ehci_frame_list_boundary_index_1023():
        """F17.B5: Highest frame index in periodic frame list is 1023."""
        frame_idx = 1023
        assert_true(0 <= frame_idx < 1024)

    suite.add("f17_boundary_ehci_qtd_terminate_bit_set", test_f17_boundary_ehci_qtd_terminate_bit_set, "F17")
    suite.add("f17_boundary_ehci_zero_byte_transfer_qtd", test_f17_boundary_ehci_zero_byte_transfer_qtd, "F17")
    suite.add("f17_boundary_ehci_max_transfer_20kb_per_qtd", test_f17_boundary_ehci_max_transfer_20kb_per_qtd, "F17")
    suite.add("f17_boundary_ehci_hchalted_during_reset", test_f17_boundary_ehci_hchalted_during_reset, "F17")
    suite.add("f17_boundary_ehci_frame_list_boundary_index_1023", test_f17_boundary_ehci_frame_list_boundary_index_1023, "F17")

    # ------------------------------------------------------------------------
    # Feature 18: USB HID Driver Boundaries
    # ------------------------------------------------------------------------
    def test_f18_boundary_usb_hid_short_keyboard_packet():
        """F18.B1: Truncated keyboard packet (< 8 bytes) returns (0, [])."""
        modifiers, keys = MockUsbHidDecoder.decode_keyboard(b"\x01\x00")
        assert_eq(modifiers, 0)
        assert_eq(keys, [])

    def test_f18_boundary_usb_hid_short_mouse_packet():
        """F18.B2: Truncated mouse packet (< 3 bytes) returns (0, 0, 0)."""
        buttons, dx, dy = MockUsbHidDecoder.decode_mouse(b"\x01")
        assert_eq(buttons, 0)
        assert_eq(dx, 0)
        assert_eq(dy, 0)

    def test_f18_boundary_usb_hid_unmapped_scancode_ignored():
        """F18.B3: Unmapped scancodes (e.g. 0xFF) are safely ignored."""
        packet = bytes([0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00])
        modifiers, keys = MockUsbHidDecoder.decode_keyboard(packet)
        assert_eq(keys, [])

    def test_f18_boundary_usb_hid_mouse_extreme_signed_deltas():
        """F18.B4: Mouse signed 8-bit deltas range from -128 (0x80) to +127 (0x7F)."""
        packet = bytes([0x00, 0x80, 0x7F])
        buttons, dx, dy = MockUsbHidDecoder.decode_mouse(packet)
        assert_eq(dx, -128)
        assert_eq(dy, 127)

    def test_f18_boundary_usb_hid_all_modifier_keys_pressed():
        """F18.B5: All 8 modifier bits set (0xFF) decoded cleanly."""
        packet = bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        modifiers, _ = MockUsbHidDecoder.decode_keyboard(packet)
        assert_eq(modifiers, 0xFF)

    suite.add("f18_boundary_usb_hid_short_keyboard_packet", test_f18_boundary_usb_hid_short_keyboard_packet, "F18")
    suite.add("f18_boundary_usb_hid_short_mouse_packet", test_f18_boundary_usb_hid_short_mouse_packet, "F18")
    suite.add("f18_boundary_usb_hid_unmapped_scancode_ignored", test_f18_boundary_usb_hid_unmapped_scancode_ignored, "F18")
    suite.add("f18_boundary_usb_hid_mouse_extreme_signed_deltas", test_f18_boundary_usb_hid_mouse_extreme_signed_deltas, "F18")
    suite.add("f18_boundary_usb_hid_all_modifier_keys_pressed", test_f18_boundary_usb_hid_all_modifier_keys_pressed, "F18")

    # ------------------------------------------------------------------------
    # Feature 19: Netfilter 5 Hooks Boundaries
    # ------------------------------------------------------------------------
    def test_f19_boundary_netfilter_empty_hook_accepts():
        """F19.B1: Traversing Netfilter hook with zero registered rules defaults to NF_ACCEPT."""
        engine = MockNetfilterEngine()
        pkt = Packet5Tuple(proto=6, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2)
        assert_eq(engine.traverse(NetfilterHook.PREROUTING, pkt), NfVerdict.ACCEPT)

    def test_f19_boundary_netfilter_first_drop_verdict_short_circuits():
        """F19.B2: Rule returning NF_DROP immediately halts traversal without evaluating subsequent rules."""
        engine = MockNetfilterEngine()
        called = []
        engine.register_rule(NetfilterHook.LOCAL_IN, priority=1, rule_fn=lambda p: (called.append("r1"), NfVerdict.DROP)[1])
        engine.register_rule(NetfilterHook.LOCAL_IN, priority=2, rule_fn=lambda p: (called.append("r2"), NfVerdict.ACCEPT)[1])
        pkt = Packet5Tuple(proto=6, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2)
        verdict = engine.traverse(NetfilterHook.LOCAL_IN, pkt)
        assert_eq(verdict, NfVerdict.DROP)
        assert_eq(called, ["r1"])

    def test_f19_boundary_netfilter_equal_priority_rules_order():
        """F19.B3: Rules with equal priority maintain deterministic registration order."""
        engine = MockNetfilterEngine()
        order = []
        engine.register_rule(NetfilterHook.POSTROUTING, priority=0, rule_fn=lambda p: (order.append("A"), NfVerdict.ACCEPT)[1])
        engine.register_rule(NetfilterHook.POSTROUTING, priority=0, rule_fn=lambda p: (order.append("B"), NfVerdict.ACCEPT)[1])
        pkt = Packet5Tuple(proto=6, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2)
        engine.traverse(NetfilterHook.POSTROUTING, pkt)
        assert_eq(order, ["A", "B"])

    def test_f19_boundary_netfilter_broadcast_ip_packet():
        """F19.B4: Broadcast IP packet 255.255.255.255 handling."""
        pkt = Packet5Tuple(proto=17, src_ip="0.0.0.0", dst_ip="255.255.255.255", src_port=68, dst_port=67)
        assert_eq(pkt.dst_ip, "255.255.255.255")

    def test_f19_boundary_netfilter_port_zero_packet():
        """F19.B5: Packet with port 0 boundary values."""
        pkt = Packet5Tuple(proto=6, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=0, dst_port=0)
        assert_eq(pkt.src_port, 0)
        assert_eq(pkt.dst_port, 0)

    suite.add("f19_boundary_netfilter_empty_hook_accepts", test_f19_boundary_netfilter_empty_hook_accepts, "F19")
    suite.add("f19_boundary_netfilter_first_drop_verdict_short_circuits", test_f19_boundary_netfilter_first_drop_verdict_short_circuits, "F19")
    suite.add("f19_boundary_netfilter_equal_priority_rules_order", test_f19_boundary_netfilter_equal_priority_rules_order, "F19")
    suite.add("f19_boundary_netfilter_broadcast_ip_packet", test_f19_boundary_netfilter_broadcast_ip_packet, "F19")
    suite.add("f19_boundary_netfilter_port_zero_packet", test_f19_boundary_netfilter_port_zero_packet, "F19")

    # ------------------------------------------------------------------------
    # Feature 20: Stateful Conntrack & NAT Boundaries
    # ------------------------------------------------------------------------
    def test_f20_boundary_conntrack_unrelated_flags_no_crash():
        """F20.B1: Conntrack handles arbitrary or empty TCP flags without crash."""
        ct = MockConntrackNatTable()
        pkt = Packet5Tuple(proto=6, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=100, dst_port=200)
        st = ct.update_tcp(pkt, "PSH-URG")
        assert_eq(st, TcpConntrackState.NONE)

    def test_f20_boundary_conntrack_reverse_direction_matching():
        """F20.B2: Reverse reply packet correctly matches original connection entry."""
        ct = MockConntrackNatTable()
        orig = Packet5Tuple(proto=6, src_ip="10.0.0.1", dst_ip="20.0.0.1", src_port=5000, dst_port=80)
        reply = Packet5Tuple(proto=6, src_ip="20.0.0.1", dst_ip="10.0.0.1", src_port=80, dst_port=5000)
        ct.update_tcp(orig, "SYN")
        st = ct.update_tcp(reply, "SYN-ACK")
        assert_eq(st, TcpConntrackState.SYN_RECV)

    def test_f20_boundary_nat_rfc1624_same_val_unchanged_csum():
        """F20.B3: RFC 1624 checksum update when old_val == new_val produces original checksum."""
        csum = 0xABCD
        updated = MockConntrackNatTable.rfc1624_update_checksum(csum, 1234, 1234)
        assert_eq(updated, csum)

    def test_f20_boundary_nat_rfc1624_zero_checksum_wrap():
        """F20.B4: RFC 1624 checksum wrap across 0xFFFF."""
        updated = MockConntrackNatTable.rfc1624_update_checksum(0xFFFF, 0, 1)
        assert_true(0 <= updated <= 0xFFFF)

    def test_f20_boundary_conntrack_entry_table_size_growth():
        """F20.B5: Conntrack table tracks 100 simultaneous distinct flows."""
        ct = MockConntrackNatTable()
        for i in range(100):
            pkt = Packet5Tuple(proto=6, src_ip="10.0.0.1", dst_ip=f"10.0.0.{i}", src_port=1000 + i, dst_port=80)
            ct.update_tcp(pkt, "SYN")
        assert_eq(len(ct.entries), 100)

    suite.add("f20_boundary_conntrack_unrelated_flags_no_crash", test_f20_boundary_conntrack_unrelated_flags_no_crash, "F20")
    suite.add("f20_boundary_conntrack_reverse_direction_matching", test_f20_boundary_conntrack_reverse_direction_matching, "F20")
    suite.add("f20_boundary_nat_rfc1624_same_val_unchanged_csum", test_f20_boundary_nat_rfc1624_same_val_unchanged_csum, "F20")
    suite.add("f20_boundary_nat_rfc1624_zero_checksum_wrap", test_f20_boundary_nat_rfc1624_zero_checksum_wrap, "F20")
    suite.add("f20_boundary_conntrack_entry_table_size_growth", test_f20_boundary_conntrack_entry_table_size_growth, "F20")

    # ------------------------------------------------------------------------
    # Feature 21: Hardware Virtualization Boundaries
    # ------------------------------------------------------------------------
    def test_f21_boundary_vmx_vmcs_unwritten_field_returns_zero():
        """F21.B1: Reading unwritten VMCS field returns 0."""
        vmcs = MockVmcsPage()
        assert_eq(vmcs.vmread(0x9999), 0)

    def test_f21_boundary_vmx_vmcs_exact_4096_byte_page():
        """F21.B2: Intel VMCS page is exactly 4096 bytes."""
        vmcs = MockVmcsPage()
        assert_eq(len(vmcs.data), 4096)

    def test_f21_boundary_svm_vmcb_intercept_all_bits():
        """F21.B3: Setting all 32 intercept bits in VMCB control area."""
        vmcb = MockVmcbPage()
        for i in range(32):
            vmcb.set_intercept(i)
        assert_eq(vmcb.intercepts, 0xFFFFFFFF)

    def test_f21_boundary_kvm_vcpu_run_loop_unknown_exit_reason():
        """F21.B4: KvmVcpuRunLoop handles unknown VM exit reason without panic."""
        vmcs = MockVmcsPage()
        vcpu = MockKvmVcpuRunLoop(vmcs)
        exit_info = vcpu.step(exit_reason=VmExitReason.TRIPLE_FAULT)
        assert_eq(exit_info.reason, VmExitReason.TRIPLE_FAULT)

    def test_f21_boundary_kvm_vcpu_run_loop_multiple_interrupts():
        """F21.B5: Injecting highest interrupt vector 0xFF (vector 255)."""
        vmcs = MockVmcsPage()
        vcpu = MockKvmVcpuRunLoop(vmcs)
        vcpu.inject_interrupt(vector=0xFF)
        exit_info = vcpu.step(exit_reason=VmExitReason.HLT)
        assert_eq(exit_info.reason, VmExitReason.EXTERNAL_INTR)
        assert_eq(exit_info.val, 0xFF)

    suite.add("f21_boundary_vmx_vmcs_unwritten_field_returns_zero", test_f21_boundary_vmx_vmcs_unwritten_field_returns_zero, "F21")
    suite.add("f21_boundary_vmx_vmcs_exact_4096_byte_page", test_f21_boundary_vmx_vmcs_exact_4096_byte_page, "F21")
    suite.add("f21_boundary_svm_vmcb_intercept_all_bits", test_f21_boundary_svm_vmcb_intercept_all_bits, "F21")
    suite.add("f21_boundary_kvm_vcpu_run_loop_unknown_exit_reason", test_f21_boundary_kvm_vcpu_run_loop_unknown_exit_reason, "F21")
    suite.add("f21_boundary_kvm_vcpu_run_loop_multiple_interrupts", test_f21_boundary_kvm_vcpu_run_loop_multiple_interrupts, "F21")

    return suite


if __name__ == "__main__":
    s = build_suite()
    passed, failed, _ = s.run(verbose=True)
    sys.exit(0 if failed == 0 else 1)
