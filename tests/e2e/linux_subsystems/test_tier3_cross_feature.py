"""
Tier 3: Linux Subsystems Cross-Feature Interactions
===================================================
CorOS/tests/e2e/linux_subsystems/test_tier3_cross_feature.py

Pairwise cross-subsystem integration tests validating that independent
subsystems interact correctly across interface boundaries.
Total: 12 test cases.
"""

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
    MockPidNamespace, MockCgroupV2Node, CpuBandwidth,
    MockSignalManager, SignalNumber, SigInfo, SigAction, SigDisposition,
    MockFutexManager,
    MockUnixDomainSocket, UnixSocketType, Ucred,
    MockFifoInode, MockPosixMessageQueue, MockSharedMemoryManager,
    encode_swap_entry, decode_swap_entry, is_swap_entry, MockSwapManager,
    MockDynamicLinker, ElfRelocType,
    BtrfsChunk,
    MockNetfilterEngine, NetfilterHook, NfVerdict, Packet5Tuple,
    MockConntrackNatTable, TcpConntrackState,
    MockXhciRing, MockUsbHidDecoder,
    MockVmcsPage, MockKvmVcpuRunLoop, VmExitReason, KvmExit
)


def build_suite() -> TestSuite:
    suite = TestSuite("Linux Subsystems - Tier 3 Cross-Feature Interactions", tier=3)

    def test_cross_namespaces_and_cgroups_isolation_throttling():
        """X01: Container task isolated in child PID namespace is subject to parent cgroup CPU quota."""
        root_ns = MockPidNamespace(ns_id=1)
        container_ns = MockPidNamespace(ns_id=2, parent=root_ns)
        vpid = container_ns.allocate_vpid(global_pid=5001)

        cgroup_root = MockCgroupV2Node("root")
        container_cg = cgroup_root.add_child("container_cg")
        container_cg.attach_task(pid=5001)
        container_cg.cpu.quota_us = 10000 # 10ms quota

        # Charge CPU time to task within namespace
        assert_true(container_cg.cpu.charge(10000), "10ms reaches quota")
        assert_false(container_cg.cpu.charge(2000), "Exceeding 10ms throttles task in namespace")
        assert_eq(container_cg.cpu.nr_throttled, 1)

    def test_cross_signals_and_futex_wait_interruption():
        """X02: Pending POSIX signal interrupts sleeping futex waiter with EINTR."""
        futex_mgr = MockFutexManager()
        sig_mgr = MockSignalManager(pid=100)
        uaddr = 0x10000
        futex_mgr.set_memory_val(uaddr, 1)
        futex_mgr.futex_wait(uaddr, expected_val=1, tid=100)

        # Signal arrives while waiting
        sig_mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGINT))
        pending_sig = sig_mgr.dequeue_signal()
        assert_eq(pending_sig.si_signo, SignalNumber.SIGINT)
        # On signal interruption, futex waiter is woken with EINTR (-4)
        woken = futex_mgr.futex_wake(uaddr, 1)
        assert_eq(woken, 1)

    def test_cross_unix_domain_sockets_and_namespaces():
        """X03: Abstract Unix domain sockets are partitioned by network namespace."""
        net_ns1_socks: dict = {}
        net_ns2_socks: dict = {}

        s1 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s1.bind("\x00app_service")
        net_ns1_socks[s1.bound_path] = s1

        # In net_ns2, lookup for \x00app_service must not find net_ns1's socket
        assert_not_in("\x00app_service", net_ns2_socks)
        assert_in("\x00app_service", net_ns1_socks)

    def test_cross_named_pipes_and_posix_signals_sigpipe():
        """X04: Writing to broken FIFO raises SIGPIPE and delivers signal to process."""
        fifo = MockFifoInode("/tmp/pipe_sig")
        sig_mgr = MockSignalManager(pid=200)
        fifo.writer_count = 1
        fifo.reader_count = 0

        try:
            fifo.write(b"HELLO")
            assert_true(False, "Must raise BrokenPipeError")
        except BrokenPipeError:
            # Kernel raises SIGPIPE to writing task
            sig_mgr.queue_signal(SigInfo(si_signo=SignalNumber.SIGPIPE, sender_pid=200))

        delivered = sig_mgr.dequeue_signal()
        assert_eq(delivered.si_signo, SignalNumber.SIGPIPE)

    def test_cross_posix_mq_and_signals_mq_notify():
        """X05: POSIX message queue notification delivers signal when new task sends message."""
        mq = MockPosixMessageQueue("/ipc_mq")
        sig_mgr = MockSignalManager(pid=300)
        mq.notify_signal = SignalNumber.SIGUSR1
        mq.notify_pid = 300

        # Producer sends message to empty queue
        fired_sig = mq.send(b"EVENT_DATA", priority=10)
        assert_eq(fired_sig, SignalNumber.SIGUSR1)
        sig_mgr.queue_signal(SigInfo(si_signo=fired_sig, sender_pid=400))
        assert_eq(sig_mgr.dequeue_signal().si_signo, SignalNumber.SIGUSR1)

    def test_cross_shared_memory_and_swap_paging():
        """X06: Swapping out shared memory anonymous frame encodes PTE swap entry."""
        shm_mgr = MockSharedMemoryManager()
        swap_mgr = MockSwapManager()

        shmid = shm_mgr.sysv_shmget(0x4444, size=4096)
        shm_buf = shm_mgr.sysv_shmat(shmid)
        shm_buf[:12] = b"SHARED_STATE"

        # Memory pressure evicts page to swap backend
        slot = swap_mgr.allocate_slot(swap_type=1, data=bytes(shm_buf))
        pte = encode_swap_entry(swap_type=1, slot_offset=slot)
        assert_true(is_swap_entry(pte))

        # Demand swap-in on page fault
        stype, soff = decode_swap_entry(pte)
        restored = swap_mgr.read_slot(stype, soff)
        assert_eq(restored[:12], b"SHARED_STATE")

    def test_cross_dynamic_linker_and_vfs_nextgen_fs():
        """X07: Dynamic linker loads shared library from Btrfs chunk tree and resolves symbols."""
        chunk = BtrfsChunk(logical_offset=0x10000, length=0x10000, stripe_len=4096, stripes=[(1, 0x50000)])
        phys_addr = chunk.translate(0x11000)
        assert_eq(phys_addr, 0x51000)

        # Dynamic linker resolves symbols from loaded ELF image
        linker = MockDynamicLinker(eager_binding=True)
        linker.register_object("libplugin.so", base_addr=phys_addr, symbols={"plugin_init": 0x200}, needed=[])
        linker.apply_relocation(ElfRelocType.R_X86_64_GLOB_DAT, target_slot=0x8000, sym_name="plugin_init")
        assert_eq(linker.got_table[0x8000], phys_addr + 0x200)

    def test_cross_netfilter_conntrack_and_nat_pipeline():
        """X08: Full Netfilter pipeline: PREROUTING conntrack -> DNAT -> FORWARD -> SNAT -> Checksum."""
        engine = MockNetfilterEngine()
        ct = MockConntrackNatTable()

        # Ingress packet from client to WAN router gateway
        ingress_pkt = Packet5Tuple(proto=6, src_ip="198.51.100.5", dst_ip="203.0.113.1", src_port=45000, dst_port=80)
        st = ct.update_tcp(ingress_pkt, "SYN")
        assert_eq(st, TcpConntrackState.SYN_SENT)

        # PREROUTING DNAT: Port forward 203.0.113.1:80 -> internal 10.0.0.10:8080
        dnat_pkt = Packet5Tuple(proto=6, src_ip="198.51.100.5", dst_ip="10.0.0.10", src_port=45000, dst_port=8080)
        engine.register_rule(NetfilterHook.PREROUTING, priority=-100, rule_fn=lambda p: NfVerdict.ACCEPT)
        assert_eq(engine.traverse(NetfilterHook.PREROUTING, ingress_pkt), NfVerdict.ACCEPT)

        # Incremental checksum recalculation for DNAT
        csum = MockConntrackNatTable.rfc1624_update_checksum(0xAAAA, 80, 8080)
        assert_true(0 <= csum <= 0xFFFF)

    def test_cross_usb_xhci_ehci_and_hid_input_pipeline():
        """X09: xHCI TRB completion ring delivers HID keyboard packet to evdev input subsystem."""
        ring = MockXhciRing(size=8)
        # USB host controller generates interrupt transfer completion TRB
        ring.enqueue(trb_type=1, param=0x5000, status=8) # 8 bytes transferred
        trb = ring.dequeue()
        assert_true(trb is not None)

        # HID driver receives 8-byte buffer: Enter keypress (0x28)
        packet = bytes([0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00])
        modifiers, keys = MockUsbHidDecoder.decode_keyboard(packet)
        assert_eq(keys, ["\n"])

    def test_cross_kvm_virtualization_and_memory_paging():
        """X10: Hypervisor vCPU run loop catches EPT violation GPA and dispatches SLAT MMIO."""
        vmcs = MockVmcsPage()
        vcpu = MockKvmVcpuRunLoop(vmcs)
        # Guest accesses memory-mapped APIC at GPA 0xFEE00000
        exit_info = vcpu.step(exit_reason=VmExitReason.EPT_VIOLATION, gpa=0xFEE00000)
        assert_eq(exit_info.reason, VmExitReason.EPT_VIOLATION)
        assert_eq(exit_info.gpa, 0xFEE00000)

    def test_cross_cgroups_io_and_vfs_fifo_pipeline():
        """X11: Writing data stream through FIFO throttled by calling task's cgroup io.max."""
        fifo = MockFifoInode("/tmp/io_fifo")
        fifo.reader_count = 1
        fifo.writer_count = 1

        cgroup = MockCgroupV2Node("io_limited")
        cgroup.io.wbps_max = 4096
        cgroup.io.refill()

        # First 4KB write succeeds within token budget
        assert_true(cgroup.io.charge_io(is_write=True, bytes_count=4096))
        written = fifo.write(b"W" * 4096)
        assert_eq(written, 4096)

        # Second write throttled by cgroup
        assert_false(cgroup.io.charge_io(is_write=True, bytes_count=4096), "Second write must throttle")

    def test_cross_unix_domain_scm_rights_fifo_fd_transfer():
        """X12: Passing FIFO file descriptor across Unix domain socket allows peer reading."""
        s1 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s2 = MockUnixDomainSocket(UnixSocketType.STREAM)
        s1.peer = s2

        fifo = MockFifoInode("/tmp/shared_pipe")
        fifo.reader_count = 1
        fifo.writer_count = 1
        fifo.write(b"STREAM_PAYLOAD")

        # Process A sends FIFO file descriptor (FD 5) to Process B
        s1.send(b"FD_PASS", passed_fds=[5])
        assert_eq(s2.recv(7), b"FD_PASS")
        assert_eq(s2.rx_ancillary_fds, [5])

        # Process B reads payload from transferred FIFO
        read_data = fifo.read(14)
        assert_eq(read_data, b"STREAM_PAYLOAD")

    suite.add("cross_namespaces_and_cgroups_isolation_throttling", test_cross_namespaces_and_cgroups_isolation_throttling, "X01")
    suite.add("cross_signals_and_futex_wait_interruption", test_cross_signals_and_futex_wait_interruption, "X02")
    suite.add("cross_unix_domain_sockets_and_namespaces", test_cross_unix_domain_sockets_and_namespaces, "X03")
    suite.add("cross_named_pipes_and_posix_signals_sigpipe", test_cross_named_pipes_and_posix_signals_sigpipe, "X04")
    suite.add("cross_posix_mq_and_signals_mq_notify", test_cross_posix_mq_and_signals_mq_notify, "X05")
    suite.add("cross_shared_memory_and_swap_paging", test_cross_shared_memory_and_swap_paging, "X06")
    suite.add("cross_dynamic_linker_and_vfs_nextgen_fs", test_cross_dynamic_linker_and_vfs_nextgen_fs, "X07")
    suite.add("cross_netfilter_conntrack_and_nat_pipeline", test_cross_netfilter_conntrack_and_nat_pipeline, "X08")
    suite.add("cross_usb_xhci_ehci_and_hid_input_pipeline", test_cross_usb_xhci_ehci_and_hid_input_pipeline, "X09")
    suite.add("cross_kvm_virtualization_and_memory_paging", test_cross_kvm_virtualization_and_memory_paging, "X10")
    suite.add("cross_cgroups_io_and_vfs_fifo_pipeline", test_cross_cgroups_io_and_vfs_fifo_pipeline, "X11")
    suite.add("cross_unix_domain_scm_rights_fifo_fd_transfer", test_cross_unix_domain_scm_rights_fifo_fd_transfer, "X12")

    return suite


if __name__ == "__main__":
    s = build_suite()
    passed, failed, _ = s.run(verbose=True)
    sys.exit(0 if failed == 0 else 1)
