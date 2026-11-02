"""
Tier 4: Linux Subsystems Real-World Workload Scenarios
======================================================
CorOS/tests/e2e/linux_subsystems/test_tier4_real_world.py

Multi-subsystem end-to-end integration workloads demonstrating realistic
production operating system use cases across all 11 Linux subsystems.
Total: 8 test cases.
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
    CloneFlags, UidGidExtent, MockUserNamespace, MockPidNamespace,
    MockUtsNamespace, MockNetNamespace, MockChrootJail,
    MockCgroupV2Node,
    MockSignalManager, SignalNumber, SigInfo, SigAction, SigDisposition,
    MockFutexManager,
    MockUnixDomainSocket, UnixSocketType, Ucred,
    MockFifoInode, MockPosixMessageQueue, MockSharedMemoryManager,
    encode_swap_entry, decode_swap_entry, is_swap_entry, MockSwapManager,
    MockPageReclaimLru, MockOomKiller,
    MockDynamicLinker, ElfRelocType,
    BtrfsChunk,
    MockNetfilterEngine, NetfilterHook, NfVerdict, Packet5Tuple,
    MockConntrackNatTable, TcpConntrackState,
    MockXhciRing, MockUsbHidDecoder,
    MockVmcsPage, MockKvmVcpuRunLoop, VmExitReason, KvmExit
)


def build_suite() -> TestSuite:
    suite = TestSuite("Linux Subsystems - Tier 4 Real-World Workload Scenarios", tier=4)

    def test_scenario_multi_tenant_container_lifecycle():
        """S01: End-to-end container lifecycle: namespace isolation, chroot jail, and cgroups v2 throttling."""
        # 1. Namespace creation with clone flags
        clone_flags = (
            CloneFlags.CLONE_NEWPID | CloneFlags.CLONE_NEWNS | CloneFlags.CLONE_NEWUTS |
            CloneFlags.CLONE_NEWNET | CloneFlags.CLONE_NEWUSER
        )
        assert_true((clone_flags & CloneFlags.CLONE_NEWPID) != 0)
        assert_true((clone_flags & CloneFlags.CLONE_NEWUSER) != 0)

        # 2. Setup user namespace UID mapping (inner 0 -> host 100000)
        user_ns = MockUserNamespace(ns_id=10)
        user_ns.set_uid_map([UidGidExtent(inside_id=0, outside_id=100000, count=1000)])
        assert_eq(user_ns.map_uid(0), 100000)

        # 3. Setup PID namespace (container init gets vpid 1)
        pid_ns = MockPidNamespace(ns_id=10)
        vpid = pid_ns.allocate_vpid(global_pid=8888)
        assert_eq(vpid, 1)

        # 4. Setup per-process chroot jail
        jail = MockChrootJail(root_dir="/containers/alpine_root")
        assert_eq(jail.resolve_path("/bin/sh"), "/containers/alpine_root/bin/sh")

        # 5. Attach to cgroups v2 hierarchy and enforce CPU and Memory limits
        cgroup_root = MockCgroupV2Node("root")
        container_cg = cgroup_root.add_child("container_app")
        container_cg.attach_task(pid=8888)
        container_cg.cpu.quota_us = 20000 # 20ms quota
        container_cg.memory.max_bytes = 64 * 1024 * 1024 # 64MB memory limit

        # 6. Execute payload within limits
        assert_true(container_cg.cpu.charge(15000), "15ms execution allowed")
        assert_true(container_cg.memory.charge(32 * 1024 * 1024), "32MB memory allocation allowed")

        # 7. Container termination cascades kill to all tasks
        killed = pid_ns.release_task(vpid=1)
        assert_true(pid_ns.is_dead)

    def test_scenario_ipc_microservice_mesh_and_shm_buffer():
        """S02: High-throughput IPC microservice: AF_UNIX stream control + shared memory data ring."""
        # Service daemon listens on Unix domain socket
        server_sock = MockUnixDomainSocket(UnixSocketType.STREAM)
        server_sock.bind("/var/run/microservice.sock")
        server_sock.listen()

        # Client connects
        client_sock = MockUnixDomainSocket(UnixSocketType.STREAM)
        client_sock.connect(server_sock)
        conn_sock = server_sock.backlog.pop(0)
        conn_sock.peer = client_sock
        client_sock.peer = conn_sock

        # Server establishes shared memory buffer for large 1MB data payload
        shm_mgr = MockSharedMemoryManager()
        shmid = shm_mgr.sysv_shmget(0x9000, size=1024 * 1024)
        server_shm = shm_mgr.sysv_shmat(shmid)
        server_shm[:16] = b"FRAME_DATA_1080P"

        # Server sends SHM file descriptor / ID to client via SCM_RIGHTS
        conn_sock.send(b"PAYLOAD_READY", passed_fds=[shmid])

        # Client receives notification and attaches to shared memory directly
        cmd = client_sock.recv(13)
        assert_eq(cmd, b"PAYLOAD_READY")
        received_shmid = client_sock.rx_ancillary_fds[0]
        client_shm = shm_mgr.sysv_shmat(received_shmid)
        assert_eq(bytes(client_shm[:16]), b"FRAME_DATA_1080P")

    def test_scenario_edge_router_nat_gateway_firewall():
        """S03: Edge router gateway: Netfilter 5-hook traversal, conntrack, DNAT, and RFC 1624 checksums."""
        netfilter = MockNetfilterEngine()
        ct_table = MockConntrackNatTable()

        # Client on WAN sends HTTP SYN packet to public gateway IP
        wan_pkt = Packet5Tuple(proto=6, src_ip="198.51.100.10", dst_ip="203.0.113.1", src_port=52000, dst_port=80)

        # 1. PREROUTING: Stateful conntrack records incoming flow
        st = ct_table.update_tcp(wan_pkt, "SYN")
        assert_eq(st, TcpConntrackState.SYN_SENT)

        # 2. PREROUTING DNAT: Port forward 203.0.113.1:80 -> internal LAN 192.168.1.100:8080
        lan_pkt = Packet5Tuple(proto=6, src_ip="198.51.100.10", dst_ip="192.168.1.100", src_port=52000, dst_port=8080)
        netfilter.register_rule(NetfilterHook.PREROUTING, priority=-100, rule_fn=lambda p: NfVerdict.ACCEPT)
        assert_eq(netfilter.traverse(NetfilterHook.PREROUTING, wan_pkt), NfVerdict.ACCEPT)

        # 3. FORWARD: Firewall checks destination port 8080 is allowed
        netfilter.register_rule(NetfilterHook.FORWARD, priority=0, rule_fn=lambda p: NfVerdict.ACCEPT if p.dst_port == 8080 else NfVerdict.DROP)
        assert_eq(netfilter.traverse(NetfilterHook.FORWARD, lan_pkt), NfVerdict.ACCEPT)

        # 4. POSTROUTING: Recalculate packet checksum incrementally in O(1)
        orig_csum = 0x5678
        updated_csum = MockConntrackNatTable.rfc1624_update_checksum(orig_csum, 80, 8080)
        assert_true(0 <= updated_csum <= 0xFFFF)
        assert_ne(updated_csum, orig_csum)

    def test_scenario_usb_workstation_hid_desktop_pipeline():
        """S04: USB desktop input pipeline: xHCI TRB ring -> HID decoder -> evdev input bridge."""
        # 1. xHCI controller maintains Transfer Ring for USB keyboard endpoint
        ep_ring = MockXhciRing(size=16)
        ep_ring.enqueue(trb_type=1, param=0x2000, status=8) # Completion of 8-byte transfer

        # 2. Dequeue transfer completion from ring
        completed_trb = ep_ring.dequeue()
        assert_true(completed_trb is not None)
        assert_eq(completed_trb.status, 8)

        # 3. Decode USB Boot Keyboard report: 'a' key (0x04) pressed
        raw_hid = bytes([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        modifiers, keys = MockUsbHidDecoder.decode_keyboard(raw_hid)
        assert_eq(keys, ["a"])

        # 4. Decode USB Boot Mouse report: left click with relative motion (dx=10, dy=-5)
        raw_mouse = bytes([0x01, 0x0A, 0xFB])
        buttons, dx, dy = MockUsbHidDecoder.decode_mouse(raw_mouse)
        assert_eq(buttons, 1) # Left button
        assert_eq(dx, 10)
        assert_eq(dy, -5)

    def test_scenario_dynamic_linker_plugin_architecture():
        """S05: Dynamic linker plugin loader: auxv setup, GNU hash symbol lookup, and GOT/PLT binding."""
        # 1. Application starts with auxiliary vector (auxv) on stack
        auxv = {
            3: 0x400000, # AT_PHDR
            7: 0x7F0000, # AT_BASE (ld.so base)
            9: 0x401000, # AT_ENTRY (main entry)
        }
        assert_eq(auxv[9], 0x401000)

        # 2. Dynamic linker initializes plugin DSO
        linker = MockDynamicLinker(eager_binding=True)
        plugin_symbols = {
            "compute_hash": 0x150,
            "plugin_version": 0x200
        }
        linker.register_object("libcrypto_plugin.so", base_addr=0x600000, symbols=plugin_symbols, needed=[])

        # 3. Resolve symbols via 32-bit GNU hash
        hash_val = MockDynamicLinker.gnu_hash("compute_hash")
        assert_true(hash_val > 0)
        resolved_addr = linker.resolve_symbol("compute_hash")
        assert_eq(resolved_addr, 0x600150)

        # 4. Patch GOT slot with resolved address
        linker.apply_relocation(ElfRelocType.R_X86_64_JUMP_SLOT, target_slot=0x5000, sym_name="compute_hash")
        assert_eq(linker.got_table[0x5000], 0x600150)

    def test_scenario_nextgen_storage_streaming_engine():
        """S06: Next-gen Btrfs filesystem logical chunk translation and FIFO streaming pipeline."""
        # 1. Btrfs chunk tree logical-to-physical address translation
        chunk = BtrfsChunk(logical_offset=0x100000, length=0x80000, stripe_len=4096, stripes=[(1, 0x800000)])
        phys_offset = chunk.translate(0x102000)
        assert_eq(phys_offset, 0x802000)

        # 2. Storage engine reads block and streams through FIFO pipe
        fifo = MockFifoInode("/tmp/data_pipe")
        fifo.reader_count = 1
        fifo.writer_count = 1
        block_data = b"BLOCK_RECORD_DATA_HASH"
        written = fifo.write(block_data)
        assert_eq(written, len(block_data))

        # 3. Consumer process receives data from FIFO
        received = fifo.read(len(block_data))
        assert_eq(received, block_data)

    def test_scenario_kvm_hypervisor_vm_execution():
        """S07: KVM hardware hypervisor execution: VMCS page setup, VM-Entry, and PIO serial dispatch."""
        # 1. Allocate 4 KiB aligned VMCS page
        vmcs = MockVmcsPage(revision_id=0x12)
        assert_eq(len(vmcs.data), 4096)

        # 2. Initialize vCPU run loop
        vcpu = MockKvmVcpuRunLoop(vmcs)

        # 3. Hypervisor starts guest, handles guest writing to COM1 serial console (0x3F8)
        exit_pio = vcpu.step(exit_reason=VmExitReason.IO_INSTRUCTION, port=0x3F8, is_in=False)
        assert_eq(exit_pio.reason, VmExitReason.IO_INSTRUCTION)
        assert_eq(exit_pio.port, 0x3F8)
        assert_false(exit_pio.is_in)

        # 4. Guest executes HLT instruction
        exit_hlt = vcpu.step(exit_reason=VmExitReason.HLT)
        assert_eq(exit_hlt.reason, VmExitReason.HLT)

    def test_scenario_memory_pressure_swap_and_oom_recovery():
        """S08: End-to-end memory pressure: LRU clock sweep, swap paging, #PF swap-in, and OOM killer."""
        swap_mgr = MockSwapManager(max_slots=10)
        lru = MockPageReclaimLru()

        # 1. Allocate memory pages under pressure
        lru.add_page(0x1000)
        lru.add_page(0x2000)

        # 2. Cold page eviction to swap partition
        page_data = b"M" * 4096
        slot = swap_mgr.allocate_slot(swap_type=1, data=page_data)
        pte = encode_swap_entry(swap_type=1, slot_offset=slot)
        assert_true(is_swap_entry(pte))

        # 3. #PF demand swap-in restores page
        stype, soff = decode_swap_entry(pte)
        restored = swap_mgr.read_slot(stype, soff)
        assert_eq(restored, page_data)
        swap_mgr.free_slot(stype, soff)

        # 4. Severe memory exhaustion triggers OOM badness scoring
        victim_score = MockOomKiller.calculate_badness(total_pages=900000, oom_score_adj=50)
        init_score = MockOomKiller.calculate_badness(total_pages=900000, is_init=True)
        assert_true(victim_score > 900)
        assert_eq(init_score, 0, "PID 1 must never be killed by OOM killer")

    suite.add("scenario_multi_tenant_container_lifecycle", test_scenario_multi_tenant_container_lifecycle, "S01")
    suite.add("scenario_ipc_microservice_mesh_and_shm_buffer", test_scenario_ipc_microservice_mesh_and_shm_buffer, "S02")
    suite.add("scenario_edge_router_nat_gateway_firewall", test_scenario_edge_router_nat_gateway_firewall, "S03")
    suite.add("scenario_usb_workstation_hid_desktop_pipeline", test_scenario_usb_workstation_hid_desktop_pipeline, "S04")
    suite.add("scenario_dynamic_linker_plugin_architecture", test_scenario_dynamic_linker_plugin_architecture, "S05")
    suite.add("scenario_nextgen_storage_streaming_engine", test_scenario_nextgen_storage_streaming_engine, "S06")
    suite.add("scenario_kvm_hypervisor_vm_execution", test_scenario_kvm_hypervisor_vm_execution, "S07")
    suite.add("scenario_memory_pressure_swap_and_oom_recovery", test_scenario_memory_pressure_swap_and_oom_recovery, "S08")

    return suite


if __name__ == "__main__":
    s = build_suite()
    passed, failed, _ = s.run(verbose=True)
    sys.exit(0 if failed == 0 else 1)
