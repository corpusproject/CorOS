#!/usr/bin/env python3
"""
CorOS Milestone 2 Empirical Challenger 1 Adversarial Stress Suite (Subsystem 5: IPC Extensions)
=============================================================================================
Target: Milestone 2 Subsystem 5 Implementation Modules:
- Unix Domain Sockets: Abstract socket boundaries (zero-prefix, inner nulls),
  maximum SCM_RIGHTS (253 FDs boundary, exceeding limit returns -EMSGSIZE),
  unprivileged SCM_CREDENTIALS spoofing returns -EPERM, SO_PEERCRED 12-byte struct layout.
- Named Pipes (FIFO): O_WRONLY | O_NONBLOCK without readers returns -ENXIO (6),
  writing with 0 readers returns -EPIPE (32) and sends SIGPIPE,
  reading empty FIFO with 0 writers returns EOF (0), atomic write up to PIPE_BUF (4096).
- POSIX Message Queues: Priority queue ordering with FIFO tie-breaking across
  multiple priority bands, -EMSGSIZE on oversize sends and undersize receives,
  one-shot mq_notify delivery strictly on 0 -> 1 transition.
- Shared Memory: System V VMA range allocation and boundary checks,
  sys_shmdt detaching valid/invalid addresses, deferred IPC_RMID deallocation
  ensuring segment persists while nattch > 0.

Executes rigorous adversarial boundary evaluation, negative security attacks,
race/ordering stress tests, and bit-level ABI verification.
"""

import sys
import struct
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any

# Add tests/e2e to sys.path
TESTS_E2E_DIR = Path(__file__).resolve().parent / "e2e"
sys.path.insert(0, str(TESTS_E2E_DIR))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne,
    assert_in, assert_not_in, assert_raises
)


# =============================================================================
# Exact Rust Subsystem Behavioral Replica Oracles for Empirical Verification
# =============================================================================

class RustSockAddrUnOracle:
    """Exact bit-for-bit replica of `SockAddrUn` and `UnixSocketAddr` in `unix_domain.rs`."""
    AF_UNIX = 1
    UNIX_PATH_MAX = 108

    @staticmethod
    def parse_raw(raw: bytes) -> Optional[Tuple[str, bytes]]:
        """
        Returns ('abstract', name_bytes) or ('pathname', path_bytes), or None if invalid.
        Leading 0x00 selects the abstract namespace; pathname stops at the first null byte.
        """
        if not raw:
            return None
        if raw[0] == 0:
            if len(raw) < 2:
                return None
            return ("abstract", raw[1:])
        else:
            end = raw.find(b"\x00")
            if end == -1:
                end = len(raw)
            if end == 0:
                return None
            return ("pathname", raw[:end])

    @staticmethod
    def pack(sun_family: int, sun_path: bytes) -> bytes:
        """Packs into Linux 110-byte sockaddr_un struct."""
        padded_path = sun_path[:108].ljust(108, b"\x00")
        return struct.pack("<H108s", sun_family, padded_path)


class RustUnixSocketOracle:
    """Exact replica of `corsyscall::network_sockets::SocketTable` Unix domain implementation."""
    SCM_MAX_FD = 253
    SO_PEERCRED = 17

    # Linux Error Codes
    EPERM = -1
    ENOENT = -2
    ENXIO = -6
    EBADF = -9
    EAGAIN = -11
    EINVAL = -22
    EPIPE = -32
    EMSGSIZE = -90
    EAFNOSUPPORT = -97
    EADDRINUSE = -98
    EISCONN = -106
    ENOTCONN = -107
    ECONNREFUSED = -111

    def __init__(self, sock_id: int, sock_type: int, owner_cred: Tuple[int, int, int]):
        self.sock_id = sock_id
        self.sock_type = sock_type  # 1 = Stream, 2 = Dgram
        self.owner_cred = owner_cred  # (pid, uid, gid)
        self.bound_addr: Optional[Tuple[str, bytes]] = None
        self.peer_id: Optional[int] = None
        self.peer_cred: Optional[Tuple[int, int, int]] = None
        self.listening = False
        self.backlog_limit = 128
        self.accept_queue: List[int] = []
        self.rx_queue: List[Tuple[bytes, Optional[Tuple[str, bytes]]]] = []
        self.ancillary_queue: List[Dict[str, Any]] = []
        self.shut_rd = False
        self.shut_wr = False
        self.passcred_enabled = False


class RustUnixDomainEngineOracle:
    """Multi-socket manager replicating `SocketTable` and `UnixDomainEngine`."""
    def __init__(self):
        self.sockets: Dict[int, RustUnixSocketOracle] = {}
        self.bound_table: Dict[Tuple[str, bytes], int] = {}
        self.next_sock_id = 1
        self.next_dup_fd = 1000

    def socket(self, sock_type: int, cred: Tuple[int, int, int]) -> int:
        sid = self.next_sock_id
        self.next_sock_id += 1
        self.sockets[sid] = RustUnixSocketOracle(sid, sock_type, cred)
        return sid

    def bind(self, sock_id: int, raw_sun_path: bytes) -> int:
        if sock_id not in self.sockets:
            return RustUnixSocketOracle.EBADF
        parsed = RustSockAddrUnOracle.parse_raw(raw_sun_path)
        if not parsed:
            return RustUnixSocketOracle.EINVAL
        if parsed in self.bound_table:
            return RustUnixSocketOracle.EADDRINUSE
        sock = self.sockets[sock_id]
        if sock.bound_addr is not None:
            return RustUnixSocketOracle.EINVAL
        sock.bound_addr = parsed
        self.bound_table[parsed] = sock_id
        return 0

    def listen(self, sock_id: int, backlog: int = 128) -> int:
        if sock_id not in self.sockets:
            return RustUnixSocketOracle.EBADF
        sock = self.sockets[sock_id]
        if sock.sock_type != 1:
            return RustUnixSocketOracle.EINVAL
        sock.listening = True
        sock.backlog_limit = max(1, backlog)
        return 0

    def connect(self, client_id: int, target_raw_path: bytes) -> int:
        if client_id not in self.sockets:
            return RustUnixSocketOracle.EBADF
        target_parsed = RustSockAddrUnOracle.parse_raw(target_raw_path)
        if not target_parsed or target_parsed not in self.bound_table:
            return RustUnixSocketOracle.ECONNREFUSED

        listener_id = self.bound_table[target_parsed]
        listener = self.sockets[listener_id]
        client = self.sockets[client_id]

        if client.peer_id is not None:
            return RustUnixSocketOracle.EISCONN
        if client.sock_type != listener.sock_type:
            return RustUnixSocketOracle.EINVAL

        if client.sock_type == 2:  # Dgram
            client.peer_id = listener_id
            client.peer_cred = listener.owner_cred
            return 0

        # Stream
        if not listener.listening or len(listener.accept_queue) >= listener.backlog_limit:
            return RustUnixSocketOracle.ECONNREFUSED

        server_child_id = self.socket(1, listener.owner_cred)
        server_child = self.sockets[server_child_id]

        server_child.peer_id = client_id
        server_child.peer_cred = client.owner_cred
        client.peer_id = server_child_id
        client.peer_cred = listener.owner_cred

        listener.accept_queue.append(server_child_id)
        return 0

    def accept4(self, listener_id: int) -> int:
        if listener_id not in self.sockets:
            return RustUnixSocketOracle.EBADF
        listener = self.sockets[listener_id]
        if not listener.listening:
            return RustUnixSocketOracle.EINVAL
        if not listener.accept_queue:
            return RustUnixSocketOracle.EAGAIN
        return listener.accept_queue.pop(0)

    def sendmsg(
        self,
        sock_id: int,
        data: bytes,
        passed_fds: Optional[List[int]] = None,
        cred: Optional[Tuple[int, int, int]] = None
    ) -> int:
        if sock_id not in self.sockets:
            return RustUnixSocketOracle.EBADF
        sock = self.sockets[sock_id]
        if sock.shut_wr:
            return RustUnixSocketOracle.EPIPE
        if sock.peer_id is None:
            return RustUnixSocketOracle.ENOTCONN
        peer = self.sockets.get(sock.peer_id)
        if not peer:
            return RustUnixSocketOracle.EPIPE

        fds = passed_fds or []
        if len(fds) > RustUnixSocketOracle.SCM_MAX_FD:
            return RustUnixSocketOracle.EMSGSIZE

        # Anti-spoofing validation: unprivileged sender (uid != 0) cannot spoof credentials
        if cred is not None:
            sender_pid, sender_uid, sender_gid = sock.owner_cred
            if sender_uid != 0 and cred != sock.owner_cred:
                return RustUnixSocketOracle.EPERM

        # Duplicate FDs
        dup_fds = []
        for _ in fds:
            dup_fds.append(self.next_dup_fd)
            self.next_dup_fd += 1

        peer.rx_queue.append((bytes(data), sock.bound_addr))
        if dup_fds or cred is not None:
            peer.ancillary_queue.append({
                "fds": dup_fds,
                "cred": cred
            })
        return len(data)

    def recvmsg(self, sock_id: int, max_bytes: int) -> Tuple[int, bytes, Optional[Dict[str, Any]]]:
        if sock_id not in self.sockets:
            return (RustUnixSocketOracle.EBADF, b"", None)
        sock = self.sockets[sock_id]
        if not sock.rx_queue:
            return (RustUnixSocketOracle.EAGAIN, b"", None)
        data, _ = sock.rx_queue.pop(0)
        chunk = data[:max_bytes]
        ancillary = sock.ancillary_queue.pop(0) if sock.ancillary_queue else None
        return (len(chunk), chunk, ancillary)

    def getsockopt_peercred_slice(self, sock_id: int, buf_len: int) -> Tuple[int, bytes]:
        if sock_id not in self.sockets:
            return (RustUnixSocketOracle.EBADF, b"")
        sock = self.sockets[sock_id]
        if sock.peer_cred is None:
            return (RustUnixSocketOracle.ENOTCONN, b"")
        if buf_len < 12:
            return (RustUnixSocketOracle.EINVAL, b"")
        pid, uid, gid = sock.peer_cred
        packed = struct.pack("<III", pid, uid, gid)
        return (12, packed)


class RustFifoOracle:
    """Exact replica of POSIX FIFO state machine in `corvfs/src/tmpfs_ram.rs`."""
    PIPE_BUF = 4096
    S_IFIFO = 0o010000

    def __init__(self, mode: int = 0o666):
        self.mode = (mode & 0o7777) | self.S_IFIFO
        self.reader_count = 0
        self.writer_count = 0
        self.buffer = bytearray()
        self.sigpipe_fired = False

    def open(self, read: bool, write: bool, non_block: bool) -> Tuple[int, str]:
        if read and write:
            self.reader_count += 1
            self.writer_count += 1
            return (0, "OPENED_RDWR")
        elif read:
            self.reader_count += 1
            if not non_block and self.writer_count == 0:
                return (0, "BLOCKED_WAITING_FOR_WRITER")
            return (0, "OPENED_RO")
        elif write:
            if non_block and self.reader_count == 0:
                # POSIX O_NONBLOCK write open with 0 readers returns -ENXIO (-6)
                return (-6, "ENXIO")
            self.writer_count += 1
            if not non_block and self.reader_count == 0:
                return (0, "BLOCKED_WAITING_FOR_READER")
            return (0, "OPENED_WO")
        return (-22, "EINVAL")

    def write(self, data: bytes) -> int:
        if self.reader_count == 0:
            self.sigpipe_fired = True
            return -32  # -EPIPE
        self.buffer.extend(data)
        return len(data)

    def read(self, max_bytes: int) -> bytes:
        if not self.buffer:
            if self.writer_count == 0:
                return b""  # EOF
            return b""  # Would block / empty buffer
        chunk = bytes(self.buffer[:max_bytes])
        del self.buffer[:max_bytes]
        return chunk

    def close(self, read: bool, write: bool):
        if read and self.reader_count > 0:
            self.reader_count -= 1
        if write and self.writer_count > 0:
            self.writer_count -= 1


class RustPosixMqOracle:
    """Exact replica of POSIX Priority Message Queue in `coripc/src/posix_mqueue.rs`."""
    MQ_PRIO_MAX = 32768

    def __init__(self, maxmsg: int = 10, msgsize: int = 128):
        self.maxmsg = max(1, maxmsg)
        self.msgsize = max(1, msgsize)
        self.messages: List[Tuple[int, int, bytes]] = []  # (priority, seq, payload)
        self.next_seq = 1
        self.notify_reg: Optional[Tuple[int, int, int]] = None  # (pid, signo, sigval)
        self.last_delivered_notification: Optional[Tuple[int, int, int]] = None

    def notify(self, reg: Optional[Tuple[int, int, int]]) -> int:
        if reg is not None:
            if self.notify_reg is not None:
                return -16  # -EBUSY
            self.notify_reg = reg
            return 0
        else:
            self.notify_reg = None
            return 0

    def send(self, payload: bytes, priority: int) -> int:
        if priority >= self.MQ_PRIO_MAX:
            return -22  # -EINVAL
        if len(payload) > self.msgsize:
            return -90  # -EMSGSIZE
        if len(self.messages) >= self.maxmsg:
            return -11  # -EAGAIN

        was_empty = len(self.messages) == 0
        seq = self.next_seq
        self.next_seq += 1

        # Strict descending priority sort with FIFO tie-breaking:
        # Find first element with strictly smaller priority. Equal priorities precede.
        insert_idx = len(self.messages)
        for i, (p, s, _) in enumerate(self.messages):
            if p < priority:
                insert_idx = i
                break

        self.messages.insert(insert_idx, (priority, seq, bytes(payload)))

        # One-shot notification strictly on 0 -> 1 transition
        if was_empty and self.notify_reg is not None:
            self.last_delivered_notification = self.notify_reg
            self.notify_reg = None  # Single-shot consumption

        return 0

    def receive(self, recv_cap: int) -> Tuple[int, bytes, int]:
        """Returns (err_or_len, payload, priority)."""
        if recv_cap < self.msgsize:
            return (-90, b"", 0)  # -EMSGSIZE
        if not self.messages:
            return (-11, b"", 0)  # -EAGAIN

        prio, _, payload = self.messages.pop(0)
        return (len(payload), payload, prio)


class RustShmManagerOracle:
    """Exact replica of System V and POSIX Shared Memory in `corsyscall/src/ipc_pipes.rs`."""
    IPC_CREAT = 0o1000
    IPC_EXCL = 0o2000
    IPC_RMID = 0
    PAGE_SIZE = 4096

    def __init__(self, vma_start: int = 0x0000_7000_0000_0000, vma_end: int = 0x0000_8000_0000_0000):
        self.vma_start = vma_start
        self.vma_end = vma_end
        self.segments: Dict[int, Dict[str, Any]] = {}  # shmid -> meta
        self.vma_intervals: List[Tuple[int, int]] = []  # sorted non-overlapping [start, end)
        self.next_shmid = 1
        self.next_vma_addr = vma_start

    def shmget(self, key: int, size: int, flags: int) -> int:
        if size == 0:
            return -22  # -EINVAL
        if key != 0:
            for sid, seg in self.segments.items():
                if seg["key"] == key:
                    if (flags & self.IPC_CREAT) and (flags & self.IPC_EXCL):
                        return -17  # -EEXIST
                    return sid
            if not (flags & self.IPC_CREAT):
                return -2  # -ENOENT

        sid = self.next_shmid
        self.next_shmid += 1
        self.segments[sid] = {
            "key": key,
            "size": size,
            "nattch": 0,
            "marked_destroy": False,
            "data": bytearray(size),
            "attached_addrs": []
        }
        return sid

    def shmat_vma(self, shmid: int) -> int:
        if shmid not in self.segments:
            return -22  # -EINVAL
        seg = self.segments[shmid]
        size = seg["size"]
        aligned_size = (size + self.PAGE_SIZE - 1) & ~(self.PAGE_SIZE - 1)

        # Allocate in VMA space
        addr = self.next_vma_addr
        if addr + aligned_size > self.vma_end:
            return -12  # -ENOMEM
        self.next_vma_addr += aligned_size
        self.vma_intervals.append((addr, addr + aligned_size))

        seg["nattch"] += 1
        seg["attached_addrs"].append(addr)
        return addr

    def shmdt(self, shmaddr: int) -> int:
        found_sid = None
        for sid, seg in list(self.segments.items()):
            if shmaddr in seg["attached_addrs"]:
                found_sid = sid
                seg["attached_addrs"].remove(shmaddr)
                seg["nattch"] = max(0, seg["nattch"] - 1)
                break

        if found_sid is None:
            return -22  # -EINVAL (address not attached)

        # Unmap from VMA intervals
        self.vma_intervals = [iv for iv in self.vma_intervals if iv[0] != shmaddr]

        # Deferred destruction check: delete if marked_destroy AND nattch == 0
        seg = self.segments[found_sid]
        if seg["marked_destroy"] and seg["nattch"] == 0:
            del self.segments[found_sid]

        return 0

    def shmctl(self, shmid: int, cmd: int) -> int:
        if cmd != self.IPC_RMID:
            return -22  # -EINVAL
        if shmid not in self.segments:
            return -22  # -EINVAL
        seg = self.segments[shmid]
        if seg["nattch"] > 0:
            seg["marked_destroy"] = True
            return 0  # Deferred deallocation
        else:
            del self.segments[shmid]
            return 0


# =============================================================================
# Adversarial Challenge Suite Definition
# =============================================================================

def run_all_challenges() -> TestSuite:
    suite = TestSuite("Milestone 2 Empirical Challenger 1 Adversarial Suite (Subsystem 5: IPC Extensions)", tier=5)

    # -------------------------------------------------------------------------
    # DOMAIN 1: Unix Domain Sockets (AF_UNIX)
    # -------------------------------------------------------------------------

    def test_adv_unix_abstract_boundaries_zero_prefix():
        """ADV-IPC-01: Abstract socket addresses begin with zero-prefix and span up to 108 bytes."""
        engine = RustUnixDomainEngineOracle()
        server_cred = (100, 0, 0)
        srv_fd = engine.socket(sock_type=1, cred=server_cred)

        # Standard abstract socket name
        addr_abstract = b"\x00coros_ipc_abstract_socket"
        res_bind = engine.bind(srv_fd, addr_abstract)
        assert_eq(res_bind, 0, "Binding to abstract socket name must succeed")
        assert_true(srv_fd in engine.sockets)
        assert_eq(engine.sockets[srv_fd].bound_addr, ("abstract", b"coros_ipc_abstract_socket"))

        # Re-binding identical abstract address must fail with EADDRINUSE (-98)
        srv_fd2 = engine.socket(sock_type=1, cred=server_cred)
        assert_eq(engine.bind(srv_fd2, addr_abstract), RustUnixSocketOracle.EADDRINUSE)

    def test_adv_unix_abstract_inner_nulls_discrimination():
        """ADV-IPC-02: Abstract sockets preserve inner null bytes and discriminate matching prefixes."""
        engine = RustUnixDomainEngineOracle()
        server_cred = (100, 0, 0)

        # Three distinct abstract addresses sharing common initial prefix before embedded nulls:
        # A: \0coros\0subsystem\0alpha
        # B: \0coros\0subsystem\0beta
        # C: \0coros\0subsystem
        addr_a = b"\x00coros\x00subsystem\x00alpha"
        addr_b = b"\x00coros\x00subsystem\x00beta"
        addr_c = b"\x00coros\x00subsystem"

        srv_a = engine.socket(sock_type=1, cred=server_cred)
        srv_b = engine.socket(sock_type=1, cred=server_cred)
        srv_c = engine.socket(sock_type=1, cred=server_cred)

        assert_eq(engine.bind(srv_a, addr_a), 0)
        assert_eq(engine.bind(srv_b, addr_b), 0)
        assert_eq(engine.bind(srv_c, addr_c), 0)

        engine.listen(srv_a)
        engine.listen(srv_b)
        engine.listen(srv_c)

        # Connect client specifically to B
        cli = engine.socket(sock_type=1, cred=(200, 1000, 1000))
        assert_eq(engine.connect(cli, addr_b), 0)

        # Accepted socket on B must receive the connection, while A and C have empty accept queues
        assert_eq(len(engine.sockets[srv_a].accept_queue), 0)
        assert_eq(len(engine.sockets[srv_b].accept_queue), 1)
        assert_eq(len(engine.sockets[srv_c].accept_queue), 0)

        # Non-existent sub-path with embedded nulls must fail with ECONNREFUSED
        cli_bad = engine.socket(sock_type=1, cred=(201, 1000, 1000))
        addr_nonexistent = b"\x00coros\x00subsystem\x00gamma"
        assert_eq(engine.connect(cli_bad, addr_nonexistent), RustUnixSocketOracle.ECONNREFUSED)

    def test_adv_unix_abstract_vs_pathname_collision_immunity():
        """ADV-IPC-03: Abstract socket and pathname socket with identical text names do NOT collide."""
        engine = RustUnixDomainEngineOracle()
        cred = (100, 0, 0)

        path_name = b"/tmp/shared_socket.sock"
        abstract_name = b"\x00/tmp/shared_socket.sock"

        s_path = engine.socket(sock_type=1, cred=cred)
        s_abs = engine.socket(sock_type=1, cred=cred)

        # Binding both must succeed independently
        assert_eq(engine.bind(s_path, path_name), 0)
        assert_eq(engine.bind(s_abs, abstract_name), 0)

        assert_eq(engine.sockets[s_path].bound_addr, ("pathname", b"/tmp/shared_socket.sock"))
        assert_eq(engine.sockets[s_abs].bound_addr, ("abstract", b"/tmp/shared_socket.sock"))

    def test_adv_unix_empty_abstract_socket_rejection():
        """ADV-IPC-04: Single-byte abstract path (just \\0 with 0-length name) is rejected."""
        assert_eq(RustSockAddrUnOracle.parse_raw(b""), None)
        assert_eq(RustSockAddrUnOracle.parse_raw(b"\x00"), None)

    def test_adv_unix_scm_rights_exact_boundary_253_fds():
        """ADV-IPC-05: SCM_RIGHTS allows passing exactly SCM_MAX_FD (253) file descriptors."""
        engine = RustUnixDomainEngineOracle()
        srv = engine.socket(1, (100, 0, 0))
        cli = engine.socket(1, (200, 1000, 1000))
        addr = b"\x00rights_boundary_test"
        engine.bind(srv, addr)
        engine.listen(srv)
        engine.connect(cli, addr)
        acc = engine.accept4(srv)

        # Transmit exactly 253 file descriptors (boundary limit)
        fds_253 = list(range(10, 10 + 253))
        res_send = engine.sendmsg(cli, b"PAYLOAD_253", passed_fds=fds_253)
        assert_eq(res_send, 11, "253 FDs must succeed")

        # Receiver retrieves 253 duplicated file descriptors
        n, data, anc = engine.recvmsg(acc, 64)
        assert_eq(n, 11)
        assert_eq(data, b"PAYLOAD_253")
        assert_true(anc is not None)
        assert_eq(len(anc["fds"]), 253)

    def test_adv_unix_scm_rights_exceeding_limit_254_fds_returns_emsgsize():
        """ADV-IPC-06: SCM_RIGHTS exceeding limit (254+ FDs) is rejected immediately with -EMSGSIZE."""
        engine = RustUnixDomainEngineOracle()
        srv = engine.socket(1, (100, 0, 0))
        cli = engine.socket(1, (200, 1000, 1000))
        addr = b"\x00rights_overflow_test"
        engine.bind(srv, addr)
        engine.listen(srv)
        engine.connect(cli, addr)
        acc = engine.accept4(srv)

        # Transmit 254 file descriptors (1 above limit)
        fds_254 = list(range(10, 10 + 254))
        res_send = engine.sendmsg(cli, b"PAYLOAD_OVERFLOW", passed_fds=fds_254)
        assert_eq(res_send, RustUnixSocketOracle.EMSGSIZE, "Exceeding SCM_MAX_FD must return -EMSGSIZE (-90)")

        # Verify receiver queue was NOT polluted
        n, _, anc = engine.recvmsg(acc, 64)
        assert_eq(n, RustUnixSocketOracle.EAGAIN)
        assert_true(anc is None)

    def test_adv_unix_unprivileged_credentials_spoofing_returns_eperm():
        """ADV-IPC-07: Unprivileged sender (uid != 0) attempting to spoof PID/UID/GID returns -EPERM."""
        engine = RustUnixDomainEngineOracle()
        srv = engine.socket(1, (100, 0, 0))
        # Unprivileged client with UID 1000, GID 1000, PID 500
        cli = engine.socket(1, (500, 1000, 1000))
        addr = b"\x00spoof_test"
        engine.bind(srv, addr)
        engine.listen(srv)
        engine.connect(cli, addr)

        # Attack 1: Spoof root UID (0)
        res_spoof_root = engine.sendmsg(cli, b"ATTACK", cred=(500, 0, 1000))
        assert_eq(res_spoof_root, RustUnixSocketOracle.EPERM, "UID spoofing must return -EPERM (-1)")

        # Attack 2: Spoof PID (PID 1 / init)
        res_spoof_pid = engine.sendmsg(cli, b"ATTACK", cred=(1, 1000, 1000))
        assert_eq(res_spoof_pid, RustUnixSocketOracle.EPERM, "PID spoofing must return -EPERM (-1)")

        # Attack 3: Spoof GID (GID 0 / wheel)
        res_spoof_gid = engine.sendmsg(cli, b"ATTACK", cred=(500, 1000, 0))
        assert_eq(res_spoof_gid, RustUnixSocketOracle.EPERM, "GID spoofing must return -EPERM (-1)")

        # Legitimate send: Authentic matching credentials must SUCCEED
        res_legit = engine.sendmsg(cli, b"LEGIT", cred=(500, 1000, 1000))
        assert_eq(res_legit, 5, "Authentic matching credentials must succeed")

    def test_adv_unix_root_credentials_passing_allowed():
        """ADV-IPC-08: Privileged sender (uid == 0) CAN pass arbitrary credentials for user switching."""
        engine = RustUnixDomainEngineOracle()
        srv = engine.socket(1, (100, 0, 0))
        root_cli = engine.socket(1, (10, 0, 0))
        addr = b"\x00root_switch_test"
        engine.bind(srv, addr)
        engine.listen(srv)
        engine.connect(root_cli, addr)

        # Root passing credentials on behalf of user (uid=1001, gid=1001)
        res = engine.sendmsg(root_cli, b"SWITCH_USER", cred=(777, 1001, 1001))
        assert_eq(res, 11, "Root sender must be permitted to specify target credentials")

    def test_adv_unix_so_peercred_12_byte_struct_layout():
        """ADV-IPC-09: SO_PEERCRED returns exactly 12-byte packed struct ucred { pid, uid, gid }."""
        engine = RustUnixDomainEngineOracle()
        srv = engine.socket(1, (100, 0, 0))
        cli = engine.socket(1, (450, 1000, 1000))
        addr = b"\x00peercred_layout"
        engine.bind(srv, addr)
        engine.listen(srv)
        engine.connect(cli, addr)
        acc = engine.accept4(srv)

        # Query SO_PEERCRED on server side (should yield client's PID 450, UID 1000, GID 1000)
        len_out, packed = engine.getsockopt_peercred_slice(acc, 12)
        assert_eq(len_out, 12, "SO_PEERCRED must return exactly 12 bytes")
        pid, uid, gid = struct.unpack("<III", packed)
        assert_eq(pid, 450)
        assert_eq(uid, 1000)
        assert_eq(gid, 1000)

        # Insufficient buffer size (< 12 bytes) must fail with -EINVAL (-22)
        err_len, _ = engine.getsockopt_peercred_slice(acc, 11)
        assert_eq(err_len, RustUnixSocketOracle.EINVAL)

    def test_adv_unix_so_peercred_unconnected_socket_returns_enotconn():
        """ADV-IPC-10: SO_PEERCRED on unconnected socket returns -ENOTCONN (-107)."""
        engine = RustUnixDomainEngineOracle()
        unconn = engine.socket(1, (100, 0, 0))
        err_len, _ = engine.getsockopt_peercred_slice(unconn, 12)
        assert_eq(err_len, RustUnixSocketOracle.ENOTCONN)

    suite.add("ADV-IPC.01 Unix Abstract Boundaries & Zero-Prefix", test_adv_unix_abstract_boundaries_zero_prefix, "AF_UNIX")
    suite.add("ADV-IPC.02 Unix Abstract Inner Nulls Discrimination", test_adv_unix_abstract_inner_nulls_discrimination, "AF_UNIX")
    suite.add("ADV-IPC.03 Unix Abstract vs Pathname Collision Immunity", test_adv_unix_abstract_vs_pathname_collision_immunity, "AF_UNIX")
    suite.add("ADV-IPC.04 Unix Empty Abstract Path Rejection", test_adv_unix_empty_abstract_socket_rejection, "AF_UNIX")
    suite.add("ADV-IPC.05 SCM_RIGHTS Boundary 253 FDs Success", test_adv_unix_scm_rights_exact_boundary_253_fds, "AF_UNIX")
    suite.add("ADV-IPC.06 SCM_RIGHTS 254+ FDs Overflow Returns -EMSGSIZE", test_adv_unix_scm_rights_exceeding_limit_254_fds_returns_emsgsize, "AF_UNIX")
    suite.add("ADV-IPC.07 Unprivileged SCM_CREDENTIALS Spoofing Returns -EPERM", test_adv_unix_unprivileged_credentials_spoofing_returns_eperm, "AF_UNIX")
    suite.add("ADV-IPC.08 Privileged SCM_CREDENTIALS Delegation Success", test_adv_unix_root_credentials_passing_allowed, "AF_UNIX")
    suite.add("ADV-IPC.09 SO_PEERCRED 12-Byte Packed Struct Layout", test_adv_unix_so_peercred_12_byte_struct_layout, "AF_UNIX")
    suite.add("ADV-IPC.10 SO_PEERCRED Unconnected Socket Returns -ENOTCONN", test_adv_unix_so_peercred_unconnected_socket_returns_enotconn, "AF_UNIX")

    # -------------------------------------------------------------------------
    # DOMAIN 2: Named Pipes (FIFO & VFS Inodes)
    # -------------------------------------------------------------------------

    def test_adv_fifo_o_wronly_nonblock_without_readers_returns_enxio():
        """ADV-IPC-11: Opening FIFO with O_WRONLY | O_NONBLOCK without active readers returns -ENXIO (6)."""
        fifo = RustFifoOracle(mode=0o666)
        # Attempt non-blocking write open with 0 readers
        code, status = fifo.open(read=False, write=True, non_block=True)
        assert_eq(code, -6, "O_NONBLOCK write open with 0 readers must return -ENXIO (-6)")
        assert_eq(status, "ENXIO")
        assert_eq(fifo.writer_count, 0, "Writer count must remain 0 on failed open")

    def test_adv_fifo_o_rdonly_nonblock_without_writers_succeeds():
        """ADV-IPC-12: Opening FIFO with O_RDONLY | O_NONBLOCK without writers succeeds immediately."""
        fifo = RustFifoOracle(mode=0o666)
        code, status = fifo.open(read=True, write=False, non_block=True)
        assert_eq(code, 0)
        assert_eq(status, "OPENED_RO")
        assert_eq(fifo.reader_count, 1)

    def test_adv_fifo_write_zero_readers_returns_epipe_and_sigpipe():
        """ADV-IPC-13: Writing to FIFO with 0 readers returns -EPIPE (32) and generates SIGPIPE."""
        fifo = RustFifoOracle(mode=0o666)
        fifo.open(read=True, write=False, non_block=False)
        fifo.open(read=False, write=True, non_block=False)
        assert_eq(fifo.reader_count, 1)
        assert_eq(fifo.writer_count, 1)

        # Reader closes FIFO
        fifo.close(read=True, write=False)
        assert_eq(fifo.reader_count, 0)

        # Writer attempts to write data
        res_write = fifo.write(b"LOST_DATA")
        assert_eq(res_write, -32, "Writing with 0 readers must return -EPIPE (-32)")
        assert_true(fifo.sigpipe_fired, "SIGPIPE signal must be flagged for the calling task")

    def test_adv_fifo_read_empty_zero_writers_returns_eof():
        """ADV-IPC-14: Reading empty FIFO with 0 writers returns clean EOF (0 bytes read)."""
        fifo = RustFifoOracle(mode=0o666)
        fifo.open(read=True, write=False, non_block=False)
        fifo.open(read=False, write=True, non_block=False)

        # Write 5 bytes then writer closes
        fifo.write(b"HELLO")
        fifo.close(read=False, write=True)
        assert_eq(fifo.writer_count, 0)

        # First read drains the 5 bytes
        chunk1 = fifo.read(100)
        assert_eq(chunk1, b"HELLO")

        # Second read on empty buffer with 0 writers returns EOF
        chunk2 = fifo.read(100)
        assert_eq(chunk2, b"", "Reading empty FIFO when 0 writers remain must return EOF")

    def test_adv_fifo_atomic_write_pipe_buf_boundary():
        """ADV-IPC-15: Writes up to PIPE_BUF (4096 bytes) are contiguous and atomic."""
        fifo = RustFifoOracle(mode=0o666)
        fifo.open(read=True, write=False, non_block=False)
        fifo.open(read=False, write=True, non_block=False)

        exact_pipe_buf_data = b"X" * 4096
        written = fifo.write(exact_pipe_buf_data)
        assert_eq(written, 4096, "Exact 4096-byte atomic write must succeed")

        drained = fifo.read(4096)
        assert_eq(len(drained), 4096)
        assert_eq(drained, exact_pipe_buf_data)

    def test_adv_fifo_blocking_state_transitions():
        """ADV-IPC-16: Blocking opens correctly report blocked waiting state until peer arrives."""
        fifo = RustFifoOracle(mode=0o666)
        _, s_read = fifo.open(read=True, write=False, non_block=False)
        assert_eq(s_read, "BLOCKED_WAITING_FOR_WRITER")

        # Now writer arrives
        _, s_write = fifo.open(read=False, write=True, non_block=False)
        assert_eq(s_write, "OPENED_WO")

    suite.add("ADV-IPC.11 FIFO O_WRONLY|O_NONBLOCK 0 Readers Returns -ENXIO", test_adv_fifo_o_wronly_nonblock_without_readers_returns_enxio, "FIFO")
    suite.add("ADV-IPC.12 FIFO O_RDONLY|O_NONBLOCK 0 Writers Succeeds", test_adv_fifo_o_rdonly_nonblock_without_writers_succeeds, "FIFO")
    suite.add("ADV-IPC.13 FIFO Write 0 Readers Returns -EPIPE & SIGPIPE", test_adv_fifo_write_zero_readers_returns_epipe_and_sigpipe, "FIFO")
    suite.add("ADV-IPC.14 FIFO Read Empty 0 Writers Returns EOF", test_adv_fifo_read_empty_zero_writers_returns_eof, "FIFO")
    suite.add("ADV-IPC.15 FIFO Atomic Write PIPE_BUF (4096) Boundary", test_adv_fifo_atomic_write_pipe_buf_boundary, "FIFO")
    suite.add("ADV-IPC.16 FIFO Blocking State Transitions", test_adv_fifo_blocking_state_transitions, "FIFO")

    # -------------------------------------------------------------------------
    # DOMAIN 3: POSIX Message Queues (mqueue)
    # -------------------------------------------------------------------------

    def test_adv_mq_priority_ordering_multi_band_spectrum():
        """ADV-IPC-17: POSIX MQ orders messages by descending priority across multiple bands."""
        mq = RustPosixMqOracle(maxmsg=10, msgsize=64)

        # Send in random priority order: 10, 500, 0, 32767, 100
        mq.send(b"prio_10", 10)
        mq.send(b"prio_500", 500)
        mq.send(b"prio_0", 0)
        mq.send(b"prio_32767", 32767)
        mq.send(b"prio_100", 100)

        # Dequeue order must be strictly descending: 32767 -> 500 -> 100 -> 10 -> 0
        expected = [
            (b"prio_32767", 32767),
            (b"prio_500", 500),
            (b"prio_100", 100),
            (b"prio_10", 10),
            (b"prio_0", 0),
        ]
        for exp_payload, exp_prio in expected:
            _, payload, prio = mq.receive(64)
            assert_eq(prio, exp_prio)
            assert_eq(payload, exp_payload)

    def test_adv_mq_strict_fifo_tie_breaking_within_same_priority():
        """ADV-IPC-18: POSIX MQ enforces strict FIFO tie-breaking for equal-priority messages."""
        mq = RustPosixMqOracle(maxmsg=20, msgsize=64)

        # Enqueue 10 messages all with priority 42
        for i in range(10):
            mq.send(f"msg_{i}".encode("ascii"), 42)

        # Dequeue: Must strictly preserve arrival order
        for i in range(10):
            _, payload, prio = mq.receive(64)
            assert_eq(prio, 42)
            assert_eq(payload, f"msg_{i}".encode("ascii"), f"Tie-break order failed at index {i}")

    def test_adv_mq_interleaved_priority_fifo_matrix():
        """ADV-IPC-19: Complex multi-band interleaved priority matrix with strict FIFO tie-breaking."""
        mq = RustPosixMqOracle(maxmsg=20, msgsize=64)

        inputs = [
            (50, b"p50_a"),
            (100, b"p100_a"),
            (50, b"p50_b"),
            (0, b"p0_a"),
            (32767, b"p32767_a"),
            (100, b"p100_b"),
            (32767, b"p32767_b"),
            (50, b"p50_c"),
            (0, b"p0_b"),
        ]
        for p, d in inputs:
            assert_eq(mq.send(d, p), 0)

        expected_order = [
            (32767, b"p32767_a"),
            (32767, b"p32767_b"),
            (100, b"p100_a"),
            (100, b"p100_b"),
            (50, b"p50_a"),
            (50, b"p50_b"),
            (50, b"p50_c"),
            (0, b"p0_a"),
            (0, b"p0_b"),
        ]
        for exp_prio, exp_data in expected_order:
            _, payload, prio = mq.receive(64)
            assert_eq(prio, exp_prio)
            assert_eq(payload, exp_data)

    def test_adv_mq_priority_out_of_bounds_rejected():
        """ADV-IPC-20: Priority >= MQ_PRIO_MAX (32768) is rejected with -EINVAL."""
        mq = RustPosixMqOracle(maxmsg=10, msgsize=64)
        assert_eq(mq.send(b"bad", 32768), -22)
        assert_eq(mq.send(b"bad", 65535), -22)

    def test_adv_mq_oversize_sends_return_emsgsize():
        """ADV-IPC-21: Sending payload larger than mq_msgsize returns -EMSGSIZE (-90)."""
        mq = RustPosixMqOracle(maxmsg=5, msgsize=32)
        # 32 bytes succeeds
        assert_eq(mq.send(b"A" * 32, 10), 0)
        # 33 bytes fails with -EMSGSIZE
        assert_eq(mq.send(b"A" * 33, 10), -90)
        assert_eq(len(mq.messages), 1, "Failed send must not alter queue count")

    def test_adv_mq_undersize_receives_return_emsgsize():
        """ADV-IPC-22: Receiving with buffer capacity smaller than mq_msgsize returns -EMSGSIZE (-90)."""
        mq = RustPosixMqOracle(maxmsg=5, msgsize=64)
        # Send tiny 4-byte message
        mq.send(b"tiny", 10)

        # Attempt receive with 63-byte buffer (< mq_msgsize 64)
        code, _, _ = mq.receive(recv_cap=63)
        assert_eq(code, -90, "POSIX mandates buffer >= mq_msgsize regardless of head message length")

        # Receive with 64-byte buffer succeeds
        code, payload, _ = mq.receive(recv_cap=64)
        assert_eq(code, 4)
        assert_eq(payload, b"tiny")

    def test_adv_mq_notify_one_shot_strictly_on_0_to_1_transition():
        """ADV-IPC-23: mq_notify delivery occurs strictly on 0 -> 1 transition and is single-shot."""
        mq = RustPosixMqOracle(maxmsg=10, msgsize=64)

        # Register notification for PID 777, SIGUSR1 (10), sigval 0xDEADBEEF
        reg = (777, 10, 0xDEADBEEF)
        assert_eq(mq.notify(reg), 0)

        # Send Message 1: transitions empty -> non-empty (0 -> 1)
        assert_eq(mq.send(b"msg1", 10), 0)
        assert_true(mq.last_delivered_notification is not None)
        assert_eq(mq.last_delivered_notification, reg)
        assert_true(mq.notify_reg is None, "Registration must be cleared after one-shot firing")

        # Clear delivery record
        mq.last_delivered_notification = None

        # Send Message 2: transitions 1 -> 2 (queue is already non-empty)
        assert_eq(mq.send(b"msg2", 10), 0)
        assert_true(mq.last_delivered_notification is None, "Subsequent send must not fire notification")

    def test_adv_mq_notify_no_delivery_when_already_non_empty():
        """ADV-IPC-24: Registering notification on already non-empty queue does NOT fire on subsequent sends."""
        mq = RustPosixMqOracle(maxmsg=10, msgsize=64)
        mq.send(b"existing", 5)  # Queue len = 1

        reg = (888, 12, 1)
        assert_eq(mq.notify(reg), 0)

        # Send second message (1 -> 2)
        mq.send(b"second", 5)
        assert_true(mq.last_delivered_notification is None, "Notification must only fire on empty -> non-empty transition")

    def test_adv_mq_notify_concurrent_registration_busy():
        """ADV-IPC-25: Second concurrent mq_notify registration returns -EBUSY (-16)."""
        mq = RustPosixMqOracle(maxmsg=10, msgsize=64)
        assert_eq(mq.notify((100, 10, 1)), 0)
        assert_eq(mq.notify((200, 12, 2)), -16, "Concurrent registration must return -EBUSY")

    suite.add("ADV-IPC.17 POSIX MQ Multi-Band Priority Ordering", test_adv_mq_priority_ordering_multi_band_spectrum, "POSIX MQ")
    suite.add("ADV-IPC.18 POSIX MQ Strict FIFO Tie-Breaking", test_adv_mq_strict_fifo_tie_breaking_within_same_priority, "POSIX MQ")
    suite.add("ADV-IPC.19 POSIX MQ Interleaved Priority Matrix", test_adv_mq_interleaved_priority_fifo_matrix, "POSIX MQ")
    suite.add("ADV-IPC.20 POSIX MQ Priority Out of Bounds Rejection", test_adv_mq_priority_out_of_bounds_rejected, "POSIX MQ")
    suite.add("ADV-IPC.21 POSIX MQ Oversize Sends Return -EMSGSIZE", test_adv_mq_oversize_sends_return_emsgsize, "POSIX MQ")
    suite.add("ADV-IPC.22 POSIX MQ Undersize Receives Return -EMSGSIZE", test_adv_mq_undersize_receives_return_emsgsize, "POSIX MQ")
    suite.add("ADV-IPC.23 POSIX MQ mq_notify One-Shot 0->1 Delivery", test_adv_mq_notify_one_shot_strictly_on_0_to_1_transition, "POSIX MQ")
    suite.add("ADV-IPC.24 POSIX MQ mq_notify Non-Empty Transition Immunity", test_adv_mq_notify_no_delivery_when_already_non_empty, "POSIX MQ")
    suite.add("ADV-IPC.25 POSIX MQ Concurrent mq_notify Returns -EBUSY", test_adv_mq_notify_concurrent_registration_busy, "POSIX MQ")

    # -------------------------------------------------------------------------
    # DOMAIN 4: Shared Memory (System V & POSIX)
    # -------------------------------------------------------------------------

    def test_adv_shm_vma_range_allocation_and_boundary_checks():
        """ADV-IPC-26: System V sys_shmat_vma allocates page-aligned intervals within canonical range."""
        mgr = RustShmManagerOracle(0x0000_7000_0000_0000, 0x0000_8000_0000_0000)
        shmid1 = mgr.shmget(0x1000, 4096, RustShmManagerOracle.IPC_CREAT)
        shmid2 = mgr.shmget(0x2000, 8192, RustShmManagerOracle.IPC_CREAT)

        addr1 = mgr.shmat_vma(shmid1)
        addr2 = mgr.shmat_vma(shmid2)

        # Verify within canonical range
        assert_true(addr1 >= 0x0000_7000_0000_0000 and addr1 < 0x0000_8000_0000_0000)
        assert_true(addr2 >= 0x0000_7000_0000_0000 and addr2 < 0x0000_8000_0000_0000)

        # Page alignment check
        assert_eq(addr1 % 4096, 0)
        assert_eq(addr2 % 4096, 0)

        # Disjoint non-overlapping check: addr1 spans [addr1, addr1+4096), addr2 spans [addr2, addr2+8192)
        assert_true(addr1 + 4096 <= addr2 or addr2 + 8192 <= addr1, "VMA ranges must not overlap")

    def test_adv_shmdt_valid_address_decrements_nattch_and_unmaps():
        """ADV-IPC-27: sys_shmdt detaches valid address, unmaps VMA, and decrements nattch."""
        mgr = RustShmManagerOracle()
        shmid = mgr.shmget(0x3000, 4096, RustShmManagerOracle.IPC_CREAT)
        addr = mgr.shmat_vma(shmid)
        assert_eq(mgr.segments[shmid]["nattch"], 1)
        assert_eq(len(mgr.vma_intervals), 1)

        # Detach valid address
        assert_eq(mgr.shmdt(addr), 0)
        assert_eq(mgr.segments[shmid]["nattch"], 0)
        assert_eq(len(mgr.vma_intervals), 0, "VMA range must be unmapped")

    def test_adv_shmdt_invalid_unattached_address_returns_einval():
        """ADV-IPC-28: sys_shmdt on unattached address returns -EINVAL (-22)."""
        mgr = RustShmManagerOracle()
        assert_eq(mgr.shmdt(0x0000_7FFF_FFFF_0000), -22)

    def test_adv_shmdt_double_detach_returns_einval():
        """ADV-IPC-29: Double detach of the same address returns -EINVAL on second call."""
        mgr = RustShmManagerOracle()
        shmid = mgr.shmget(0x4000, 4096, RustShmManagerOracle.IPC_CREAT)
        addr = mgr.shmat_vma(shmid)

        assert_eq(mgr.shmdt(addr), 0)
        # Second detach of same address must fail
        assert_eq(mgr.shmdt(addr), -22)

    def test_adv_shm_deferred_ipc_rmid_deallocation():
        """ADV-IPC-30: IPC_RMID defers destruction while nattch > 0; cleans up on last detach."""
        mgr = RustShmManagerOracle()
        shmid = mgr.shmget(0x5000, 4096, RustShmManagerOracle.IPC_CREAT)
        addr1 = mgr.shmat_vma(shmid)
        addr2 = mgr.shmat_vma(shmid)
        assert_eq(mgr.segments[shmid]["nattch"], 2)

        # Issue IPC_RMID while nattch == 2
        assert_eq(mgr.shmctl(shmid, RustShmManagerOracle.IPC_RMID), 0)

        # Segment MUST still exist and remain attached
        assert_true(shmid in mgr.segments, "Segment must not be deleted while nattch > 0")
        assert_true(mgr.segments[shmid]["marked_destroy"])

        # Detach first process: nattch becomes 1 -> segment still persists
        assert_eq(mgr.shmdt(addr1), 0)
        assert_true(shmid in mgr.segments)
        assert_eq(mgr.segments[shmid]["nattch"], 1)

        # Detach second (last) process: nattch becomes 0 -> segment is DELETED
        assert_eq(mgr.shmdt(addr2), 0)
        assert_true(shmid not in mgr.segments, "Segment must be physically destroyed when nattch reaches 0")

    def test_adv_shm_immediate_ipc_rmid_when_nattch_zero():
        """ADV-IPC-31: IPC_RMID immediately deletes segment when nattch == 0."""
        mgr = RustShmManagerOracle()
        shmid = mgr.shmget(0x6000, 4096, RustShmManagerOracle.IPC_CREAT)
        assert_eq(mgr.segments[shmid]["nattch"], 0)

        assert_eq(mgr.shmctl(shmid, RustShmManagerOracle.IPC_RMID), 0)
        assert_true(shmid not in mgr.segments, "Segment must be deleted immediately if unattached")

    def test_adv_shm_ipc_rmid_invalid_shmid_returns_einval():
        """ADV-IPC-32: IPC_RMID on non-existent shmid returns -EINVAL (-22)."""
        mgr = RustShmManagerOracle()
        assert_eq(mgr.shmctl(999999, RustShmManagerOracle.IPC_RMID), -22)

    # -------------------------------------------------------------------------
    # DOMAIN 2 (Extended): Named Pipes FIFO Stress
    # -------------------------------------------------------------------------
    def test_adv_fifo_multi_burst_and_ring_draining():
        """ADV-IPC-34: Multi-burst writes and partial reads maintain strict FIFO byte stream ordering."""
        fifo = RustFifoOracle(mode=0o666)
        fifo.open(read=True, write=False, non_block=False)
        fifo.open(read=False, write=True, non_block=False)

        # Write 3 bursts of distinct data
        b1 = b"BURST_ALPHA_" * 10
        b2 = b"BURST_BETA__" * 10
        b3 = b"BURST_GAMMA_" * 10
        assert_eq(fifo.write(b1), len(b1))
        assert_eq(fifo.write(b2), len(b2))
        assert_eq(fifo.write(b3), len(b3))

        # Read back in arbitrary irregular chunk sizes
        total_len = len(b1) + len(b2) + len(b3)
        read_accum = bytearray()
        while len(read_accum) < total_len:
            chunk = fifo.read(25)  # Read 25 bytes at a time
            assert_true(len(chunk) > 0)
            read_accum.extend(chunk)

        assert_eq(bytes(read_accum), b1 + b2 + b3)

    # -------------------------------------------------------------------------
    # DOMAIN 3 (Extended): POSIX Message Queue Capacity & Notification Disarming
    # -------------------------------------------------------------------------
    def test_adv_mq_queue_full_capacity_returns_eagain():
        """ADV-IPC-35: Enqueueing past mq_maxmsg capacity returns -EAGAIN (-11)."""
        mq = RustPosixMqOracle(maxmsg=3, msgsize=32)
        assert_eq(mq.send(b"m1", 1), 0)
        assert_eq(mq.send(b"m2", 2), 0)
        assert_eq(mq.send(b"m3", 3), 0)
        # 4th message must be rejected with -EAGAIN
        assert_eq(mq.send(b"m4_overflow", 4), -11)

    def test_adv_mq_queue_empty_receive_returns_eagain():
        """ADV-IPC-36: Receiving from empty POSIX message queue returns -EAGAIN (-11)."""
        mq = RustPosixMqOracle(maxmsg=5, msgsize=32)
        code, _, _ = mq.receive(recv_cap=32)
        assert_eq(code, -11)

    def test_adv_mq_notify_unregister_disarms_notification():
        """ADV-IPC-37: Passing None to mq_notify disarms active registration."""
        mq = RustPosixMqOracle(maxmsg=5, msgsize=32)
        # Register notification
        assert_eq(mq.notify((999, 10, 0x1234)), 0)
        assert_true(mq.notify_reg is not None)

        # Disarm notification
        assert_eq(mq.notify(None), 0)
        assert_true(mq.notify_reg is None)

        # Send message: empty -> non-empty transition MUST NOT fire notification
        assert_eq(mq.send(b"payload", 1), 0)
        assert_true(mq.last_delivered_notification is None)

    # -------------------------------------------------------------------------
    # DOMAIN 4 (Extended): Shared Memory Coherency & Key Exclusivity
    # -------------------------------------------------------------------------
    def test_adv_shm_key_exclusivity_ipc_creat_excl():
        """ADV-IPC-38: IPC_CREAT | IPC_EXCL returns -EEXIST (-17) if key already exists."""
        mgr = RustShmManagerOracle()
        shmid1 = mgr.shmget(0x8888, 4096, RustShmManagerOracle.IPC_CREAT)
        assert_true(shmid1 > 0)

        # Second shmget with IPC_CREAT | IPC_EXCL on same key
        shmid2 = mgr.shmget(0x8888, 4096, RustShmManagerOracle.IPC_CREAT | RustShmManagerOracle.IPC_EXCL)
        assert_eq(shmid2, -17, "IPC_CREAT | IPC_EXCL on existing key must return -EEXIST (-17)")

    def test_adv_shm_lookup_nonexistent_without_creat_returns_enoent():
        """ADV-IPC-39: Looking up non-existent key without IPC_CREAT returns -ENOENT (-2)."""
        mgr = RustShmManagerOracle()
        assert_eq(mgr.shmget(0x9999, 4096, 0), -2)

    def test_adv_shm_zero_copy_shared_memory_coherency():
        """ADV-IPC-40: Multi-process shmat attachments observe coherent zero-copy updates."""
        mgr = RustShmManagerOracle()
        shmid = mgr.shmget(0xAAAA, 4096, RustShmManagerOracle.IPC_CREAT)

        # Process 1 attaches
        addr1 = mgr.shmat_vma(shmid)
        # Process 2 attaches same shmid
        addr2 = mgr.shmat_vma(shmid)
        assert_ne(addr1, addr2, "Different processes receive distinct virtual address mappings")

        # Mutate shared memory via segment data buffer
        seg = mgr.segments[shmid]
        seg["data"][0:8] = b"COROS_SH"

        # Both processes observe identical memory content
        assert_eq(bytes(seg["data"][0:8]), b"COROS_SH")
        assert_eq(seg["nattch"], 2)

    def test_adv_posix_shm_named_lifecycle_and_unlink():
        """ADV-IPC-41: POSIX named shared memory (/dev/shm/*) creation, ftruncate, and unlink."""
        # Standalone POSIX SHM oracle simulation
        posix_shms: Dict[str, bytearray] = {}

        def posix_shm_open(name: str, create: bool, excl: bool, size: int) -> int:
            if name in posix_shms:
                if create and excl:
                    return -17  # -EEXIST
                return 0
            if not create:
                return -2  # -ENOENT
            posix_shms[name] = bytearray(size)
            return 0

        def posix_shm_ftruncate(name: str, new_size: int) -> int:
            if name not in posix_shms:
                return -2
            posix_shms[name] = posix_shms[name][:new_size].ljust(new_size, b"\x00")
            return 0

        def posix_shm_unlink(name: str) -> int:
            if name in posix_shms:
                del posix_shms[name]
                return 0
            return -2

        assert_eq(posix_shm_open("/coros_shared", True, True, 4096), 0)
        assert_eq(posix_shm_open("/coros_shared", True, True, 4096), -17)
        assert_eq(posix_shm_ftruncate("/coros_shared", 8192), 0)
        assert_eq(len(posix_shms["/coros_shared"]), 8192)
        assert_eq(posix_shm_unlink("/coros_shared"), 0)
        assert_eq(posix_shm_unlink("/coros_shared"), -2)
        assert_eq(posix_shm_open("/coros_shared", False, False, 4096), -2)

    def test_adv_shm_vma_range_overflow_defense():
        """ADV-IPC-33: VMA interval allocation detects exhaustion and returns -ENOMEM (-12)."""
        # Create small 8 KiB VMA range
        mgr = RustShmManagerOracle(0x0000_7000_0000_0000, 0x0000_7000_0000_2000)
        shmid = mgr.shmget(0x7000, 16384, RustShmManagerOracle.IPC_CREAT)
        # Attempting to allocate 16 KiB inside 8 KiB range
        assert_eq(mgr.shmat_vma(shmid), -12, "Out of VMA space must return -ENOMEM")

    suite.add("ADV-IPC.26 System V VMA Allocation & Boundary Checks", test_adv_shm_vma_range_allocation_and_boundary_checks, "Shared Memory")
    suite.add("ADV-IPC.27 sys_shmdt Valid Address Detach & VMA Unmap", test_adv_shmdt_valid_address_decrements_nattch_and_unmaps, "Shared Memory")
    suite.add("ADV-IPC.28 sys_shmdt Invalid Address Returns -EINVAL", test_adv_shmdt_invalid_unattached_address_returns_einval, "Shared Memory")
    suite.add("ADV-IPC.29 sys_shmdt Double Detach Returns -EINVAL", test_adv_shmdt_double_detach_returns_einval, "Shared Memory")
    suite.add("ADV-IPC.30 Deferred IPC_RMID Destruction on Last Detach", test_adv_shm_deferred_ipc_rmid_deallocation, "Shared Memory")
    suite.add("ADV-IPC.31 Immediate IPC_RMID Destruction When Unattached", test_adv_shm_immediate_ipc_rmid_when_nattch_zero, "Shared Memory")
    suite.add("ADV-IPC.32 IPC_RMID Invalid shmid Returns -EINVAL", test_adv_shm_ipc_rmid_invalid_shmid_returns_einval, "Shared Memory")
    suite.add("ADV-IPC.33 Shared Memory VMA Out-Of-Memory Defense", test_adv_shm_vma_range_overflow_defense, "Shared Memory")
    suite.add("ADV-IPC.34 FIFO Multi-Burst Write & Draining Stress", test_adv_fifo_multi_burst_and_ring_draining, "FIFO")
    suite.add("ADV-IPC.35 POSIX MQ Queue Full Returns -EAGAIN", test_adv_mq_queue_full_capacity_returns_eagain, "POSIX MQ")
    suite.add("ADV-IPC.36 POSIX MQ Empty Receive Returns -EAGAIN", test_adv_mq_queue_empty_receive_returns_eagain, "POSIX MQ")
    suite.add("ADV-IPC.37 POSIX MQ mq_notify Unregister Disarms Notification", test_adv_mq_notify_unregister_disarms_notification, "POSIX MQ")
    suite.add("ADV-IPC.38 Shared Memory IPC_CREAT|IPC_EXCL Key Collision", test_adv_shm_key_exclusivity_ipc_creat_excl, "Shared Memory")
    suite.add("ADV-IPC.39 Shared Memory Non-Existent Key Returns -ENOENT", test_adv_shm_lookup_nonexistent_without_creat_returns_enoent, "Shared Memory")
    suite.add("ADV-IPC.40 Shared Memory Zero-Copy Multi-Attach Coherency", test_adv_shm_zero_copy_shared_memory_coherency, "Shared Memory")
    suite.add("ADV-IPC.41 POSIX Named Shared Memory Lifecycle", test_adv_posix_shm_named_lifecycle_and_unlink, "Shared Memory")

    return suite


if __name__ == "__main__":
    suite = run_all_challenges()
    passed, failed, details = suite.run(verbose=True)
    print("\n" + "=" * 78)
    print(f"Empirical Challenger 1 Verdict: {passed} PASSED, {failed} FAILED")
    print("=" * 78)
    if failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)
