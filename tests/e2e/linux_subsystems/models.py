"""
CorOS Linux Subsystems Authoritative Models & Simulation Framework
==================================================================
CorOS/tests/e2e/linux_subsystems/models.py

Pure-Python standard library implementations of the data structures,
hardware register layouts, bitfields, and algorithmic models for all 11
Linux subsystems (Features 1 through 21).
"""

import collections
import dataclasses
import enum
import hashlib
import struct
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


# ============================================================================
# Subsystem 1: Namespaces & Chroot (Feature 1)
# ============================================================================

class CloneFlags:
    CSIGNAL              = 0x000000FF
    CLONE_VM             = 0x00000100
    CLONE_FS             = 0x00000200
    CLONE_FILES          = 0x00000400
    CLONE_SIGHAND        = 0x00000800
    CLONE_PIDFD          = 0x00001000
    CLONE_PTRACE         = 0x00002000
    CLONE_VFORK          = 0x00004000
    CLONE_PARENT         = 0x00008000
    CLONE_THREAD         = 0x00010000
    CLONE_NEWNS          = 0x00020000  # Mount namespace
    CLONE_SYSVSEM        = 0x00040000
    CLONE_SETTLS         = 0x00080000
    CLONE_PARENT_SETTID  = 0x00100000
    CLONE_CHILD_CLEARTID = 0x00200000
    CLONE_DETACHED       = 0x00400000
    CLONE_UNTRACED       = 0x00800000
    CLONE_CHILD_SETTID   = 0x01000000
    CLONE_NEWCGROUP      = 0x02000000  # Cgroup namespace
    CLONE_NEWUTS         = 0x04000000  # UTS namespace
    CLONE_NEWIPC         = 0x08000000  # IPC namespace
    CLONE_NEWUSER        = 0x10000000  # User namespace
    CLONE_NEWPID         = 0x20000000  # PID namespace
    CLONE_NEWNET         = 0x40000000  # Network namespace
    CLONE_IO             = 0x80000000


class MountPropagation(enum.Enum):
    SHARED = 1
    PRIVATE = 2
    SLAVE = 3
    UNBINDABLE = 4


@dataclasses.dataclass
class UidGidExtent:
    inside_id: int
    outside_id: int
    count: int

    def map_id_up(self, inner_id: int) -> Optional[int]:
        if self.inside_id <= inner_id < self.inside_id + self.count:
            return self.outside_id + (inner_id - self.inside_id)
        return None

    def map_id_down(self, outer_id: int) -> Optional[int]:
        if self.outside_id <= outer_id < self.outside_id + self.count:
            return self.inside_id + (outer_id - self.outside_id)
        return None


class MockUserNamespace:
    OVERFLOW_ID = 65534

    def __init__(self, ns_id: int, parent: Optional["MockUserNamespace"] = None):
        self.ns_id = ns_id
        self.parent = parent
        self.uid_extents: List[UidGidExtent] = []
        self.gid_extents: List[UidGidExtent] = []

    def set_uid_map(self, extents: List[UidGidExtent]):
        self.uid_extents = list(extents)

    def set_gid_map(self, extents: List[UidGidExtent]):
        self.gid_extents = list(extents)

    def map_uid(self, inner_uid: int) -> int:
        for ext in self.uid_extents:
            mapped = ext.map_id_up(inner_uid)
            if mapped is not None:
                return mapped
        return self.OVERFLOW_ID

    def map_gid(self, inner_gid: int) -> int:
        for ext in self.gid_extents:
            mapped = ext.map_id_up(inner_gid)
            if mapped is not None:
                return mapped
        return self.OVERFLOW_ID


class MockPidNamespace:
    MAX_DEPTH = 32

    def __init__(self, ns_id: int, parent: Optional["MockPidNamespace"] = None):
        self.ns_id = ns_id
        self.parent = parent
        self.depth = 0 if parent is None else parent.depth + 1
        if self.depth >= self.MAX_DEPTH:
            raise ValueError(f"Max PID namespace depth {self.MAX_DEPTH} exceeded")
        self.next_vpid = 1
        self.tasks: Dict[int, int] = {}  # vpid -> global_pid
        self.global_to_vpid: Dict[int, int] = {}  # global_pid -> vpid
        self.is_dead = False

    def allocate_vpid(self, global_pid: int) -> int:
        if self.is_dead:
            raise RuntimeError("Cannot allocate PID in dead namespace")
        vpid = self.next_vpid
        self.next_vpid += 1
        self.tasks[vpid] = global_pid
        self.global_to_vpid[global_pid] = vpid
        return vpid

    def release_task(self, vpid: int) -> List[int]:
        """If init (vpid 1) exits, cascades termination to all child tasks in namespace."""
        killed_global_pids = []
        if vpid == 1:
            self.is_dead = True
            for vp, gp in list(self.tasks.items()):
                if vp != 1:
                    killed_global_pids.append(gp)
            self.tasks.clear()
            self.global_to_vpid.clear()
        else:
            if vpid in self.tasks:
                gp = self.tasks.pop(vpid)
                self.global_to_vpid.pop(gp, None)
        return killed_global_pids


class MockUtsNamespace:
    def __init__(self, nodename: str = "coros-node", domainname: str = "localdomain"):
        self.sysname = "CorOS-Linux"
        self.nodename = nodename
        self.release = "6.1.0-coros-uefi"
        self.version = "#1 SMP PREEMPT"
        self.machine = "x86_64"
        self.domainname = domainname


class MockNetNamespace:
    def __init__(self, ns_id: int):
        self.ns_id = ns_id
        self.interfaces: Dict[str, Dict[str, Any]] = {
            "lo": {"ip": "127.0.0.1", "mask": "255.0.0.0", "up": True}
        }
        self.routes: List[Dict[str, Any]] = [
            {"dest": "127.0.0.0", "mask": "255.0.0.0", "iface": "lo", "gw": "0.0.0.0"}
        ]

    def add_interface(self, name: str, ip: str, mask: str):
        self.interfaces[name] = {"ip": ip, "mask": mask, "up": True}

    def route_lookup(self, dest_ip: str) -> Optional[str]:
        for r in self.routes:
            if dest_ip.startswith("127.") and r["iface"] == "lo":
                return "lo"
        return None


class MockMountNamespace:
    def __init__(self, ns_id: int):
        self.ns_id = ns_id
        self.mounts: Dict[str, MountPropagation] = {
            "/": MountPropagation.SHARED
        }
        self.peer_groups: Dict[str, int] = {"/": 1}

    def bind_mount(self, src: str, dst: str, propagation: MountPropagation):
        self.mounts[dst] = propagation
        if propagation == MountPropagation.SHARED:
            self.peer_groups[dst] = self.peer_groups.get(src, 1)


class MockChrootJail:
    def __init__(self, root_dir: str = "/"):
        self.root_dir = root_dir.rstrip("/") or "/"
        self.cwd = "/"

    def set_root(self, new_root: str):
        if not new_root.startswith("/"):
            raise ValueError("Root must be absolute path")
        self.root_dir = new_root.rstrip("/") or "/"
        self.cwd = "/"

    def resolve_path(self, path: str) -> str:
        """Confines path traversal within self.root_dir, preventing escaping via '..'"""
        if path.startswith("/"):
            tokens = path.split("/")
        else:
            tokens = (self.cwd + "/" + path).split("/")

        stack = []
        for t in tokens:
            if not t or t == ".":
                continue
            if t == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(t)

        rel = "/" + "/".join(stack)
        if self.root_dir == "/":
            return rel
        if rel == "/":
            return self.root_dir
        return self.root_dir + rel


# ============================================================================
# Subsystem 2: cgroups v2 Resource Control (Feature 2)
# ============================================================================

@dataclasses.dataclass
class CpuBandwidth:
    quota_us: Optional[int] = None
    period_us: int = 100000  # Default 100ms
    consumed_in_period_us: int = 0
    nr_throttled: int = 0
    throttled_usec: int = 0
    cpu_weight: int = 100  # Range 1..10000

    def charge(self, runtime_us: int) -> bool:
        """Charges CPU runtime. Returns True if task is allowed, False if throttled."""
        if self.quota_us is None:
            self.consumed_in_period_us += runtime_us
            return True
        if self.consumed_in_period_us + runtime_us > self.quota_us:
            self.nr_throttled += 1
            self.throttled_usec += runtime_us
            return False
        self.consumed_in_period_us += runtime_us
        return True

    def reset_period(self):
        self.consumed_in_period_us = 0


@dataclasses.dataclass
class MemoryController:
    current_bytes: int = 0
    min_bytes: int = 0
    low_bytes: int = 0
    high_bytes: Optional[int] = None
    max_bytes: Optional[int] = None
    events_high: int = 0
    events_max: int = 0
    events_oom: int = 0

    def charge(self, bytes_count: int) -> bool:
        """Returns True if allocation succeeds, False if rejected by memory.max."""
        new_usage = self.current_bytes + bytes_count
        if self.max_bytes is not None and new_usage > self.max_bytes:
            self.events_max += 1
            self.events_oom += 1
            return False
        if self.high_bytes is not None and new_usage > self.high_bytes:
            self.events_high += 1
        self.current_bytes = new_usage
        return True

    def uncharge(self, bytes_count: int):
        self.current_bytes = max(0, self.current_bytes - bytes_count)


@dataclasses.dataclass
class IoTokenBucket:
    rbps_max: Optional[int] = None
    wbps_max: Optional[int] = None
    riops_max: Optional[int] = None
    wiops_max: Optional[int] = None
    read_tokens: int = 0
    write_tokens: int = 0
    read_iops: int = 0
    write_iops: int = 0

    def refill(self):
        if self.rbps_max:
            self.read_tokens = self.rbps_max
        if self.wbps_max:
            self.write_tokens = self.wbps_max
        if self.riops_max:
            self.read_iops = self.riops_max
        if self.wiops_max:
            self.write_iops = self.wiops_max

    def charge_io(self, is_write: bool, bytes_count: int) -> bool:
        if is_write:
            if self.wbps_max and self.write_tokens < bytes_count:
                return False
            if self.wiops_max and self.write_iops <= 0:
                return False
            if self.wbps_max:
                self.write_tokens -= bytes_count
            if self.wiops_max:
                self.write_iops -= 1
        else:
            if self.rbps_max and self.read_tokens < bytes_count:
                return False
            if self.riops_max and self.read_iops <= 0:
                return False
            if self.rbps_max:
                self.read_tokens -= bytes_count
            if self.riops_max:
                self.read_iops -= 1
        return True


class MockCgroupV2Node:
    def __init__(self, name: str, parent: Optional["MockCgroupV2Node"] = None):
        self.name = name
        self.parent = parent
        self.children: Dict[str, "MockCgroupV2Node"] = {}
        self.procs: Set[int] = set()
        self.cpu = CpuBandwidth()
        self.memory = MemoryController()
        self.io = IoTokenBucket()

    def add_child(self, name: str) -> "MockCgroupV2Node":
        child = MockCgroupV2Node(name, parent=self)
        self.children[name] = child
        return child

    def attach_task(self, pid: int):
        # Enforce cgroups v2 "no internal processes" constraint
        if self.children and self.parent is not None:
            raise RuntimeError("cgroupv2 violation: cannot attach task to internal node with children")
        self.procs.add(pid)


# ============================================================================
# Subsystem 3: Full POSIX Signals (Feature 3)
# ============================================================================

class SignalNumber(enum.IntEnum):
    SIGHUP    = 1
    SIGINT    = 2
    SIGQUIT   = 3
    SIGILL    = 4
    SIGTRAP   = 5
    SIGABRT   = 6
    SIGBUS    = 7
    SIGFPE    = 8
    SIGKILL   = 9
    SIGUSR1   = 10
    SIGSEGV   = 11
    SIGUSR2   = 12
    SIGPIPE   = 13
    SIGALRM   = 14
    SIGTERM   = 15
    SIGSTKFLT = 16
    SIGCHLD   = 17
    SIGCONT   = 18
    SIGSTOP   = 19
    SIGTSTP   = 20
    SIGTTIN   = 21
    SIGTTOU   = 22
    SIGURG    = 23
    SIGXCPU   = 24
    SIGXFSZ   = 25
    SIGVTALRM = 26
    SIGPROF   = 27
    SIGWINCH  = 28
    SIGIO     = 29
    SIGPWR    = 30
    SIGSYS    = 31
    SIGRTMIN  = 34
    SIGRTMAX  = 64


class SigActionFlags:
    SA_NOCLDSTOP = 0x00000001
    SA_NOCLDWAIT = 0x00000002
    SA_SIGINFO   = 0x00000004
    SA_ONSTACK   = 0x08000000
    SA_RESTART   = 0x10000000
    SA_NODEFER   = 0x40000000
    SA_RESETHAND = 0x80000000


class SigDisposition(enum.Enum):
    DEFAULT = 0
    IGNORE = 1
    HANDLER = 2


@dataclasses.dataclass
class SigAction:
    disposition: SigDisposition = SigDisposition.DEFAULT
    handler_addr: int = 0
    flags: int = 0
    mask: int = 0
    restorer: int = 0


@dataclasses.dataclass
class SigInfo:
    si_signo: int
    si_errno: int = 0
    si_code: int = 0
    sender_pid: int = 0
    sender_uid: int = 0
    sigval: int = 0


@dataclasses.dataclass
class UContextX86_64:
    rip: int
    rsp: int
    rax: int
    rdi: int
    rsi: int
    rdx: int
    rflags: int
    old_mask: int


class MockSignalManager:
    UNBLOCKABLE_MASK = (1 << (SignalNumber.SIGKILL - 1)) | (1 << (SignalNumber.SIGSTOP - 1))

    def __init__(self, pid: int):
        self.pid = pid
        self.handlers: Dict[int, SigAction] = {
            s.value: SigAction() for s in SignalNumber
        }
        self.blocked_mask: int = 0
        self.pending_queue: List[SigInfo] = []
        self.altstack_sp: Optional[int] = None
        self.altstack_size: int = 0
        self.terminated: bool = False
        self.exit_code: int = 0

    def sigaction(self, sig: int, act: SigAction) -> SigAction:
        if sig in (SignalNumber.SIGKILL, SignalNumber.SIGSTOP):
            raise PermissionError("Cannot set handler for SIGKILL or SIGSTOP")
        old_act = self.handlers[sig]
        self.handlers[sig] = act
        return old_act

    def sigprocmask(self, how: str, mask: int) -> int:
        old = self.blocked_mask
        if how == "SIG_BLOCK":
            self.blocked_mask |= (mask & ~self.UNBLOCKABLE_MASK)
        elif how == "SIG_UNBLOCK":
            self.blocked_mask &= ~(mask | self.UNBLOCKABLE_MASK)
        elif how == "SIG_SETMASK":
            self.blocked_mask = (mask & ~self.UNBLOCKABLE_MASK)
        return old

    def queue_signal(self, info: SigInfo):
        self.pending_queue.append(info)

    def dequeue_signal(self) -> Optional[SigInfo]:
        for i, info in enumerate(self.pending_queue):
            mask_bit = 1 << (info.si_signo - 1)
            if (self.blocked_mask & mask_bit) == 0:
                return self.pending_queue.pop(i)
        return None

    def execute_default_action(self, sig: int):
        """Executes Linux default signal action."""
        if sig in (SignalNumber.SIGCHLD, SignalNumber.SIGURG, SignalNumber.SIGWINCH):
            return  # Ignored by default
        if sig in (SignalNumber.SIGSTOP, SignalNumber.SIGTSTP):
            return  # Stop process
        if sig == SignalNumber.SIGCONT:
            return  # Continue process
        # Terminate
        self.terminated = True
        self.exit_code = 128 + sig


# ============================================================================
# Subsystem 4: Futex & POSIX Sync Primitives (Feature 4)
# ============================================================================

class FutexOp(enum.IntEnum):
    FUTEX_WAIT = 0
    FUTEX_WAKE = 1
    FUTEX_FD = 2
    FUTEX_REQUEUE = 3
    FUTEX_CMP_REQUEUE = 4
    FUTEX_WAKE_OP = 5
    FUTEX_WAIT_BITSET = 9
    FUTEX_WAKE_BITSET = 10


FUTEX_WAITERS = 0x80000000
FUTEX_OWNER_DIED = 0x40000000
FUTEX_TID_MASK = 0x3FFFFFFF


class MockFutexManager:
    def __init__(self):
        # uaddr -> list of waiting thread IDs
        self.waiters: Dict[int, List[int]] = collections.defaultdict(list)
        self.memory: Dict[int, int] = {}
        self.robust_lists: Dict[int, List[int]] = {}  # tid -> list of locked uaddrs

    def set_memory_val(self, uaddr: int, val: int):
        self.memory[uaddr] = val & 0xFFFFFFFF

    def get_memory_val(self, uaddr: int) -> int:
        return self.memory.get(uaddr, 0)

    def futex_wait(self, uaddr: int, expected_val: int, tid: int) -> int:
        cur = self.get_memory_val(uaddr)
        if cur != (expected_val & 0xFFFFFFFF):
            return -11  # -EAGAIN
        self.waiters[uaddr].append(tid)
        return 0

    def futex_wake(self, uaddr: int, nr_wake: int) -> int:
        q = self.waiters.get(uaddr, [])
        woken = 0
        while q and woken < nr_wake:
            q.pop(0)
            woken += 1
        return woken

    def futex_cmp_requeue(self, uaddr1: int, uaddr2: int, nr_wake: int, nr_requeue: int, val3: int) -> int:
        cur = self.get_memory_val(uaddr1)
        if cur != (val3 & 0xFFFFFFFF):
            return -11  # -EAGAIN
        woken = self.futex_wake(uaddr1, nr_wake)
        q1 = self.waiters.get(uaddr1, [])
        requeued = 0
        while q1 and requeued < nr_requeue:
            tid = q1.pop(0)
            self.waiters[uaddr2].append(tid)
            requeued += 1
        return woken + requeued

    def handle_thread_exit(self, tid: int):
        """Robust futex owner termination handling."""
        held_addrs = self.robust_lists.get(tid, [])
        for addr in held_addrs:
            val = self.get_memory_val(addr)
            if (val & FUTEX_TID_MASK) == tid:
                # Mark owner died and wake waiters
                new_val = (val & ~FUTEX_TID_MASK) | FUTEX_OWNER_DIED
                self.set_memory_val(addr, new_val)
                self.futex_wake(addr, 1)


class MockPthreadMutex:
    def __init__(self, futex_mgr: MockFutexManager, uaddr: int):
        self.mgr = futex_mgr
        self.uaddr = uaddr
        self.mgr.set_memory_val(uaddr, 0)

    def lock(self, tid: int) -> bool:
        cur = self.mgr.get_memory_val(self.uaddr)
        # Fast path
        if cur == 0:
            self.mgr.set_memory_val(self.uaddr, tid)
            return True
        # Slow path: mark waiters and wait
        self.mgr.set_memory_val(self.uaddr, cur | FUTEX_WAITERS)
        self.mgr.futex_wait(self.uaddr, cur | FUTEX_WAITERS, tid)
        return False

    def unlock(self, tid: int) -> bool:
        cur = self.mgr.get_memory_val(self.uaddr)
        if (cur & FUTEX_TID_MASK) != tid:
            raise PermissionError("Calling thread does not own mutex")
        self.mgr.set_memory_val(self.uaddr, 0)
        if (cur & FUTEX_WAITERS) != 0:
            self.mgr.futex_wake(self.uaddr, 1)
        return True


class MockPthreadRwLock:
    def __init__(self):
        self.readers = 0
        self.writer: Optional[int] = None

    def read_lock(self, tid: int) -> bool:
        if self.writer is not None:
            return False
        self.readers += 1
        return True

    def read_unlock(self, tid: int):
        if self.readers <= 0:
            raise RuntimeError("Read lock underflow")
        self.readers -= 1

    def write_lock(self, tid: int) -> bool:
        if self.readers > 0 or self.writer is not None:
            return False
        self.writer = tid
        return True

    def write_unlock(self, tid: int):
        if self.writer != tid:
            raise PermissionError("Not writer owner")
        self.writer = None


class MockPosixSemaphore:
    def __init__(self, initial_value: int = 0):
        self.value = initial_value

    def post(self):
        self.value += 1

    def wait(self) -> bool:
        if self.value > 0:
            self.value -= 1
            return True
        return False


# ============================================================================
# Subsystem 10: Swap & Virtual Memory Paging (Feature 5)
# ============================================================================

SWAP_ENTRY_FLAG = 1 << 1


def encode_swap_entry(swap_type: int, slot_offset: int) -> int:
    """Encode (swap_type: 5 bits, slot_offset: 50 bits) into non-present PTE."""
    return SWAP_ENTRY_FLAG | ((swap_type & 0x1F) << 2) | ((slot_offset & 0x0003FFFFFFFFFFFF) << 7)


def is_swap_entry(pte_val: int) -> bool:
    return (pte_val & 1 == 0) and ((pte_val & SWAP_ENTRY_FLAG) != 0)


def decode_swap_entry(pte_val: int) -> Tuple[int, int]:
    swap_type = (pte_val >> 2) & 0x1F
    slot_offset = (pte_val >> 7) & 0x0003FFFFFFFFFFFF
    return swap_type, slot_offset


class MockSwapBackend(enum.Enum):
    ZRAM = 0
    PARTITION = 1
    FILE = 2


class MockSwapManager:
    def __init__(self, max_slots: int = 1024):
        self.max_slots = max_slots
        self.slots: Dict[Tuple[int, int], bytes] = {}  # (type, slot) -> 4096-byte payload
        self.free_slots = list(range(1, max_slots))

    def allocate_slot(self, swap_type: int, data: bytes) -> int:
        if not self.free_slots:
            raise MemoryError("Swap space exhausted")
        slot = self.free_slots.pop(0)
        self.slots[(swap_type, slot)] = bytes(data)
        return slot

    def read_slot(self, swap_type: int, slot: int) -> bytes:
        if (swap_type, slot) not in self.slots:
            raise KeyError(f"Swap slot {(swap_type, slot)} not found")
        return self.slots[(swap_type, slot)]

    def free_slot(self, swap_type: int, slot: int):
        if (swap_type, slot) in self.slots:
            del self.slots[(swap_type, slot)]
            self.free_slots.append(slot)


class MockPageReclaimLru:
    def __init__(self):
        self.active_anon: List[int] = []
        self.inactive_anon: List[int] = []
        self.page_accessed: Dict[int, bool] = {}

    def add_page(self, vaddr: int):
        self.inactive_anon.append(vaddr)
        self.page_accessed[vaddr] = True

    def clock_sweep_evict(self) -> Optional[int]:
        """Second-chance clock sweep: returns candidate for swap eviction."""
        if not self.inactive_anon:
            if not self.active_anon:
                return None
            self.inactive_anon.extend(self.active_anon)
            self.active_anon.clear()

        # Sweep inactive list
        for _ in range(len(self.inactive_anon)):
            p = self.inactive_anon.pop(0)
            if self.page_accessed.get(p, False):
                self.page_accessed[p] = False
                self.active_anon.append(p)
            else:
                return p
        return None


class MockOomKiller:
    @staticmethod
    def calculate_badness(total_pages: int, oom_score_adj: int = 0, is_init: bool = False) -> int:
        """Linux-compatible oom_badness calculation in [0..1000]."""
        if is_init or oom_score_adj <= -1000:
            return 0
        points = int((total_pages / 1000000) * 1000)
        points += oom_score_adj
        return max(1, min(1000, points))


# ============================================================================
# Subsystem 5: IPC Extensions (Features 6, 7, 8, 9)
# ============================================================================

# Feature 6: Unix Domain Sockets
class UnixSocketType(enum.Enum):
    STREAM = 1
    DGRAM = 2


@dataclasses.dataclass
class Ucred:
    pid: int
    uid: int
    gid: int


class MockUnixDomainSocket:
    def __init__(self, sock_type: UnixSocketType):
        self.sock_type = sock_type
        self.bound_path: Optional[str] = None
        self.is_abstract: bool = False
        self.peer: Optional["MockUnixDomainSocket"] = None
        self.rx_buffer = bytearray()
        self.rx_ancillary_fds: List[int] = []
        self.rx_credentials: Optional[Ucred] = None
        self.is_listening: bool = False
        self.backlog: List["MockUnixDomainSocket"] = []

    def bind(self, path: str):
        self.bound_path = path
        self.is_abstract = path.startswith("\x00")

    def listen(self):
        if self.sock_type != UnixSocketType.STREAM:
            raise ValueError("Only STREAM sockets can listen")
        self.is_listening = True

    def connect(self, target: "MockUnixDomainSocket"):
        if not target.is_listening and target.sock_type == UnixSocketType.STREAM:
            raise ConnectionRefusedError("Target is not listening")
        self.peer = target
        if target.sock_type == UnixSocketType.STREAM:
            target.backlog.append(self)

    def send(self, data: bytes, passed_fds: Optional[List[int]] = None, cred: Optional[Ucred] = None):
        if not self.peer:
            raise BrokenPipeError("Socket not connected")
        self.peer.rx_buffer.extend(data)
        if passed_fds:
            self.peer.rx_ancillary_fds.extend(passed_fds)
        if cred:
            self.peer.rx_credentials = cred

    def recv(self, max_bytes: int) -> bytes:
        chunk = bytes(self.rx_buffer[:max_bytes])
        self.rx_buffer = self.rx_buffer[max_bytes:]
        return chunk


# Feature 7: Named Pipes (FIFO)
class MockFifoInode:
    PIPE_BUF = 4096

    def __init__(self, path: str):
        self.path = path
        self.buffer = bytearray()
        self.reader_count = 0
        self.writer_count = 0

    def open(self, mode: str, non_block: bool = False) -> str:
        if "r" in mode:
            self.reader_count += 1
            if not non_block and self.writer_count == 0:
                return "BLOCKED_WAITING_FOR_WRITER"
            return "OPENED_RO"
        elif "w" in mode:
            self.writer_count += 1
            if non_block and self.reader_count == 0:
                raise OSError(6, "ENXIO: No such device or address")
            if not non_block and self.reader_count == 0:
                return "BLOCKED_WAITING_FOR_READER"
            return "OPENED_WO"
        raise ValueError("Invalid mode")

    def write(self, data: bytes) -> int:
        if self.reader_count == 0:
            raise BrokenPipeError("EPIPE / SIGPIPE: Writing to FIFO with zero readers")
        self.buffer.extend(data)
        return len(data)

    def read(self, max_bytes: int) -> bytes:
        if not self.buffer:
            if self.writer_count == 0:
                return b""  # EOF
            return b""  # In blocking pipe, would wait
        chunk = bytes(self.buffer[:max_bytes])
        self.buffer = self.buffer[max_bytes:]
        return chunk


# Feature 8: POSIX Message Queues
@dataclasses.dataclass
class MqMessage:
    priority: int
    payload: bytes
    seq: int  # For FIFO ordering within same priority


class MockPosixMessageQueue:
    def __init__(self, name: str, max_msg: int = 10, max_msgsize: int = 8192):
        self.name = name
        self.max_msg = max_msg
        self.max_msgsize = max_msgsize
        self.queue: List[MqMessage] = []
        self.seq_counter = 0
        self.notify_signal: Optional[int] = None
        self.notify_pid: Optional[int] = None

    def send(self, data: bytes, priority: int = 0):
        if len(data) > self.max_msgsize:
            raise ValueError("Message too large (EMSGSIZE)")
        if len(self.queue) >= self.max_msg:
            raise RuntimeError("Queue full (EAGAIN)")
        
        was_empty = len(self.queue) == 0
        msg = MqMessage(priority=priority, payload=bytes(data), seq=self.seq_counter)
        self.seq_counter += 1
        self.queue.append(msg)
        # Sort by priority DESCENDING, then sequence ASCENDING (FIFO within tie)
        self.queue.sort(key=lambda m: (-m.priority, m.seq))

        if was_empty and self.notify_signal and self.notify_pid:
            sig = self.notify_signal
            self.notify_signal = None  # One-shot notification
            return sig
        return None

    def receive(self) -> Tuple[bytes, int]:
        if not self.queue:
            raise RuntimeError("Queue empty (EAGAIN)")
        msg = self.queue.pop(0)
        return msg.payload, msg.priority


# Feature 9: Shared Memory
class MockSharedMemoryManager:
    def __init__(self):
        self.sysv_segments: Dict[int, Dict[str, Any]] = {}  # shmid -> meta
        self.posix_shm: Dict[str, bytearray] = {}  # name -> buffer
        self.next_shmid = 100

    def sysv_shmget(self, key: int, size: int) -> int:
        shmid = self.next_shmid
        self.next_shmid += 1
        self.sysv_segments[shmid] = {
            "key": key,
            "size": size,
            "data": bytearray(size),
            "nattch": 0,
            "marked_destroy": False
        }
        return shmid

    def sysv_shmat(self, shmid: int) -> bytearray:
        if shmid not in self.sysv_segments:
            raise KeyError("Invalid shmid")
        seg = self.sysv_segments[shmid]
        seg["nattch"] += 1
        return seg["data"]

    def sysv_shmdt(self, shmid: int):
        if shmid in self.sysv_segments:
            seg = self.sysv_segments[shmid]
            seg["nattch"] = max(0, seg["nattch"] - 1)
            if seg["marked_destroy"] and seg["nattch"] == 0:
                del self.sysv_segments[shmid]

    def posix_shm_open(self, name: str, size: int = 0) -> bytearray:
        if name not in self.posix_shm:
            self.posix_shm[name] = bytearray(size)
        return self.posix_shm[name]


# ============================================================================
# Subsystem 6: Dynamic Linker & ELF Shared Library Loader (Feature 10)
# ============================================================================

class ElfDynamicTag(enum.IntEnum):
    DT_NULL         = 0
    DT_NEEDED       = 1
    DT_PLTRELSZ     = 2
    DT_PLTGOT       = 3
    DT_HASH         = 4
    DT_STRTAB       = 5
    DT_SYMTAB       = 6
    DT_RELA         = 7
    DT_RELASZ       = 8
    DT_STRSZ        = 10
    DT_SYMENT       = 11
    DT_INIT         = 12
    DT_FINI         = 13
    DT_SONAME       = 14
    DT_JMPREL       = 23
    DT_INIT_ARRAY   = 25
    DT_FLAGS        = 30
    DT_GNU_HASH     = 0x6FFFFEF5


class ElfRelocType(enum.IntEnum):
    R_X86_64_NONE      = 0
    R_X86_64_64        = 1
    R_X86_64_GLOB_DAT  = 6
    R_X86_64_JUMP_SLOT = 7
    R_X86_64_RELATIVE  = 8


@dataclasses.dataclass
class DynamicSymbol:
    name: str
    value: int
    size: int
    binding: str  # GLOBAL, WEAK, LOCAL


class MockDynamicLinker:
    @staticmethod
    def gnu_hash(name: str) -> int:
        """Standard 32-bit GNU hash function."""
        h = 5381
        for c in name.encode("utf-8"):
            h = (((h << 5) + h) + c) & 0xFFFFFFFF
        return h

    @staticmethod
    def sysv_hash(name: str) -> int:
        """Standard SysV ELF hash function."""
        h = 0
        for c in name.encode("utf-8"):
            h = (h << 4) + c
            g = h & 0xF0000000
            if g != 0:
                h ^= (g >> 24)
            h &= ~g
        return h & 0xFFFFFFFF

    def __init__(self, eager_binding: bool = False):
        self.eager_binding = eager_binding
        self.loaded_objects: Dict[str, Dict[str, Any]] = {}
        self.global_symbol_table: Dict[str, int] = {}
        self.got_table: Dict[int, int] = {}  # slot_addr -> resolved_addr

    def register_object(self, name: str, base_addr: int, symbols: Dict[str, int], needed: List[str]):
        self.loaded_objects[name] = {
            "base": base_addr,
            "symbols": symbols,
            "needed": needed
        }
        for s_name, s_val in symbols.items():
            if s_name not in self.global_symbol_table:
                self.global_symbol_table[s_name] = base_addr + s_val

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self.global_symbol_table.get(name)

    def apply_relocation(self, reloc_type: ElfRelocType, target_slot: int, sym_name: Optional[str] = None, addend: int = 0, base_addr: int = 0):
        if reloc_type == ElfRelocType.R_X86_64_RELATIVE:
            self.got_table[target_slot] = base_addr + addend
        elif reloc_type in (ElfRelocType.R_X86_64_64, ElfRelocType.R_X86_64_GLOB_DAT):
            sym_addr = self.resolve_symbol(sym_name or "")
            if sym_addr is None:
                raise LookupError(f"Undefined dynamic symbol: {sym_name}")
            self.got_table[target_slot] = sym_addr + addend
        elif reloc_type == ElfRelocType.R_X86_64_JUMP_SLOT:
            if self.eager_binding:
                sym_addr = self.resolve_symbol(sym_name or "")
                if sym_addr is None:
                    raise LookupError(f"Undefined symbol: {sym_name}")
                self.got_table[target_slot] = sym_addr
            else:
                # Lazy: points to PLT0 trampoline
                self.got_table[target_slot] = target_slot + 6

    def dl_runtime_resolve(self, target_slot: int, sym_name: str) -> int:
        """Lazy PLT resolver: patches GOT on first invocation."""
        sym_addr = self.resolve_symbol(sym_name)
        if sym_addr is None:
            raise LookupError(f"Dynamic resolution failed for {sym_name}")
        self.got_table[target_slot] = sym_addr
        return sym_addr


# ============================================================================
# Subsystem 7: Advanced VFS & Filesystems (Features 11, 12, 13, 14, 15)
# ============================================================================

# Feature 11: Btrfs
@dataclasses.dataclass
class BtrfsChunk:
    logical_offset: int
    length: int
    stripe_len: int
    stripes: List[Tuple[int, int]]  # (devid, physical_offset)

    def translate(self, logical: int) -> Optional[int]:
        if self.logical_offset <= logical < self.logical_offset + self.length:
            offset_in_chunk = logical - self.logical_offset
            stripe_nr = (offset_in_chunk // self.stripe_len) % len(self.stripes)
            stripe_offset = (offset_in_chunk // (self.stripe_len * len(self.stripes))) * self.stripe_len + (offset_in_chunk % self.stripe_len)
            phys_base = self.stripes[stripe_nr][1]
            return phys_base + stripe_offset
        return None


class MockBtrfsParser:
    MAGIC = b"_BtrFS_M"

    def __init__(self, raw_disk: bytes):
        self.raw_disk = raw_disk

    def verify_superblock(self) -> bool:
        if len(self.raw_disk) < 0x10000 + 1024:
            return False
        sb_magic = self.raw_disk[0x10000 + 64 : 0x10000 + 72]
        return sb_magic == self.MAGIC


# Feature 12: ZFS
class MockZfsParser:
    UBERBLOCK_MAGIC = 0x00BAB10C

    @staticmethod
    def fletcher4(data: bytes) -> Tuple[int, int, int, int]:
        """ZFS Fletcher4 256-bit checksum."""
        words = struct.unpack(f"<{len(data)//4}I", data)
        a, b, c, d = 0, 0, 0, 0
        for w in words:
            a = (a + w) & 0xFFFFFFFFFFFFFFFF
            b = (b + a) & 0xFFFFFFFFFFFFFFFF
            c = (c + b) & 0xFFFFFFFFFFFFFFFF
            d = (d + c) & 0xFFFFFFFFFFFFFFFF
        return a, b, c, d

    def scan_uberblocks(self, raw_label: bytes) -> Optional[Tuple[int, int]]:
        """Scans 128 uberblock slots (128KB to 256KB) and returns (best_slot, highest_txg)."""
        best_slot = None
        highest_txg = -1
        for i in range(128):
            slot_offset = 128 * 1024 + i * 1024
            if slot_offset + 1024 > len(raw_label):
                break
            slot = raw_label[slot_offset : slot_offset + 1024]
            magic = struct.unpack("<I", slot[:4])[0]
            if magic == self.UBERBLOCK_MAGIC:
                txg = struct.unpack("<Q", slot[8:16])[0]
                if txg > highest_txg:
                    highest_txg = txg
                    best_slot = i
        return (best_slot, highest_txg) if best_slot is not None else None


# Feature 13: F2FS
class MockF2fsParser:
    SUPER_MAGIC = 0xF2F52010
    NAT_ENTRY_PER_BLOCK = 455

    @staticmethod
    def translate_nat(nat_blkaddr: int, nid: int, nat_blocks: Dict[int, bytes]) -> Optional[int]:
        block_idx = nat_blkaddr + (nid // MockF2fsParser.NAT_ENTRY_PER_BLOCK)
        entry_idx = (nid % MockF2fsParser.NAT_ENTRY_PER_BLOCK) * 9
        block = nat_blocks.get(block_idx)
        if not block or len(block) < entry_idx + 9:
            return None
        blk_addr = struct.unpack("<I", block[entry_idx + 5 : entry_idx + 9])[0]
        return blk_addr


# Feature 14: XFS
class MockXfsParser:
    SB_MAGIC = 0x58465342

    @staticmethod
    def inode_to_physical(ino: int, inopblog: int, agblklog: int, agblocks: int, blocksize: int, inodesize: int) -> int:
        """Decodes 64-bit XFS inode into exact physical disk byte offset."""
        agno = ino >> (inopblog + agblklog)
        agbno = (ino >> inopblog) & ((1 << agblklog) - 1)
        offset_in_block = (ino & ((1 << inopblog) - 1)) * inodesize
        return (agno * agblocks + agbno) * blocksize + offset_in_block


# Feature 15: ISO9660 Rock Ridge & Joliet
class MockIso9660ExtendedParser:
    @staticmethod
    def parse_joliet_name(raw_bytes: bytes) -> str:
        """Decodes Joliet UCS-2 Big-Endian filename, stripping ISO ;1 version."""
        try:
            s = raw_bytes.decode("utf-16be").split(";")[0]
            return s
        except UnicodeDecodeError:
            return ""

    @staticmethod
    def parse_rock_ridge_susp(susp_bytes: bytes) -> Dict[str, Any]:
        """Parses SUSP records (RR, NM, PX, SL, TF)."""
        idx = 0
        records = {}
        while idx + 4 <= len(susp_bytes):
            sig = susp_bytes[idx : idx + 2]
            length = susp_bytes[idx + 2]
            if length < 4 or idx + length > len(susp_bytes):
                break
            payload = susp_bytes[idx + 4 : idx + length]
            if sig == b"NM":
                # Alternate name (flag at byte 0)
                name = payload[1:].decode("utf-8", errors="replace")
                records["NM"] = name
            elif sig == b"PX":
                # POSIX attributes (mode: 8B, links: 8B, uid: 8B, gid: 8B)
                records["PX"] = "POSIX_ATTRS_VALID"
            elif sig == b"SL":
                # Symlink target (flag at byte 0)
                records["SL"] = payload[1:].decode("utf-8", errors="replace")
            elif sig == b"RR":
                records["RR"] = True
            idx += length
        return records


# ============================================================================
# Subsystem 8: Hardware USB Stack (Features 16, 17, 18)
# ============================================================================

# Feature 16: xHCI
@dataclasses.dataclass
class XhciTrb:
    parameter: int = 0
    status: int = 0
    control: int = 0

    @property
    def cycle_bit(self) -> bool:
        return bool(self.control & 1)

    @property
    def trb_type(self) -> int:
        return (self.control >> 10) & 0x3F


class MockXhciRing:
    def __init__(self, size: int = 16):
        self.size = size
        self.ring = [XhciTrb() for _ in range(size)]
        self.enqueue_idx = 0
        self.dequeue_idx = 0
        self.producer_cycle = True
        self.consumer_cycle = True

    def enqueue(self, trb_type: int, param: int = 0, status: int = 0) -> int:
        idx = self.enqueue_idx
        ctrl = (trb_type << 10) | (1 if self.producer_cycle else 0)
        self.ring[idx] = XhciTrb(param, status, ctrl)
        self.enqueue_idx = (self.enqueue_idx + 1) % self.size
        if self.enqueue_idx == 0:
            self.producer_cycle = not self.producer_cycle
        return idx

    def dequeue(self) -> Optional[XhciTrb]:
        trb = self.ring[self.dequeue_idx]
        if trb.cycle_bit == self.consumer_cycle:
            self.dequeue_idx = (self.dequeue_idx + 1) % self.size
            if self.dequeue_idx == 0:
                self.consumer_cycle = not self.consumer_cycle
            return trb
        return None


# Feature 17: EHCI
@dataclasses.dataclass
class EhciQtd:
    next_qtd: int = 1  # 1 = Terminate
    token: int = 0x80  # Active = 0x80
    buffer_ptr: int = 0
    total_bytes: int = 0


@dataclasses.dataclass
class EhciQueueHead:
    horizontal_link: int = 1
    endpoint_char: int = 0
    endpoint_cap: int = 0
    current_qtd: int = 0
    overlay: EhciQtd = dataclasses.field(default_factory=EhciQtd)


class MockEhciController:
    def __init__(self):
        self.usbcmd = 0
        self.usbsts = 0x1000  # HCHalted = 1
        self.async_list_addr = 0
        self.periodic_list_base = 0

    def start(self):
        self.usbcmd |= 1  # Run
        self.usbsts &= ~0x1000  # Running

    def stop(self):
        self.usbcmd &= ~1
        self.usbsts |= 0x1000  # HCHalted


# Feature 18: USB HID Driver
class MockUsbHidDecoder:
    BOOT_KEYBOARD_MAP = {
        0x04: "a", 0x05: "b", 0x06: "c", 0x28: "\n", 0x2C: " "
    }

    @staticmethod
    def decode_keyboard(packet: bytes) -> Tuple[int, List[str]]:
        """Decodes 8-byte Boot Keyboard packet: [modifiers, res, k0..k5]."""
        if len(packet) < 8:
            return 0, []
        modifiers = packet[0]
        keys = []
        for b in packet[2:8]:
            if b in MockUsbHidDecoder.BOOT_KEYBOARD_MAP:
                keys.append(MockUsbHidDecoder.BOOT_KEYBOARD_MAP[b])
        return modifiers, keys

    @staticmethod
    def decode_mouse(packet: bytes) -> Tuple[int, int, int]:
        """Decodes 3-byte Boot Mouse packet: [buttons, delta_x, delta_y]."""
        if len(packet) < 3:
            return 0, 0, 0
        buttons = packet[0]
        # Sign-extend 8-bit signed deltas
        dx = struct.unpack("b", bytes([packet[1]]))[0]
        dy = struct.unpack("b", bytes([packet[2]]))[0]
        return buttons, dx, dy


# ============================================================================
# Subsystem 9: Netfilter & Advanced Packet Routing (Features 19, 20)
# ============================================================================

class NetfilterHook(enum.IntEnum):
    PREROUTING  = 0
    LOCAL_IN    = 1
    FORWARD     = 2
    LOCAL_OUT   = 3
    POSTROUTING = 4


class NfVerdict(enum.IntEnum):
    DROP   = 0
    ACCEPT = 1
    STOLEN = 2
    QUEUE  = 3
    REPEAT = 4
    STOP   = 5


@dataclasses.dataclass
class Packet5Tuple:
    proto: int  # 6=TCP, 17=UDP, 1=ICMP
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int


class MockNetfilterEngine:
    def __init__(self):
        # hook -> list of (priority, rule_fn)
        self.hooks: Dict[NetfilterHook, List[Tuple[int, Callable]]] = collections.defaultdict(list)

    def register_rule(self, hook: NetfilterHook, priority: int, rule_fn: Callable[[Packet5Tuple], NfVerdict]):
        self.hooks[hook].append((priority, rule_fn))
        self.hooks[hook].sort(key=lambda x: x[0])

    def traverse(self, hook: NetfilterHook, pkt: Packet5Tuple) -> NfVerdict:
        for _, rule in self.hooks.get(hook, []):
            verdict = rule(pkt)
            if verdict != NfVerdict.ACCEPT:
                return verdict
        return NfVerdict.ACCEPT


class TcpConntrackState(enum.Enum):
    NONE = 0
    SYN_SENT = 1
    SYN_RECV = 2
    ESTABLISHED = 3
    FIN_WAIT = 4
    CLOSE = 5


class MockConntrackNatTable:
    def __init__(self):
        self.entries: Dict[Tuple[int, str, str, int, int], Dict[str, Any]] = {}
        self.snat_rules: List[Dict[str, Any]] = []
        self.dnat_rules: List[Dict[str, Any]] = []

    def update_tcp(self, pkt: Packet5Tuple, flags: str) -> TcpConntrackState:
        k = (pkt.proto, pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        rev_k = (pkt.proto, pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port)
        
        entry = self.entries.get(k) or self.entries.get(rev_k)
        if not entry:
            entry = {"state": TcpConntrackState.NONE, "dir": "ORIG"}
            self.entries[k] = entry

        cur = entry["state"]
        if flags == "SYN":
            entry["state"] = TcpConntrackState.SYN_SENT
        elif flags == "SYN-ACK" and cur == TcpConntrackState.SYN_SENT:
            entry["state"] = TcpConntrackState.SYN_RECV
        elif flags == "ACK" and cur == TcpConntrackState.SYN_RECV:
            entry["state"] = TcpConntrackState.ESTABLISHED
        elif "FIN" in flags:
            entry["state"] = TcpConntrackState.FIN_WAIT

        return entry["state"]

    @staticmethod
    def rfc1624_update_checksum(old_csum: int, old_val: int, new_val: int) -> int:
        """RFC 1624 incremental ones'-complement checksum update in O(1)."""
        hc = ~old_csum & 0xFFFF
        m = ~old_val & 0xFFFF
        m_prime = new_val & 0xFFFF
        res = hc + m + m_prime
        while (res >> 16) > 0:
            res = (res & 0xFFFF) + (res >> 16)
        return (~res) & 0xFFFF


# ============================================================================
# Subsystem 11: Hardware Virtualization (KVM/VMX/SVM) (Feature 21)
# ============================================================================

class VmExitReason(enum.IntEnum):
    EXCEPTION_NMI   = 0
    EXTERNAL_INTR   = 1
    TRIPLE_FAULT    = 2
    CPUID           = 10
    HLT             = 12
    VMCALL          = 18
    IO_INSTRUCTION  = 30
    EPT_VIOLATION   = 48


@dataclasses.dataclass
class KvmExit:
    reason: VmExitReason
    port: int = 0
    size: int = 0
    is_in: bool = False
    gpa: int = 0
    val: int = 0


class MockVmcsPage:
    PAGE_SIZE = 4096

    def __init__(self, revision_id: int = 0x12):
        self.data = bytearray(self.PAGE_SIZE)
        # Store revision ID at byte 0
        struct.pack_into("<I", self.data, 0, revision_id)
        self.fields: Dict[int, int] = {}

    def vmwrite(self, field: int, val: int):
        self.fields[field] = val

    def vmread(self, field: int) -> int:
        return self.fields.get(field, 0)


class MockVmcbPage:
    PAGE_SIZE = 4096

    def __init__(self):
        self.control_area = bytearray(1024)
        self.state_save_area = bytearray(3072)
        self.intercepts = 0
        self.asid = 1

    def set_intercept(self, bit: int):
        self.intercepts |= (1 << bit)


class MockKvmVcpuRunLoop:
    def __init__(self, vmcs: MockVmcsPage):
        self.vmcs = vmcs
        self.rip = 0x1000
        self.rax = 0
        self.pending_vector: Optional[int] = None

    def inject_interrupt(self, vector: int):
        self.pending_vector = vector

    def step(self, exit_reason: VmExitReason, **kwargs) -> KvmExit:
        if self.pending_vector is not None:
            # Deliver interrupt
            vec = self.pending_vector
            self.pending_vector = None
            return KvmExit(reason=VmExitReason.EXTERNAL_INTR, val=vec)

        if exit_reason == VmExitReason.CPUID:
            self.rax = 0x80000001
            self.rip += 2
            return KvmExit(reason=VmExitReason.CPUID)
        elif exit_reason == VmExitReason.HLT:
            return KvmExit(reason=VmExitReason.HLT)
        elif exit_reason == VmExitReason.IO_INSTRUCTION:
            port = kwargs.get("port", 0x3F8)
            is_in = kwargs.get("is_in", False)
            return KvmExit(reason=VmExitReason.IO_INSTRUCTION, port=port, is_in=is_in)
        elif exit_reason == VmExitReason.EPT_VIOLATION:
            gpa = kwargs.get("gpa", 0xFEE00000)
            return KvmExit(reason=VmExitReason.EPT_VIOLATION, gpa=gpa)
        elif exit_reason == VmExitReason.VMCALL:
            return KvmExit(reason=VmExitReason.VMCALL)
        return KvmExit(reason=exit_reason)
