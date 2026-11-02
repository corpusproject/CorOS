"""
CorOS End-to-End Test Infrastructure Common Framework
=====================================================
CorOS/tests/e2e/common.py

Provides authoritative models, fixtures, assertion utilities, hardware/kernel
structure simulators, and oracle functions for the 4-tier E2E test suite.
Zero external dependencies (pure Python standard library).
"""

import collections
import dataclasses
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# ---------------------------------------------------------------------------
# Path Anchors
# ---------------------------------------------------------------------------
TESTS_E2E_DIR = Path(__file__).resolve().parent
COROS_ROOT = TESTS_E2E_DIR.parent.parent
WORKSPACE_ROOT = COROS_ROOT.parent

# ---------------------------------------------------------------------------
# Architecture and Boot Constants
# ---------------------------------------------------------------------------
ARCH_X86_64 = 1
ARCH_AARCH64 = 2
ARCH_RISCV64 = 3

BOOTINFO_MAGIC = 0x544F4F4253524F43 # 'CORSBOOT'
BOOTINFO_VERSION = 1
BOOTINFO_SIZE = 240

PAGE_SIZE_4K = 4096
PAGE_SIZE_2M = 2 * 1024 * 1024
PAGE_SIZE_1G = 1024 * 1024 * 1024

# Page Table Flags (Multi-Arch Universal Abstraction)
PAGE_PRESENT = 1 << 0
PAGE_WRITABLE = 1 << 1
PAGE_USER = 1 << 2
PAGE_WRITE_THROUGH = 1 << 3
PAGE_NO_CACHE = 1 << 4
PAGE_ACCESSED = 1 << 5
PAGE_DIRTY = 1 << 6
PAGE_HUGE = 1 << 7
PAGE_GLOBAL = 1 << 8
PAGE_NO_EXECUTE = 1 << 63

# ---------------------------------------------------------------------------
# POSIX Standard Errno Constants
# ---------------------------------------------------------------------------
EPERM = 1
ENOENT = 2
ESRCH = 3
EINTR = 4
EIO = 5
ENXIO = 6
E2BIG = 7
ENOEXEC = 8
EBADF = 9
ECHILD = 10
EAGAIN = 11
ENOMEM = 12
EACCES = 13
EFAULT = 14
EBUSY = 16
EEXIST = 17
EXDEV = 18
ENODEV = 19
ENOTDIR = 20
EISDIR = 21
EINVAL = 22
ENFILE = 23
EMFILE = 24
ENOTTY = 25
EFBIG = 27
ENOSPC = 28
ESPIPE = 29
EROFS = 30
EMLINK = 31
EPIPE = 32
ENAMETOOLONG = 36
ENOSYS = 38
ENOTEMPTY = 39
ELOOP = 40
ENOTSOCK = 88
EPROTONOSUPPORT = 93
EAFNOSUPPORT = 97
EADDRINUSE = 98
EADDRNOTAVAIL = 99
ENETDOWN = 100
ENETUNREACH = 101
ECONNRESET = 104
EISCONN = 106
ENOTCONN = 107
ETIMEDOUT = 110
ECONNREFUSED = 111

# ---------------------------------------------------------------------------
# Syscall ABI Vector Numbers (Linux x86_64 ABI Compatible)
# ---------------------------------------------------------------------------
SYS_READ = 0
SYS_WRITE = 1
SYS_OPEN = 2
SYS_CLOSE = 3
SYS_STAT = 4
SYS_FSTAT = 5
SYS_LSTAT = 6
SYS_POLL = 7
SYS_LSEEK = 8
SYS_MMAP = 9
SYS_MPROTECT = 10
SYS_MUNMAP = 11
SYS_BRK = 12
SYS_RT_SIGACTION = 13
SYS_RT_SIGPROCMASK = 14
SYS_RT_SIGRETURN = 15
SYS_IOCTL = 16
SYS_PREAD64 = 17
SYS_PWRITE64 = 18
SYS_READV = 19
SYS_WRITEV = 20
SYS_ACCESS = 21
SYS_PIPE = 22
SYS_SELECT = 23
SYS_SCHED_YIELD = 24
SYS_MREMAP = 25
SYS_MSYNC = 26
SYS_MINCORE = 27
SYS_MADVISE = 28
SYS_SHMGET = 29
SYS_SHMAT = 30
SYS_SHMCTL = 31
SYS_DUP = 32
SYS_DUP2 = 33
SYS_PAUSE = 34
SYS_NANOSLEEP = 35
SYS_GETITIMER = 36
SYS_ALARM = 37
SYS_SETITIMER = 38
SYS_GETPID = 39
SYS_SENDFILE = 40
SYS_SOCKET = 41
SYS_CONNECT = 42
SYS_ACCEPT = 43
SYS_SENDTO = 44
SYS_RECVFROM = 45
SYS_SENDMSG = 46
SYS_RECVMSG = 47
SYS_SHUTDOWN = 48
SYS_BIND = 49
SYS_LISTEN = 50
SYS_GETSOCKNAME = 51
SYS_GETPEERNAME = 52
SYS_SOCKETPAIR = 53
SYS_SETSOCKOPT = 54
SYS_GETSOCKOPT = 55
SYS_CLONE = 56
SYS_FORK = 57
SYS_VFORK = 58
SYS_EXECVE = 59
SYS_EXIT = 60
SYS_WAIT4 = 61
SYS_KILL = 62
SYS_UNAME = 63
SYS_SEMGET = 64
SYS_SEMOP = 65
SYS_SEMCTL = 66
SYS_SHMDT = 67
SYS_MSGGET = 68
SYS_MSGSND = 69
SYS_MSGRCV = 70
SYS_MSGCTL = 71
SYS_FCNTL = 72
SYS_FLOCK = 73
SYS_FSYNC = 74
SYS_FDATASYNC = 75
SYS_TRUNCATE = 76
SYS_FTRUNCATE = 77
SYS_GETDENTS = 78
SYS_GETCWD = 79
SYS_CHDIR = 80
SYS_FCHDIR = 81
SYS_RENAME = 82
SYS_MKDIR = 83
SYS_RMDIR = 84
SYS_CREAT = 85
SYS_LINK = 86
SYS_UNLINK = 87
SYS_SYMLINK = 88
SYS_READLINK = 89
SYS_CHMOD = 90
SYS_FCHMOD = 91
SYS_CHOWN = 92
SYS_FCHOWN = 93
SYS_LCHOWN = 94
SYS_UMASK = 95
SYS_GETTIMEOFDAY = 96
SYS_GETRLIMIT = 97
SYS_GETRUSAGE = 98
SYS_SYSINFO = 99
SYS_TIMES = 100
SYS_PTRACE = 101
SYS_GETUID = 102
SYS_SYSLOG = 103
SYS_GETGID = 104
SYS_SETUID = 105
SYS_SETGID = 106
SYS_GETEUID = 107
SYS_GETEGID = 108
SYS_SETPGID = 109
SYS_GETPPID = 110
SYS_GETPGRP = 111
SYS_SETSID = 112
SYS_SETREUID = 113
SYS_SETREGID = 114
SYS_GETGROUPS = 115
SYS_SETGROUPS = 116
SYS_SETRESUID = 117
SYS_GETRESUID = 118
SYS_SETRESGID = 119
SYS_GETRESGID = 120
SYS_GETPGID = 121
SYS_SETFSUID = 122
SYS_SETFSGID = 123
SYS_GETSID = 124
SYS_CAPGET = 125
SYS_CAPSET = 126
SYS_RT_SIGPENDING = 127
SYS_RT_SIGTIMEDWAIT = 128
SYS_RT_SIGQUEUEINFO = 129
SYS_RT_SIGSUSPEND = 130
SYS_SIGALTSTACK = 131
SYS_UTIME = 132
SYS_MKNOD = 133
SYS_PERSONALITY = 135
SYS_STATFS = 137
SYS_FSTATFS = 138
SYS_GETPRIORITY = 140
SYS_SETPRIORITY = 141
SYS_SCHED_SETPARAM = 142
SYS_SCHED_GETPARAM = 143
SYS_SCHED_SETSCHEDULER = 144
SYS_SCHED_GETSCHEDULER = 145
SYS_SCHED_GET_PRIORITY_MAX = 146
SYS_SCHED_GET_PRIORITY_MIN = 147
SYS_SCHED_RR_GET_INTERVAL = 148
SYS_MLOCK = 149
SYS_MUNLOCK = 150
SYS_MLOCKALL = 151
SYS_MUNLOCKALL = 152
SYS_PIVOT_ROOT = 155
SYS_PRCTL = 157
SYS_ARCH_PRCTL = 158
SYS_SETRLIMIT = 160
SYS_CHROOT = 161
SYS_SYNC = 162
SYS_MOUNT = 165
SYS_UMOUNT2 = 166
SYS_REBOOT = 169
SYS_SETHOSTNAME = 170
SYS_SETDOMAINNAME = 171
SYS_GETTID = 186
SYS_TKILL = 200
SYS_TIME = 201
SYS_FUTEX = 202
SYS_SCHED_SETAFFINITY = 203
SYS_SCHED_GETAFFINITY = 204
SYS_EPOLL_CREATE = 213
SYS_GETDENTS64 = 217
SYS_SET_TID_ADDRESS = 218
SYS_TIMER_CREATE = 222
SYS_TIMER_SETTIME = 223
SYS_TIMER_GETTIME = 224
SYS_TIMER_DELETE = 226
SYS_CLOCK_SETTIME = 227
SYS_CLOCK_GETTIME = 228
SYS_CLOCK_GETRES = 229
SYS_CLOCK_NANOSLEEP = 230
SYS_EXIT_GROUP = 231
SYS_EPOLL_WAIT = 232
SYS_EPOLL_CTL = 233
SYS_TGKILL = 234
SYS_OPENAT = 257
SYS_MKDIRAT = 258
SYS_NEWFSTATAT = 262
SYS_UNLINKAT = 263
SYS_RENAMEAT = 264
SYS_UNSHARE = 272
SYS_SPLICE = 275
SYS_EVENTFD = 284
SYS_FALLOCATE = 285
SYS_ACCEPT4 = 288
SYS_EVENTFD2 = 290
SYS_EPOLL_CREATE1 = 291
SYS_DUP3 = 292
SYS_PIPE2 = 293
SYS_PRLIMIT64 = 302
SYS_SETNS = 308
SYS_GETCPU = 309
SYS_RENAMEAT2 = 316
SYS_SECCOMP = 317
SYS_GETRANDOM = 318
SYS_MEMFD_CREATE = 319
SYS_BPF = 321
SYS_EXECVEAT = 322

# ---------------------------------------------------------------------------
# Test Assertion Infrastructure
# ---------------------------------------------------------------------------
class TestFailure(Exception):
    pass

def assert_true(condition: bool, msg: str = "Condition is False"):
    if not condition:
        raise TestFailure(msg)

def assert_false(condition: bool, msg: str = "Condition is True"):
    if condition:
        raise TestFailure(msg)

def assert_eq(actual: Any, expected: Any, msg: str = ""):
    if actual != expected:
        details = f"Expected {expected!r}, got {actual!r}"
        raise TestFailure(f"{msg}: {details}" if msg else details)

def assert_ne(actual: Any, expected: Any, msg: str = ""):
    if actual == expected:
        details = f"Expected not {expected!r}, but was equal"
        raise TestFailure(f"{msg}: {details}" if msg else details)

def assert_in(item: Any, container: Any, msg: str = ""):
    if item not in container:
        details = f"Expected {item!r} in {container!r}"
        raise TestFailure(f"{msg}: {details}" if msg else details)

def assert_not_in(item: Any, container: Any, msg: str = ""):
    if item in container:
        details = f"Expected {item!r} not in {container!r}"
        raise TestFailure(f"{msg}: {details}" if msg else details)

def assert_almost_eq(actual: float, expected: float, delta: float = 0.001, msg: str = ""):
    if abs(actual - expected) > delta:
        details = f"Expected {expected} +/- {delta}, got {actual}"
        raise TestFailure(f"{msg}: {details}" if msg else details)

def assert_raises(exc_type: type, callable_obj: Callable, *args, **kwargs):
    try:
        callable_obj(*args, **kwargs)
    except exc_type:
        return
    except Exception as e:
        raise TestFailure(f"Expected exception {exc_type.__name__}, got {type(e).__name__}: {e}")
    raise TestFailure(f"Expected exception {exc_type.__name__}, but no exception was raised")

# ---------------------------------------------------------------------------
# Test Case & Suite Framework
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class TestCase:
    name: str
    fn: Callable
    tier: int
    feature_id: str = ""
    description: str = ""

class TestSuite:
    def __init__(self, name: str, tier: int):
        self.name = name
        self.tier = tier
        self.tests: List[TestCase] = []

    def add(self, name: str, fn: Callable, feature_id: str = "", description: str = ""):
        self.tests.append(TestCase(name=name, fn=fn, tier=self.tier, feature_id=feature_id, description=description or (fn.__doc__ or "").strip()))

    def run(self, verbose: bool = False) -> Tuple[int, int, List[Dict[str, Any]]]:
        passed = 0
        failed = 0
        details = []

        print(f"\n--- Running [{self.name}] (Tier {self.tier}) - {len(self.tests)} tests ---")
        t0 = time.time()
        for test in self.tests:
            start = time.time()
            try:
                test.fn()
                elapsed = time.time() - start
                passed += 1
                details.append({
                    "name": test.name,
                    "passed": True,
                    "feature_id": test.feature_id,
                    "duration_sec": elapsed,
                    "error": ""
                })
                if verbose:
                    feat_str = f"[{test.feature_id}] " if test.feature_id else ""
                    print(f"  [PASS] {feat_str}{test.name} ({elapsed*1000:.1f}ms)")
            except Exception as e:
                elapsed = time.time() - start
                failed += 1
                err_msg = str(e)
                details.append({
                    "name": test.name,
                    "passed": False,
                    "feature_id": test.feature_id,
                    "duration_sec": elapsed,
                    "error": err_msg
                })
                feat_str = f"[{test.feature_id}] " if test.feature_id else ""
                print(f"  [FAIL] {feat_str}{test.name}: {err_msg}")

        total_elapsed = time.time() - t0
        print(f"Summary for {self.name}: {passed} passed, {failed} failed in {total_elapsed:.3f}s")
        return passed, failed, details

# ---------------------------------------------------------------------------
# BootInfo Specification & Multi-Arch Model (F01)
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class BootInfo:
    magic: int = BOOTINFO_MAGIC
    version: int = BOOTINFO_VERSION
    size: int = BOOTINFO_SIZE
    architecture: int = ARCH_X86_64
    flags: int = 0
    bootloader_version: int = 1
    _reserved0: int = 0
    bootloader_image_addr: int = 0x1000000
    bootloader_image_size: int = 65536
    memory_map_addr: int = 0x10000000
    memory_map_size: int = 4096
    descriptor_size: int = 48
    descriptor_version: int = 1
    firmware_revision: int = 0x00020000
    acpi_rsdp_addr: int = 0x000E0000
    framebuffer_addr: int = 0xE0000000
    framebuffer_size: int = 1920 * 1080 * 4
    fb_width: int = 1920
    fb_height: int = 1080
    fb_stride: int = 1920
    fb_pixel_format: int = 1 # PixelBlueGreenRedReserved8BitPerColor
    red_mask: int = 0x00FF0000
    green_mask: int = 0x0000FF00
    blue_mask: int = 0x000000FF
    reserved_mask: int = 0xFF000000
    kernel_image_addr: int = 0x2000000
    kernel_image_size: int = 3729408
    cmdline: str = "console=ttyS0,115200 root=/dev/nvme0n1p2 quiet"
    initrd_addr: int = 0x20000000
    initrd_size: int = 8 * 1024 * 1024
    boot_slot: int = 0
    last_boot_status: int = 0

    # Format: Q:magic (8), IIIIII (24), QQQQQ (40), II (8), QQQ (24), IIIIIIII (32), QQ (16), 64s (64), QQ (16), II (8) = 240 bytes
    STRUCT_FMT = "<QIIIIIIQQQQQIIQQQIIIIIIIIQQ64sQQII"

    def pack(self) -> bytes:
        cmd_bytes = self.cmdline.encode("ascii")[:64].ljust(64, b"\x00")
        raw = struct.pack(
            self.STRUCT_FMT,
            self.magic, self.version, self.size, self.architecture, self.flags, self.bootloader_version, self._reserved0,
            self.bootloader_image_addr, self.bootloader_image_size,
            self.memory_map_addr, self.memory_map_size, self.descriptor_size,
            self.descriptor_version, self.firmware_revision,
            self.acpi_rsdp_addr, self.framebuffer_addr, self.framebuffer_size,
            self.fb_width, self.fb_height, self.fb_stride, self.fb_pixel_format,
            self.red_mask, self.green_mask, self.blue_mask, self.reserved_mask,
            self.kernel_image_addr, self.kernel_image_size,
            cmd_bytes,
            self.initrd_addr, self.initrd_size,
            self.boot_slot, self.last_boot_status
        )
        return raw

    @classmethod
    def unpack(cls, data: bytes) -> "BootInfo":
        if len(data) < BOOTINFO_SIZE:
            raise ValueError(f"BootInfo buffer too short: {len(data)} < {BOOTINFO_SIZE}")
        fields = struct.unpack(cls.STRUCT_FMT, data[:BOOTINFO_SIZE])
        magic = fields[0]
        ver, sz, arch, flags, bl_ver, rsv0 = fields[1:7]
        bl_addr, bl_sz, mmap_addr, mmap_sz, desc_sz = fields[7:12]
        desc_ver, fw_rev = fields[12:14]
        rsdp, fb_addr, fb_sz = fields[14:17]
        fb_w, fb_h, fb_stride, fb_fmt, r_mask, g_mask, b_mask, rsv_mask = fields[17:25]
        kern_addr, kern_sz = fields[25:27]
        cmdline = fields[27].rstrip(b"\x00").decode("ascii", errors="ignore")
        initrd_addr, initrd_sz, b_slot, b_stat = fields[28:32]
        return cls(
            magic=magic, version=ver, size=sz, architecture=arch, flags=flags,
            bootloader_version=bl_ver, _reserved0=rsv0,
            bootloader_image_addr=bl_addr, bootloader_image_size=bl_sz,
            memory_map_addr=mmap_addr, memory_map_size=mmap_sz, descriptor_size=desc_sz,
            descriptor_version=desc_ver, firmware_revision=fw_rev,
            acpi_rsdp_addr=rsdp, framebuffer_addr=fb_addr, framebuffer_size=fb_sz,
            fb_width=fb_w, fb_height=fb_h, fb_stride=fb_stride, fb_pixel_format=fb_fmt,
            red_mask=r_mask, green_mask=g_mask, blue_mask=b_mask, reserved_mask=rsv_mask,
            kernel_image_addr=kern_addr, kernel_image_size=kern_sz,
            cmdline=cmdline, initrd_addr=initrd_addr, initrd_size=initrd_sz,
            boot_slot=b_slot, last_boot_status=b_stat
        )

    def validate(self) -> Tuple[bool, str]:
        if self.magic != BOOTINFO_MAGIC:
            return False, f"Invalid magic: 0x{self.magic:016X}"
        if self.version != BOOTINFO_VERSION:
            return False, f"Unsupported version: {self.version}"
        if self.size < BOOTINFO_SIZE:
            return False, f"Invalid struct size: {self.size} < {BOOTINFO_SIZE}"
        if self.architecture not in (ARCH_X86_64, ARCH_AARCH64, ARCH_RISCV64):
            return False, f"Unsupported architecture: {self.architecture}"
        if self.memory_map_addr == 0 or self.memory_map_size == 0:
            return False, "Invalid memory map pointer or size"
        if self.framebuffer_addr == 0 or self.fb_width == 0 or self.fb_height == 0:
            return False, "Invalid framebuffer configuration"
        return True, "Valid"

# ---------------------------------------------------------------------------
# Architecture HAL Traits & Register Frames (F02, F03, F04, F05, F07)
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class X86_64SyscallRegisters:
    rax: int = 0
    rdi: int = 0
    rsi: int = 0
    rdx: int = 0
    r10: int = 0
    r8: int = 0
    r9: int = 0
    rflags: int = 0x202 # IF flag
    rcx: int = 0       # User RIP
    rsp: int = 0       # User RSP

@dataclasses.dataclass
class AArch64SyscallRegisters:
    x8: int = 0        # Syscall number
    x0: int = 0        # Arg0 / Return val
    x1: int = 0
    x2: int = 0
    x3: int = 0
    x4: int = 0
    x5: int = 0
    sp: int = 0
    elr: int = 0       # Return PC
    spsr: int = 0

@dataclasses.dataclass
class Riscv64SyscallRegisters:
    a7: int = 0        # Syscall number
    a0: int = 0        # Arg0 / Return val
    a1: int = 0
    a2: int = 0
    a3: int = 0
    a4: int = 0
    a5: int = 0
    sp: int = 0
    sepc: int = 0      # Return PC
    sstatus: int = 0

class MockCpuOps:
    def __init__(self, arch: int = ARCH_X86_64, cpu_id: int = 0):
        self.arch = arch
        self.cpu_id = cpu_id
        self.interrupts_enabled = False
        self.halted = False
        self.relax_count = 0

    def enable_interrupts(self):
        self.interrupts_enabled = True

    def disable_interrupts(self):
        self.interrupts_enabled = False

    def is_interrupts_enabled(self) -> bool:
        return self.interrupts_enabled

    def halt(self):
        self.halted = True

    def relax(self):
        self.relax_count += 1

    def current_cpu_id(self) -> int:
        return self.cpu_id

class MockTimerOps:
    def __init__(self, ticks_per_sec: int = 1_000_000_000): # 1 GHz TSC
        self.ticks_per_sec = ticks_per_sec
        self.ticks = 0

    def read_ticks(self) -> int:
        return self.ticks

    def ticks_per_second(self) -> int:
        return self.ticks_per_sec

    def sleep_ns(self, ns: int):
        self.ticks += (ns * self.ticks_per_sec) // 1_000_000_000

class MockSmpOps:
    def __init__(self, num_cores: int = 4):
        self.num_cores = num_cores
        self.online_cores: Set[int] = {0}
        self.ipi_log: List[Tuple[int, int]] = []

    def boot_secondary_cores(self, entry: int) -> int:
        for i in range(1, self.num_cores):
            self.online_cores.add(i)
        return len(self.online_cores)

    def send_ipi(self, target_cpu: int, vector: int):
        assert_true(target_cpu < self.num_cores, f"Target CPU {target_cpu} out of range")
        self.ipi_log.append((target_cpu, vector))

# ---------------------------------------------------------------------------
# Multi-Arch Page Table Walker & MMU (F06, F13)
# ---------------------------------------------------------------------------
class MultiArchPageTable:
    def __init__(self, arch: int = ARCH_X86_64, levels: int = 4):
        self.arch = arch
        self.levels = levels
        # Map vaddr (page-aligned) -> (paddr, flags)
        self.mappings: Dict[int, Tuple[int, int]] = {}
        self.root_paddr: int = 0x100000 # PML4 or TTBR or satp base
        self.tlb_flushes: List[int] = []

    def map_page(self, vaddr: int, paddr: int, flags: int):
        page_mask = ~(PAGE_SIZE_4K - 1)
        aligned_vaddr = vaddr & page_mask
        aligned_paddr = paddr & page_mask
        self.mappings[aligned_vaddr] = (aligned_paddr, flags)

    def unmap_page(self, vaddr: int) -> bool:
        aligned = vaddr & ~(PAGE_SIZE_4K - 1)
        if aligned in self.mappings:
            del self.mappings[aligned]
            return True
        return False

    def translate(self, vaddr: int) -> Optional[Tuple[int, int]]:
        page_offset = vaddr & (PAGE_SIZE_4K - 1)
        aligned_vaddr = vaddr & ~(PAGE_SIZE_4K - 1)
        if aligned_vaddr in self.mappings:
            paddr_base, flags = self.mappings[aligned_vaddr]
            return (paddr_base + page_offset, flags)
        return None

    def flush_tlb(self, vaddr: int):
        self.tlb_flushes.append(vaddr)

    def flush_tlb_all(self):
        self.tlb_flushes.append(-1)

# ---------------------------------------------------------------------------
# Buddy Allocator & SLUB Cache (F13)
# ---------------------------------------------------------------------------
class MockBuddyAllocator:
    def __init__(self, total_pages: int = 16384, max_order: int = 11): # 64 MiB
        self.total_pages = total_pages
        self.max_order = max_order
        # free_lists[order] = set of pfn
        self.free_lists: List[Set[int]] = [set() for _ in range(max_order + 1)]
        # Initially add largest power-of-two blocks
        pfn = 0
        while pfn < total_pages:
            order = min(max_order, (total_pages - pfn).bit_length() - 1)
            while (pfn % (1 << order)) != 0 and order > 0:
                order -= 1
            self.free_lists[order].add(pfn)
            pfn += (1 << order)
        self.allocated: Dict[int, int] = {} # pfn -> order

    def allocate(self, order: int) -> Optional[int]:
        if order > self.max_order or order < 0:
            return None
        # Find first non-empty block at or above requested order
        found_order = -1
        for o in range(order, self.max_order + 1):
            if self.free_lists[o]:
                found_order = o
                break
        if found_order == -1:
            return None # Out of memory

        pfn = self.free_lists[found_order].pop()
        # Split down to requested order
        while found_order > order:
            found_order -= 1
            buddy_pfn = pfn + (1 << found_order)
            self.free_lists[found_order].add(buddy_pfn)

        self.allocated[pfn] = order
        return pfn

    def free(self, pfn: int, order: int):
        assert_true(pfn in self.allocated, f"Double free or unallocated pfn {pfn}")
        assert_eq(self.allocated[pfn], order, "Free order mismatch")
        del self.allocated[pfn]

        curr_pfn = pfn
        curr_order = order
        while curr_order < self.max_order:
            buddy_pfn = curr_pfn ^ (1 << curr_order)
            if buddy_pfn in self.free_lists[curr_order]:
                self.free_lists[curr_order].remove(buddy_pfn)
                curr_pfn = min(curr_pfn, buddy_pfn)
                curr_order += 1
            else:
                break
        self.free_lists[curr_order].add(curr_pfn)

class MockSlubCache:
    def __init__(self, object_size: int, alignment: int = 8):
        self.object_size = max(object_size, 8)
        self.alignment = alignment
        self.allocated_objects: Set[int] = set()
        self.next_obj_id = 1000

    def alloc(self) -> int:
        ptr = self.next_obj_id
        self.next_obj_id += self.object_size
        self.allocated_objects.add(ptr)
        return ptr

    def free(self, ptr: int):
        assert_true(ptr in self.allocated_objects, f"Bad SLUB free: {ptr}")
        self.allocated_objects.remove(ptr)

# ---------------------------------------------------------------------------
# Hardware Driver Simulation: ATA IDE, AHCI SATA, NVMe, PCI ECAM (F08..F12)
# ---------------------------------------------------------------------------
class MockAtaIdeController:
    """Legacy ATA PIO Controller: Primary 0x1F0-0x1F7/0x3F6, Secondary 0x170-0x177/0x376."""
    STATUS_ERR = 0x01
    STATUS_DRQ = 0x08
    STATUS_DRDY = 0x40
    STATUS_BSY = 0x80

    def __init__(self, sector_count: int = 65536): # 32 MiB
        self.sector_count = sector_count
        self.storage = bytearray(sector_count * 512)
        self.selected_drive = 0 # 0=Master, 1=Slave
        self.lba = 0
        self.sector_count_reg = 0
        self.status = self.STATUS_DRDY
        self.error = 0

    def select_drive(self, drive: int, lba_head: int):
        self.selected_drive = drive
        self.lba = (self.lba & 0x0FFFFFFF) | ((lba_head & 0x0F) << 24)

    def set_lba28(self, lba: int, count: int):
        self.lba = lba & 0x0FFFFFFF
        self.sector_count_reg = count if count != 0 else 256

    def read_sectors_pio(self) -> bytes:
        assert_true(self.lba + self.sector_count_reg <= self.sector_count, "ATA LBA out of bounds")
        start = self.lba * 512
        end = start + (self.sector_count_reg * 512)
        self.status = self.STATUS_DRDY
        return bytes(self.storage[start:end])

    def write_sectors_pio(self, data: bytes):
        expected_len = self.sector_count_reg * 512
        assert_eq(len(data), expected_len, "ATA PIO data length mismatch")
        assert_true(self.lba + self.sector_count_reg <= self.sector_count, "ATA LBA out of bounds")
        start = self.lba * 512
        end = start + expected_len
        self.storage[start:end] = data
        self.status = self.STATUS_DRDY

class MockPciEcam:
    """PCIe ECAM MMIO space and legacy 0xCF8/0xCFC I/O ports emulator."""
    def __init__(self, ecam_base: int = 0xE0000000):
        self.ecam_base = ecam_base
        # (bus, dev, func) -> bytearray(4096)
        self.devices: Dict[Tuple[int, int, int], bytearray] = {}
        self.cf8_address = 0

    def register_device(self, bus: int, dev: int, func: int, vendor_id: int, device_id: int,
                        class_code: int, subclass: int, prog_if: int, header_type: int = 0x00):
        cfg = bytearray(4096)
        struct.pack_into("<HH", cfg, 0, vendor_id, device_id)
        struct.pack_into("<HH", cfg, 4, 0x0007, 0x0010) # Command, Status
        struct.pack_into("<BBBB", cfg, 8, 0x01, prog_if, subclass, class_code)
        struct.pack_into("<B", cfg, 14, header_type)
        self.devices[(bus, dev, func)] = cfg

    def ecam_read32(self, bus: int, dev: int, func: int, offset: int) -> int:
        if (bus, dev, func) in self.devices and offset + 4 <= 4096:
            return struct.unpack_from("<I", self.devices[(bus, dev, func)], offset)[0]
        return 0xFFFFFFFF

    def ecam_write32(self, bus: int, dev: int, func: int, offset: int, val: int):
        if (bus, dev, func) in self.devices and offset + 4 <= 4096:
            struct.pack_into("<I", self.devices[(bus, dev, func)], offset, val)

    def io_port_cf8_write(self, val: int):
        self.cf8_address = val

    def io_port_cfc_read32(self) -> int:
        if (self.cf8_address & 0x80000000) == 0:
            return 0xFFFFFFFF
        bus = (self.cf8_address >> 16) & 0xFF
        dev = (self.cf8_address >> 11) & 0x1F
        func = (self.cf8_address >> 8) & 0x07
        reg = self.cf8_address & 0xFC
        return self.ecam_read32(bus, dev, func, reg)

class MockBlockDevice:
    def __init__(self, name: str, sector_count: int = 131072, sector_size: int = 512):
        self.name = name
        self.sector_count = sector_count
        self.sector_size = sector_size
        self.storage = bytearray(sector_count * sector_size)
        self.flush_count = 0

    def read_sectors(self, lba: int, count: int) -> bytes:
        assert_true(lba + count <= self.sector_count, f"Read beyond disk end: LBA {lba} + count {count} > {self.sector_count}")
        start = lba * self.sector_size
        end = start + (count * self.sector_size)
        return bytes(self.storage[start:end])

    def write_sectors(self, lba: int, count: int, data: bytes):
        assert_true(lba + count <= self.sector_count, f"Write beyond disk end: LBA {lba} + count {count} > {self.sector_count}")
        assert_eq(len(data), count * self.sector_size, "Write buffer size mismatch")
        start = lba * self.sector_size
        end = start + len(data)
        self.storage[start:end] = data

    def flush(self):
        self.flush_count += 1

# ---------------------------------------------------------------------------
# VirtIO Input & Sound Models (F08, F09)
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class VirtIoInputEvent:
    event_type: int
    code: int
    value: int

class MockVirtIoInput:
    def __init__(self):
        self.event_queue: collections.deque[VirtIoInputEvent] = collections.deque()
        self.status = 0
        self.config_select = 0
        self.config_subsel = 0

    def push_event(self, event_type: int, code: int, value: int):
        self.event_queue.append(VirtIoInputEvent(event_type, code, value))

    def pop_event(self) -> Optional[VirtIoInputEvent]:
        if self.event_queue:
            return self.event_queue.popleft()
        return None

class MockVirtIoSound:
    def __init__(self):
        self.streams: Dict[int, Dict[str, Any]] = {}
        self.pcm_buffers: Dict[int, bytearray] = {}
        self.jacks: List[str] = ["Headphones 3.5mm", "Line Out Front"]

    def set_pcm_params(self, stream_id: int, format_pcm: int, channels: int, rate: int):
        self.streams[stream_id] = {
            "format": format_pcm,
            "channels": channels,
            "rate": rate,
            "active": False
        }
        self.pcm_buffers[stream_id] = bytearray()

    def start_stream(self, stream_id: int):
        assert_in(stream_id, self.streams, "Stream not found")
        self.streams[stream_id]["active"] = True

    def write_pcm_frames(self, stream_id: int, frames: bytes) -> int:
        assert_in(stream_id, self.streams, "Stream not configured")
        assert_true(self.streams[stream_id]["active"], "Stream not started")
        self.pcm_buffers[stream_id].extend(frames)
        return len(frames)

    def stop_stream(self, stream_id: int):
        assert_in(stream_id, self.streams, "Stream not found")
        self.streams[stream_id]["active"] = False

# ---------------------------------------------------------------------------
# Scheduler: Linux 6.6 EEVDF CFS + SCHED_DEADLINE CBS (F15)
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class TaskEntity:
    tid: int
    name: str
    weight: int = 1024 # NICE 0
    vruntime: int = 0
    deadline: int = 0
    runtime: int = 0
    period: int = 0
    is_deadline: bool = False
    state: str = "READY" # READY, RUNNING, SLEEPING, DEAD

class MockEevdfScheduler:
    def __init__(self):
        self.runqueue: List[TaskEntity] = []
        self.current_task: Optional[TaskEntity] = None
        self.min_vruntime: int = 0
        self.context_switches: int = 0

    def add_task(self, task: TaskEntity):
        task.vruntime = self.min_vruntime
        self.runqueue.append(task)

    def schedule(self) -> Optional[TaskEntity]:
        if not self.runqueue:
            return None
        # Prioritize SCHED_DEADLINE tasks with earliest deadline
        dl_tasks = [t for t in self.runqueue if t.is_deadline and t.state in ("READY", "RUNNING")]
        if dl_tasks:
            best = min(dl_tasks, key=lambda t: t.deadline)
        else:
            ready_cfs = [t for t in self.runqueue if not t.is_deadline and t.state in ("READY", "RUNNING")]
            if not ready_cfs:
                return None
            # EEVDF: Pick eligible task with smallest virtual deadline
            best = min(ready_cfs, key=lambda t: t.vruntime)

        if self.current_task != best:
            self.context_switches += 1
            if self.current_task and self.current_task.state == "RUNNING":
                self.current_task.state = "READY"
            best.state = "RUNNING"
            self.current_task = best
            self.min_vruntime = max(self.min_vruntime, best.vruntime)
        return best

    def tick(self, delta_ns: int):
        if self.current_task and self.current_task.state == "RUNNING":
            scaled_delta = (delta_ns * 1024) // self.current_task.weight
            self.current_task.vruntime += scaled_delta
            if self.current_task.is_deadline:
                self.current_task.runtime += delta_ns

# ---------------------------------------------------------------------------
# VFS & Inode Pipeline Simulation (F16)
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class VfsInode:
    ino: int
    mode: int # 0x8000 for regular, 0x4000 for dir
    uid: int = 0
    gid: int = 0
    size: int = 0
    data: bytearray = dataclasses.field(default_factory=bytearray)
    children: Dict[str, int] = dataclasses.field(default_factory=dict) # name -> ino

class MockVfs:
    S_IFREG = 0x8000
    S_IFDIR = 0x4000

    def __init__(self):
        self.inodes: Dict[int, VfsInode] = {}
        self.next_ino = 1
        # Create root inode
        root = VfsInode(ino=self.next_ino, mode=self.S_IFDIR | 0o755)
        self.inodes[root.ino] = root
        self.next_ino += 1

    def mkdir(self, parent_ino: int, name: str, mode: int = 0o755) -> int:
        assert_in(parent_ino, self.inodes, "Parent inode not found")
        parent = self.inodes[parent_ino]
        assert_true((parent.mode & self.S_IFDIR) != 0, "Parent not a directory")
        assert_not_in(name, parent.children, f"Entry {name} already exists")

        new_dir = VfsInode(ino=self.next_ino, mode=self.S_IFDIR | mode)
        self.inodes[new_dir.ino] = new_dir
        self.next_ino += 1
        parent.children[name] = new_dir.ino
        return new_dir.ino

    def create_file(self, parent_ino: int, name: str, mode: int = 0o644) -> int:
        assert_in(parent_ino, self.inodes, "Parent inode not found")
        parent = self.inodes[parent_ino]
        assert_true((parent.mode & self.S_IFDIR) != 0, "Parent not a directory")
        assert_not_in(name, parent.children, f"File {name} already exists")

        new_file = VfsInode(ino=self.next_ino, mode=self.S_IFREG | mode)
        self.inodes[new_file.ino] = new_file
        self.next_ino += 1
        parent.children[name] = new_file.ino
        return new_file.ino

    def write(self, ino: int, offset: int, data: bytes) -> int:
        assert_in(ino, self.inodes, "Inode not found")
        node = self.inodes[ino]
        assert_true((node.mode & self.S_IFREG) != 0, "Not a regular file")
        if offset + len(data) > len(node.data):
            node.data.extend(b"\x00" * (offset + len(data) - len(node.data)))
        node.data[offset:offset+len(data)] = data
        node.size = len(node.data)
        return len(data)

    def read(self, ino: int, offset: int, count: int) -> bytes:
        assert_in(ino, self.inodes, "Inode not found")
        node = self.inodes[ino]
        if offset >= len(node.data):
            return b""
        return bytes(node.data[offset:offset+count])

# ---------------------------------------------------------------------------
# Network Stack & Packet Framing (F20)
# ---------------------------------------------------------------------------
class MockNetworkStack:
    ETH_P_IP = 0x0800
    ETH_P_ARP = 0x0806
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17

    def __init__(self, mac: bytes = b"\x52\x54\x00\x12\x34\x56", ip: str = "192.168.1.100"):
        self.mac = mac
        self.ip = ip
        self.arp_table: Dict[str, bytes] = {}
        self.tx_frames: List[bytes] = []

    def frame_ethernet(self, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
        return dst_mac + self.mac + struct.pack("!H", ethertype) + payload

    def parse_ethernet(self, frame: bytes) -> Tuple[bytes, bytes, int, bytes]:
        assert_true(len(frame) >= 14, "Frame shorter than Ethernet header")
        dst_mac = frame[:6]
        src_mac = frame[6:12]
        ethertype = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]
        return dst_mac, src_mac, ethertype, payload

    def build_ipv4_packet(self, dst_ip: str, proto: int, payload: bytes) -> bytes:
        src_octets = bytes([int(x) for x in self.ip.split(".")])
        dst_octets = bytes([int(x) for x in dst_ip.split(".")])
        total_len = 20 + len(payload)
        hdr_no_csum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0, 64, proto, 0, src_octets, dst_octets)
        csum = self.ip_checksum(hdr_no_csum)
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0, 64, proto, csum, src_octets, dst_octets)
        return hdr + payload

    @staticmethod
    def ip_checksum(data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            s += w
        while (s >> 16) > 0:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

# ---------------------------------------------------------------------------
# Cryptographic Known Answer Tests (KAT) & Oracles (F30, Tier 1/2)
# ---------------------------------------------------------------------------
class CryptoOracle:
    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def sha512(data: bytes) -> bytes:
        return hashlib.sha512(data).digest()

    @staticmethod
    def hmac_sha256(key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, hashlib.sha256).digest()

    @staticmethod
    def blake2b_256(data: bytes) -> bytes:
        return hashlib.blake2b(data, digest_size=32).digest()

    @staticmethod
    def chacha20_keystream_block(key: bytes, counter: int, nonce: bytes) -> bytes:
        """Pure-Python quarter-round ChaCha20 reference block generator (RFC 7539)."""
        assert_eq(len(key), 32, "Key must be 256-bit")
        assert_eq(len(nonce), 12, "Nonce must be 96-bit")

        # Constants: 'expand 32-byte k'
        state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            *struct.unpack("<8I", key),
            counter & 0xFFFFFFFF,
            *struct.unpack("<3I", nonce)
        ]
        orig = list(state)

        def rotl32(v, c):
            return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

        def qround(a, b, c, d):
            state[a] = (state[a] + state[b]) & 0xFFFFFFFF
            state[d] = rotl32(state[d] ^ state[a], 16)
            state[c] = (state[c] + state[d]) & 0xFFFFFFFF
            state[b] = rotl32(state[b] ^ state[c], 12)
            state[a] = (state[a] + state[b]) & 0xFFFFFFFF
            state[d] = rotl32(state[d] ^ state[a], 8)
            state[c] = (state[c] + state[d]) & 0xFFFFFFFF
            state[b] = rotl32(state[b] ^ state[c], 7)

        for _ in range(10): # 20 rounds (10 column + 10 diagonal)
            qround(0, 4, 8, 12)
            qround(1, 5, 9, 13)
            qround(2, 6, 10, 14)
            qround(3, 7, 11, 15)
            qround(0, 5, 10, 15)
            qround(1, 6, 11, 12)
            qround(2, 7, 8, 13)
            qround(3, 4, 9, 14)

        out = bytearray(64)
        for i in range(16):
            summed = (state[i] + orig[i]) & 0xFFFFFFFF
            struct.pack_into("<I", out, i * 4, summed)
        return bytes(out)

# ---------------------------------------------------------------------------
# PE32+ and ELF64 Binary Parsers & Verifiers (F26, F31)
# ---------------------------------------------------------------------------
class BinaryInspection:
    @staticmethod
    def verify_pe32_plus(data: bytes) -> Dict[str, Any]:
        if len(data) < 512:
            raise ValueError("PE file too small")
        if data[:2] != b"MZ":
            raise ValueError("Missing MZ DOS signature")
        pe_offset = struct.unpack("<I", data[60:64])[0]
        if pe_offset + 24 > len(data):
            raise ValueError("Corrupt PE offset")
        if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            raise ValueError("Missing PE00 signature")
        machine, num_sections = struct.unpack("<HH", data[pe_offset+4:pe_offset+8])
        opt_hdr_size = struct.unpack("<H", data[pe_offset+20:pe_offset+22])
        opt_offset = pe_offset + 24
        opt_magic = struct.unpack("<H", data[opt_offset:opt_offset+2])[0]
        if opt_magic != 0x020B:
            raise ValueError(f"Not PE32+ (expected 0x020B, got 0x{opt_magic:04X})")
        entry_point = struct.unpack("<I", data[opt_offset+16:opt_offset+20])[0]
        subsystem = struct.unpack("<H", data[opt_offset+68:opt_offset+70])[0]
        return {
            "machine": machine,
            "num_sections": num_sections,
            "opt_magic": opt_magic,
            "entry_point": entry_point,
            "subsystem": subsystem
        }

    @staticmethod
    def verify_elf64(data: bytes) -> Dict[str, Any]:
        if len(data) < 64:
            raise ValueError("ELF file too small")
        if data[:4] != b"\x7fELF":
            raise ValueError("Missing ELF magic")
        ei_class = data[4]
        if ei_class != 2:
            raise ValueError("Not 64-bit ELF (EI_CLASS != 2)")
        e_type, e_machine, e_version = struct.unpack("<HHI", data[16:24])
        e_entry, e_phoff, e_shoff = struct.unpack("<QQQ", data[24:48])
        return {
            "class": "ELF64",
            "type": e_type,
            "machine": e_machine,
            "entry": e_entry,
            "phoff": e_phoff,
            "shoff": e_shoff
        }
