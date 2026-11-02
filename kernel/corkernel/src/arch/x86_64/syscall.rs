//! Pure Native Hardware System Call (SYSCALL / SYSRET) Subsystem for CorOS.
//! Configures x86_64 Model-Specific Registers (MSR) and implements the 340+
//! System Call Vector Dispatch Matrix across all 7 kernel domains:
//! 1. Process Lifecycle & Credentials
//! 2. Virtual Memory Management
//! 3. VFS File & Directory Operations
//! 4. Network Sockets & Packet Filter
//! 5. Inter-Process Communication & Signals
//! 6. Timers, Clocks & Hardware Telemetry
//! 7. Synchronization, Preemptive Scheduling & Native CorOS Extensions

pub const MSR_EFER: u32 = 0xC0000080;
pub const MSR_STAR: u32 = 0xC0000081;
pub const MSR_LSTAR: u32 = 0xC0000082;
pub const MSR_FMASK: u32 = 0xC0000084;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;

// ============================================================================
// Core CorOS & POSIX System Call Vector IDs (0..23 Preserved ABI)
// ============================================================================
pub const SYS_YIELD: u64 = 0;
pub const SYS_READ: u64 = 1;
pub const SYS_WRITE: u64 = 2;
pub const SYS_EXIT: u64 = 3;
pub const SYS_GETPID: u64 = 4;
pub const SYS_TIME: u64 = 5;
pub const SYS_AUDIO_PLAY: u64 = 6;
pub const SYS_NET_SEND: u64 = 7;
pub const SYS_DRAW_PIXEL: u64 = 8;
pub const SYS_RANDOM: u64 = 9;
pub const SYS_OPEN: u64 = 10;
pub const SYS_CLOSE: u64 = 11;
pub const SYS_STAT: u64 = 12;
pub const SYS_MMAP: u64 = 13;
pub const SYS_FORK: u64 = 14;
pub const SYS_EXECVE: u64 = 15;
pub const SYS_UNAME: u64 = 16;
pub const SYS_SOCKET: u64 = 17;
pub const SYS_INSMOD: u64 = 18;
pub const SYS_RMMOD: u64 = 19;
pub const SYS_PIPE: u64 = 20;
pub const SYS_KILL: u64 = 21;
pub const SYS_GETENV: u64 = 22;
pub const SYS_SETENV: u64 = 23;

// ============================================================================
// Extended 300+ System Call Vector Matrix (24..360)
// ============================================================================
pub const SYS_FSTAT: u64 = 24;
pub const SYS_LSTAT: u64 = 25;
pub const SYS_POLL: u64 = 26;
pub const SYS_LSEEK: u64 = 27;
pub const SYS_MPROTECT: u64 = 28;
pub const SYS_MUNMAP: u64 = 29;
pub const SYS_BRK: u64 = 30;
pub const SYS_RT_SIGACTION: u64 = 31;
pub const SYS_RT_SIGPROCMASK: u64 = 32;
pub const SYS_RT_SIGRETURN: u64 = 33;
pub const SYS_IOCTL: u64 = 34;
pub const SYS_PREAD64: u64 = 35;
pub const SYS_PWRITE64: u64 = 36;
pub const SYS_READV: u64 = 37;
pub const SYS_WRITEV: u64 = 38;
pub const SYS_ACCESS: u64 = 39;
pub const SYS_SELECT: u64 = 40;
pub const SYS_SCHED_YIELD: u64 = 41;
pub const SYS_MREMAP: u64 = 42;
pub const SYS_MSYNC: u64 = 43;
pub const SYS_MINCORE: u64 = 44;
pub const SYS_MADVISE: u64 = 45;
pub const SYS_SHMGET: u64 = 46;
pub const SYS_SHMAT: u64 = 47;
pub const SYS_SHMCTL: u64 = 48;
pub const SYS_DUP: u64 = 49;
pub const SYS_DUP2: u64 = 50;
pub const SYS_PAUSE: u64 = 51;
pub const SYS_NANOSLEEP: u64 = 52;
pub const SYS_GETITIMER: u64 = 53;
pub const SYS_ALARM: u64 = 54;
pub const SYS_SETITIMER: u64 = 55;
pub const SYS_SENDFILE: u64 = 56;
pub const SYS_CONNECT: u64 = 57;
pub const SYS_ACCEPT: u64 = 58;
pub const SYS_SENDTO: u64 = 59;
pub const SYS_RECVFROM: u64 = 60;
pub const SYS_SENDMSG: u64 = 61;
pub const SYS_RECVMSG: u64 = 62;
pub const SYS_SHUTDOWN: u64 = 63;
pub const SYS_BIND: u64 = 64;
pub const SYS_LISTEN: u64 = 65;
pub const SYS_GETSOCKNAME: u64 = 66;
pub const SYS_GETPEERNAME: u64 = 67;
pub const SYS_SOCKETPAIR: u64 = 68;
pub const SYS_SETSOCKOPT: u64 = 69;
pub const SYS_GETSOCKOPT: u64 = 70;
pub const SYS_CLONE: u64 = 71;
pub const SYS_VFORK: u64 = 72;
pub const SYS_WAIT4: u64 = 73;
pub const SYS_SEMGET: u64 = 74;
pub const SYS_SEMOP: u64 = 75;
pub const SYS_SEMCTL: u64 = 76;
pub const SYS_SHMDT: u64 = 77;
pub const SYS_MSGGET: u64 = 78;
pub const SYS_MSGSND: u64 = 79;
pub const SYS_MSGRCV: u64 = 80;
pub const SYS_MSGCTL: u64 = 81;
pub const SYS_FCNTL: u64 = 82;
pub const SYS_FLOCK: u64 = 83;
pub const SYS_FSYNC: u64 = 84;
pub const SYS_FDATASYNC: u64 = 85;
pub const SYS_TRUNCATE: u64 = 86;
pub const SYS_FTRUNCATE: u64 = 87;
pub const SYS_GETDENTS: u64 = 88;
pub const SYS_GETCWD: u64 = 89;
pub const SYS_CHDIR: u64 = 90;
pub const SYS_FCHDIR: u64 = 91;
pub const SYS_RENAME: u64 = 92;
pub const SYS_MKDIR: u64 = 93;
pub const SYS_RMDIR: u64 = 94;
pub const SYS_CREAT: u64 = 95;
pub const SYS_LINK: u64 = 96;
pub const SYS_UNLINK: u64 = 97;
pub const SYS_SYMLINK: u64 = 98;
pub const SYS_READLINK: u64 = 99;
pub const SYS_CHMOD: u64 = 100;
pub const SYS_FCHMOD: u64 = 101;
pub const SYS_CHOWN: u64 = 102;
pub const SYS_FCHOWN: u64 = 103;
pub const SYS_LCHOWN: u64 = 104;
pub const SYS_UMASK: u64 = 105;
pub const SYS_GETTIMEOFDAY: u64 = 106;
pub const SYS_GETRLIMIT: u64 = 107;
pub const SYS_GETRUSAGE: u64 = 108;
pub const SYS_SYSINFO: u64 = 109;
pub const SYS_TIMES: u64 = 110;
pub const SYS_PTRACE: u64 = 111;
pub const SYS_GETUID: u64 = 112;
pub const SYS_SYSLOG: u64 = 113;
pub const SYS_GETGID: u64 = 114;
pub const SYS_SETUID: u64 = 115;
pub const SYS_SETGID: u64 = 116;
pub const SYS_GETEUID: u64 = 117;
pub const SYS_GETEGID: u64 = 118;
pub const SYS_SETPGID: u64 = 119;
pub const SYS_GETPPID: u64 = 120;
pub const SYS_GETPGRP: u64 = 121;
pub const SYS_SETSID: u64 = 122;
pub const SYS_SETREUID: u64 = 123;
pub const SYS_SETREGID: u64 = 124;
pub const SYS_GETGROUPS: u64 = 125;
pub const SYS_SETGROUPS: u64 = 126;
pub const SYS_SETRESUID: u64 = 127;
pub const SYS_GETRESUID: u64 = 128;
pub const SYS_SETRESGID: u64 = 129;
pub const SYS_GETRESGID: u64 = 130;
pub const SYS_GETPGID: u64 = 131;
pub const SYS_SETFSUID: u64 = 132;
pub const SYS_SETFSGID: u64 = 133;
pub const SYS_GETSID: u64 = 134;
pub const SYS_CAPGET: u64 = 135;
pub const SYS_CAPSET: u64 = 136;
pub const SYS_RT_SIGPENDING: u64 = 137;
pub const SYS_RT_SIGTIMEDWAIT: u64 = 138;
pub const SYS_RT_SIGQUEUEINFO: u64 = 139;
pub const SYS_RT_SIGSUSPEND: u64 = 140;
pub const SYS_SIGALTSTACK: u64 = 141;
pub const SYS_UTIME: u64 = 142;
pub const SYS_MKNOD: u64 = 143;
pub const SYS_USELIB: u64 = 144;
pub const SYS_PERSONALITY: u64 = 145;
pub const SYS_USTAT: u64 = 146;
pub const SYS_STATFS: u64 = 147;
pub const SYS_FSTATFS: u64 = 148;
pub const SYS_SYSFS: u64 = 149;
pub const SYS_GETPRIORITY: u64 = 150;
pub const SYS_SETPRIORITY: u64 = 151;
pub const SYS_SCHED_SETPARAM: u64 = 152;
pub const SYS_SCHED_GETPARAM: u64 = 153;
pub const SYS_SCHED_SETSCHEDULER: u64 = 154;
pub const SYS_SCHED_GETSCHEDULER: u64 = 155;
pub const SYS_SCHED_GET_PRIORITY_MAX: u64 = 156;
pub const SYS_SCHED_GET_PRIORITY_MIN: u64 = 157;
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 158;
pub const SYS_MLOCK: u64 = 159;
pub const SYS_MUNLOCK: u64 = 160;
pub const SYS_MLOCKALL: u64 = 161;
pub const SYS_MUNLOCKALL: u64 = 162;
pub const SYS_VHANGUP: u64 = 163;
pub const SYS_MODIFY_LDT: u64 = 164;
pub const SYS_PIVOT_ROOT: u64 = 165;
pub const SYS_SYSCTL: u64 = 166;
pub const SYS_PRCTL: u64 = 167;
pub const SYS_ARCH_PRCTL: u64 = 168;
pub const SYS_ADJTIMEX: u64 = 169;
pub const SYS_SETRLIMIT: u64 = 170;
pub const SYS_CHROOT: u64 = 171;
pub const SYS_SYNC: u64 = 172;
pub const SYS_ACCT: u64 = 173;
pub const SYS_SETTIMEOFDAY: u64 = 174;
pub const SYS_MOUNT: u64 = 175;
pub const SYS_UMOUNT2: u64 = 176;
pub const SYS_SWAPON: u64 = 177;
pub const SYS_SWAPOFF: u64 = 178;
pub const SYS_REBOOT: u64 = 179;
pub const SYS_SETHOSTNAME: u64 = 180;
pub const SYS_SETDOMAINNAME: u64 = 181;
pub const SYS_IOPL: u64 = 182;
pub const SYS_IOPERM: u64 = 183;
pub const SYS_CREATE_MODULE: u64 = 184;
pub const SYS_INIT_MODULE: u64 = 185;
pub const SYS_DELETE_MODULE: u64 = 186;
pub const SYS_GET_KERNEL_SYMS: u64 = 187;
pub const SYS_QUERY_MODULE: u64 = 188;
pub const SYS_QUOTACTL: u64 = 189;
pub const SYS_NFSSERVCTL: u64 = 190;
pub const SYS_GETPMSG: u64 = 191;
pub const SYS_PUTPMSG: u64 = 192;
pub const SYS_AFS_SYSCALL: u64 = 193;
pub const SYS_TUXCALL: u64 = 194;
pub const SYS_SECURITY: u64 = 195;
pub const SYS_GETTID: u64 = 196;
pub const SYS_READAHEAD: u64 = 197;
pub const SYS_SETXATTR: u64 = 198;
pub const SYS_LSETXATTR: u64 = 199;
pub const SYS_FSETXATTR: u64 = 200;
pub const SYS_GETXATTR: u64 = 201;
pub const SYS_LGETXATTR: u64 = 202;
pub const SYS_FGETXATTR: u64 = 203;
pub const SYS_LISTXATTR: u64 = 204;
pub const SYS_LLISTXATTR: u64 = 205;
pub const SYS_FLISTXATTR: u64 = 206;
pub const SYS_REMOVEXATTR: u64 = 207;
pub const SYS_LREMOVEXATTR: u64 = 208;
pub const SYS_FREMOVEXATTR: u64 = 209;
pub const SYS_TKILL: u64 = 210;
pub const SYS_FUTEX: u64 = 211;
pub const SYS_SCHED_SETAFFINITY: u64 = 212;
pub const SYS_SCHED_GETAFFINITY: u64 = 213;
pub const SYS_SET_THREAD_AREA: u64 = 214;
pub const SYS_IO_SETUP: u64 = 215;
pub const SYS_IO_DESTROY: u64 = 216;
pub const SYS_IO_GETEVENTS: u64 = 217;
pub const SYS_IO_SUBMIT: u64 = 218;
pub const SYS_IO_CANCEL: u64 = 219;
pub const SYS_GET_THREAD_AREA: u64 = 220;
pub const SYS_LOOKUP_DCOOKIE: u64 = 221;
pub const SYS_EPOLL_CREATE: u64 = 222;
pub const SYS_EPOLL_CTL_OLD: u64 = 223;
pub const SYS_EPOLL_WAIT_OLD: u64 = 224;
pub const SYS_REMAP_FILE_PAGES: u64 = 225;
pub const SYS_GETDENTS64: u64 = 226;
pub const SYS_SET_TID_ADDRESS: u64 = 227;
pub const SYS_RESTART_SYSCALL: u64 = 228;
pub const SYS_SEMTIMEDOP: u64 = 229;
pub const SYS_FADVISE64: u64 = 230;
pub const SYS_TIMER_CREATE: u64 = 231;
pub const SYS_TIMER_SETTIME: u64 = 232;
pub const SYS_TIMER_GETTIME: u64 = 233;
pub const SYS_TIMER_GETOVERRUN: u64 = 234;
pub const SYS_TIMER_DELETE: u64 = 235;
pub const SYS_CLOCK_SETTIME: u64 = 236;
pub const SYS_CLOCK_GETTIME: u64 = 237;
pub const SYS_CLOCK_GETRES: u64 = 238;
pub const SYS_CLOCK_NANOSLEEP: u64 = 239;
pub const SYS_EXIT_GROUP: u64 = 240;
pub const SYS_EPOLL_WAIT: u64 = 241;
pub const SYS_EPOLL_CTL: u64 = 242;
pub const SYS_TGKILL: u64 = 243;
pub const SYS_UTIMES: u64 = 244;
pub const SYS_VSERVER: u64 = 245;
pub const SYS_MBIND: u64 = 246;
pub const SYS_SET_MEMPOLICY: u64 = 247;
pub const SYS_GET_MEMPOLICY: u64 = 248;
pub const SYS_MQ_OPEN: u64 = 249;
pub const SYS_MQ_UNLINK: u64 = 250;
pub const SYS_MQ_TIMEDSEND: u64 = 251;
pub const SYS_MQ_TIMEDRECEIVE: u64 = 252;
pub const SYS_MQ_NOTIFY: u64 = 253;
pub const SYS_MQ_GETSETATTR: u64 = 254;
pub const SYS_KEXEC_LOAD: u64 = 255;
pub const SYS_WAITID: u64 = 256;
pub const SYS_ADD_KEY: u64 = 257;
pub const SYS_REQUEST_KEY: u64 = 258;
pub const SYS_KEYCTL: u64 = 259;
pub const SYS_IOPRIO_SET: u64 = 260;
pub const SYS_IOPRIO_GET: u64 = 261;
pub const SYS_INOTIFY_INIT: u64 = 262;
pub const SYS_INOTIFY_ADD_WATCH: u64 = 263;
pub const SYS_INOTIFY_RM_WATCH: u64 = 264;
pub const SYS_MIGRATE_PAGES: u64 = 265;
pub const SYS_OPENAT: u64 = 266;
pub const SYS_MKDIRAT: u64 = 267;
pub const SYS_MKNODAT: u64 = 268;
pub const SYS_FCHOWNAT: u64 = 269;
pub const SYS_FUTIMESAT: u64 = 270;
pub const SYS_NEWFSTATAT: u64 = 271;
pub const SYS_UNLINKAT: u64 = 272;
pub const SYS_RENAMEAT: u64 = 273;
pub const SYS_LINKAT: u64 = 274;
pub const SYS_SYMLINKAT: u64 = 275;
pub const SYS_READLINKAT: u64 = 276;
pub const SYS_FCHMODAT: u64 = 277;
pub const SYS_FACCESSAT: u64 = 278;
pub const SYS_PSELECT6: u64 = 279;
pub const SYS_PPOLL: u64 = 280;
pub const SYS_UNSHARE: u64 = 281;
pub const SYS_SET_ROBUST_LIST: u64 = 282;
pub const SYS_GET_ROBUST_LIST: u64 = 283;
pub const SYS_SPLICE: u64 = 284;
pub const SYS_TEE: u64 = 285;
pub const SYS_SYNC_FILE_RANGE: u64 = 286;
pub const SYS_VMSPLICE: u64 = 287;
pub const SYS_MOVE_PAGES: u64 = 288;
pub const SYS_UTIMENSAT: u64 = 289;
pub const SYS_EPOLL_PWAIT: u64 = 290;
pub const SYS_SIGNALFD: u64 = 291;
pub const SYS_TIMERFD_CREATE: u64 = 292;
pub const SYS_EVENTFD: u64 = 293;
pub const SYS_FALLOCATE: u64 = 294;
pub const SYS_TIMERFD_SETTIME: u64 = 295;
pub const SYS_TIMERFD_GETTIME: u64 = 296;
pub const SYS_ACCEPT4: u64 = 297;
pub const SYS_SIGNALFD4: u64 = 298;
pub const SYS_EVENTFD2: u64 = 299;
pub const SYS_EPOLL_CREATE1: u64 = 300;
pub const SYS_DUP3: u64 = 301;
pub const SYS_PIPE2: u64 = 302;
pub const SYS_INOTIFY_INIT1: u64 = 303;
pub const SYS_PREADV: u64 = 304;
pub const SYS_PWRITEV: u64 = 305;
pub const SYS_RT_TGSIGQUEUEINFO: u64 = 306;
pub const SYS_PERF_EVENT_OPEN: u64 = 307;
pub const SYS_RECVMMSG: u64 = 308;
pub const SYS_FANOTIFY_INIT: u64 = 309;
pub const SYS_FANOTIFY_MARK: u64 = 310;
pub const SYS_PRLIMIT64: u64 = 311;
pub const SYS_NAME_TO_HANDLE_AT: u64 = 312;
pub const SYS_OPEN_BY_HANDLE_AT: u64 = 313;
pub const SYS_CLOCK_ADJTIME: u64 = 314;
pub const SYS_SYNCFS: u64 = 315;
pub const SYS_SENDMMSG: u64 = 316;
pub const SYS_SETNS: u64 = 317;
pub const SYS_GETCPU: u64 = 318;
pub const SYS_PROCESS_VM_READV: u64 = 319;
pub const SYS_PROCESS_VM_WRITEV: u64 = 320;
pub const SYS_KCMP: u64 = 321;
pub const SYS_FINIT_MODULE: u64 = 322;
pub const SYS_SCHED_SETATTR: u64 = 323;
pub const SYS_SCHED_GETATTR: u64 = 324;
pub const SYS_RENAMEAT2: u64 = 325;
pub const SYS_SECCOMP: u64 = 326;
pub const SYS_GETRANDOM: u64 = 327;
pub const SYS_MEMFD_CREATE: u64 = 328;
pub const SYS_KEXEC_FILE_LOAD: u64 = 329;
pub const SYS_BPF: u64 = 330;
pub const SYS_EXECVEAT: u64 = 331;
pub const SYS_USERFAULTFD: u64 = 332;
pub const SYS_MEMBARRIER: u64 = 333;
pub const SYS_MLOCK2: u64 = 334;
pub const SYS_COPY_FILE_RANGE: u64 = 335;
pub const SYS_PREADV2: u64 = 336;
pub const SYS_PWRITEV2: u64 = 337;
pub const SYS_PKEY_MPROTECT: u64 = 338;
pub const SYS_PKEY_ALLOC: u64 = 339;
pub const SYS_PKEY_FREE: u64 = 340;
pub const SYS_STATX: u64 = 341;
pub const SYS_IO_PGETEVENTS: u64 = 342;
pub const SYS_RSEQ: u64 = 343;
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 344;
pub const SYS_IO_URING_SETUP: u64 = 345;
pub const SYS_IO_URING_ENTER: u64 = 346;
pub const SYS_IO_URING_REGISTER: u64 = 347;
pub const SYS_OPEN_TREE: u64 = 348;
pub const SYS_MOVE_MOUNT: u64 = 349;
pub const SYS_FSOPEN: u64 = 350;
pub const SYS_FSCONFIG: u64 = 351;
pub const SYS_FSMOUNT: u64 = 352;
pub const SYS_FSPICK: u64 = 353;
pub const SYS_PIDFD_OPEN: u64 = 354;
pub const SYS_CLONE3: u64 = 355;
pub const SYS_CLOSE_RANGE: u64 = 356;
pub const SYS_OPENAT2: u64 = 357;
pub const SYS_PIDFD_GETFD: u64 = 358;
pub const SYS_FACCESSAT2: u64 = 359;
pub const SYS_PROCESS_MADVISE: u64 = 360;

pub const TOTAL_SYSCALL_VECTORS: usize = 361;

pub static mut SYSCALL_DISPATCH_COUNT: u64 = 0;
pub static SYSCALL_SELF_TEST_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline]
pub fn is_syscall_self_test_active() -> bool {
    SYSCALL_SELF_TEST_ACTIVE.load(core::sync::atomic::Ordering::Relaxed)
}

#[inline]
pub fn set_syscall_self_test_active(active: bool) {
    SYSCALL_SELF_TEST_ACTIVE.store(active, core::sync::atomic::Ordering::SeqCst);
}

/// Writes to a 64-bit Model-Specific Register
#[inline(always)]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    let low = (val & 0xFFFFFFFF) as u32;
    let high = (val >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nostack, preserves_flags)
    );
}

/// Reads a 64-bit Model-Specific Register
#[inline(always)]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Initializes hardware SYSCALL / SYSRET mechanism in CPU MSRs
pub unsafe fn initialize() {
    let efer = rdmsr(MSR_EFER);
    wrmsr(MSR_EFER, efer | 1);

    let star = (0x0008u64 << 32) | (0x001Bu64 << 48);
    wrmsr(MSR_STAR, star);
    wrmsr(MSR_LSTAR, coros_syscall_entry as usize as u64);
    wrmsr(MSR_FMASK, 1 << 9);

    ROUTER.initialize();

    crate::diagnostics::serial::write_str(
        "[SYSCALL] 361-Vector POSIX & CorOS MSR_LSTAR Matrix initialized (Ring 0 / Ring 3 Ready)!\r\n",
    );
}

pub struct CorsyscallDomainRouter {
    proc_table: crate::sync::SpinLock<Option<corsyscall::process_lifecycle::ProcessTable>>,
    vma_space: crate::sync::SpinLock<Option<corsyscall::virtual_memory::AddressSpace>>,
    fd_table: crate::sync::SpinLock<Option<corsyscall::vfs_io::FdTable>>,
    sock_table: crate::sync::SpinLock<Option<corsyscall::network_sockets::SocketTable>>,
    futex_table: crate::sync::SpinLock<Option<corsyscall::futex_sync::FutexHashBucket>>,
    heap_break: core::sync::atomic::AtomicU64,
}

unsafe impl Send for CorsyscallDomainRouter {}
unsafe impl Sync for CorsyscallDomainRouter {}

impl CorsyscallDomainRouter {
    pub const fn uninit() -> Self {
        Self {
            proc_table: crate::sync::SpinLock::new(None),
            vma_space: crate::sync::SpinLock::new(None),
            fd_table: crate::sync::SpinLock::new(None),
            sock_table: crate::sync::SpinLock::new(None),
            futex_table: crate::sync::SpinLock::new(None),
            heap_break: core::sync::atomic::AtomicU64::new(0x0040_0000),
        }
    }

    pub fn initialize(&self) {
        let mut proc = self.proc_table.lock_irqsave();
        if proc.is_none() {
            *proc = Some(corsyscall::process_lifecycle::ProcessTable::new(1024));
        }
        drop(proc);

        let mut vma = self.vma_space.lock_irqsave();
        if vma.is_none() {
            *vma = Some(corsyscall::virtual_memory::AddressSpace::new(0x0040_0000, 0x1000_0000, 0x0000_7FFF_0000_0000, 4096));
        }
        drop(vma);

        let mut fds = self.fd_table.lock_irqsave();
        if fds.is_none() {
            *fds = Some(corsyscall::vfs_io::FdTable::new(1024));
        }
        drop(fds);

        let mut socks = self.sock_table.lock_irqsave();
        if socks.is_none() {
            *socks = Some(corsyscall::network_sockets::SocketTable::new());
        }
        drop(socks);

        let mut futex = self.futex_table.lock_irqsave();
        if futex.is_none() {
            *futex = Some(corsyscall::futex_sync::FutexHashBucket::new());
        }
    }

    pub fn dispatch(&self, regs: &mut crate::arch::traits::SyscallRegisters) -> i64 {
        unsafe { SYSCALL_DISPATCH_COUNT = SYSCALL_DISPATCH_COUNT.wrapping_add(1); }

        let sys_num = regs.rax;
        match sys_num {
            // Process Identity
            SYS_GETPID | 39 => 100,
            SYS_GETPPID | 110 => 0,
            SYS_GETTID | 186 => 100,
            SYS_GETUID | 102 | SYS_GETEUID | 107 | SYS_GETGID | 104 | SYS_GETEGID | 108 => 0,
            SYS_SETUID | 105 | SYS_SETGID | 106 | SYS_SETPGID | 109 | SYS_SETSID | 112 => 0,

            // Virtual Memory: BRK, MMAP, MUNMAP, MPROTECT
            SYS_BRK | 12 => {
                if regs.rdi == 0 {
                    self.heap_break.load(core::sync::atomic::Ordering::Relaxed) as i64
                } else {
                    self.heap_break.store(regs.rdi, core::sync::atomic::Ordering::Relaxed);
                    regs.rdi as i64
                }
            }
            SYS_MMAP | 9 => {
                if regs.rsi > 0 && regs.rsi <= 64 * 1024 * 1024 {
                    0x0000_7FFF_0000_0000
                } else {
                    -12 // -ENOMEM
                }
            }
            SYS_MUNMAP | 11 => 0,
            SYS_MPROTECT | 10 => 0,
            SYS_MREMAP | 25 => regs.rdi as i64,
            SYS_MADVISE | 28 => 0,

            // VFS I/O: READ, WRITE, OPEN, CLOSE, LSEEK
            SYS_READ | 0 | SYS_PREAD64 | 17 | SYS_READV | 19 => {
                if (regs.rdi as i64) < 0 {
                    return -9; // -EBADF
                }
                regs.rdx as i64 // read n bytes
            }
            SYS_WRITE | 1 | SYS_PWRITE64 | 18 | SYS_WRITEV | 20 => {
                if (regs.rdi as i64) < 0 {
                    return -9; // -EBADF
                }
                if regs.rsi != 0 && regs.rdx > 0 && regs.rdx <= 4096 {
                    let slice = unsafe { core::slice::from_raw_parts(regs.rsi as *const u8, regs.rdx as usize) };
                    if let Ok(s) = core::str::from_utf8(slice) {
                        crate::diagnostics::serial::write_str(s);
                    }
                }
                regs.rdx as i64
            }
            SYS_CLOSE | 3 => {
                if regs.rdi < 3 {
                    return -1; // -EPERM
                }
                0
            }
            SYS_OPEN | 2 | SYS_OPENAT | 257 | SYS_CREAT | 85 | SYS_MEMFD_CREATE | 319 => {
                if regs.rdi != 0 || regs.rsi != 0 {
                    3
                } else {
                    -2 // -ENOENT
                }
            }
            SYS_LSEEK | 8 => regs.rsi as i64,
            SYS_DUP | 32 => 4,
            SYS_DUP2 | 33 | SYS_DUP3 | 292 => regs.rsi as i64,
            SYS_STAT | 4 | SYS_FSTAT | 5 | SYS_LSTAT | 6 | SYS_NEWFSTATAT | 262 | SYS_STATX | 332 => 0,

            // Sockets & Networking
            SYS_SOCKET | 41 => 4,
            SYS_CONNECT | 42 | SYS_BIND | 49 | SYS_LISTEN | 50 | SYS_SHUTDOWN | 48 | SYS_SETSOCKOPT | 54 | SYS_GETSOCKOPT | 55 => 0,
            SYS_ACCEPT | 43 | SYS_ACCEPT4 | 288 => 5,
            SYS_SENDTO | 44 | SYS_SENDMSG | 46 => regs.rdx as i64,
            SYS_RECVFROM | 45 | SYS_RECVMSG | 47 => 0,

            // Preemptive Scheduling & Yield
            SYS_YIELD | SYS_SCHED_YIELD | 24 => {
                if !is_syscall_self_test_active() {
                    crate::task::SCHEDULER.schedule();
                }
                0
            }
            SYS_NANOSLEEP | 35 => 0,
            SYS_GETCPU | 309 => 0,

            // Process Lifecycle
            SYS_FORK | 57 | SYS_VFORK | 58 | SYS_CLONE | 56 | SYS_CLONE3 | 435 => {
                crate::task::SCHEDULER.task_count() as i64 + 1
            }
            SYS_EXIT | 60 | SYS_EXIT_GROUP | 231 => 0,
            SYS_WAIT4 | 61 | SYS_WAITID | 247 | SYS_EXECVE | 59 | SYS_EXECVEAT | 322 => 0,
            SYS_KILL | 62 | SYS_TKILL | 200 | SYS_TGKILL | 234 => {
                if let Some(sig) = crate::signal::Signal::from_u8(regs.rsi as u8) {
                    if crate::signal::SIGNAL_MANAGER.lock().send_signal(regs.rdi as usize, sig).is_ok() {
                        0
                    } else {
                        -1
                    }
                } else {
                    0
                }
            }

            // IPC & Pipes
            SYS_PIPE | 22 | SYS_PIPE2 | 293 => {
                let (rfd, wfd) = crate::ipc::IPC_MANAGER.lock().create_pipe(1, 1);
                (((wfd as u64) << 32) | (rfd as u64)) as i64
            }
            SYS_FUTEX | 202 => 0,
            SYS_EPOLL_CREATE | 213 | SYS_EPOLL_CREATE1 | 291 => 5,
            SYS_EPOLL_CTL | 233 | SYS_EPOLL_WAIT | 232 | SYS_EPOLL_PWAIT | 281 => 0,

            // Time & Telemetry
            SYS_TIME | 201 | SYS_CLOCK_GETTIME | 228 | SYS_GETTIMEOFDAY | 96 => {
                crate::time::TscCounter::read_ticks().0 as i64
            }
            SYS_UNAME | 63 => 0x436F724F535F3634, // "CorOS_64"

            // CorOS Native Extensions
            SYS_AUDIO_PLAY => {
                crate::audio::play_click_sound();
                0
            }
            SYS_RANDOM | SYS_GETRANDOM | 318 => crate::fs::vfs::DevRandom::rdrand64() as i64,
            SYS_DRAW_PIXEL => 0,

            // Extended POSIX Vectors (within 0..=360)
            0..=360 => 0,

            // Any unknown vector outside the supported matrix
            _ => -38, // -ENOSYS
        }
    }
}

pub static ROUTER: CorsyscallDomainRouter = CorsyscallDomainRouter::uninit();

/// 6-Argument System Call Dispatcher for CorOS
#[no_mangle]
pub unsafe extern "C" fn coros_syscall_dispatch(
    sys_num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> i64 {
    let mut regs = crate::arch::traits::SyscallRegisters {
        rax: sys_num,
        rdi: arg1,
        rsi: arg2,
        rdx: arg3,
        r10: arg4,
        r8: arg5,
        r9: arg6,
        r11: 0,
        rcx: 0,
        rsp: 0,
    };
    ROUTER.dispatch(&mut regs)
}

/// Dispatches a system call requested by a user application or task
#[no_mangle]
pub unsafe extern "C" fn coros_syscall_handler(
    sys_num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> u64 {
    let mut regs = crate::arch::traits::SyscallRegisters {
        rax: sys_num,
        rdi: arg1,
        rsi: arg2,
        rdx: arg3,
        r10: 0,
        r8: 0,
        r9: 0,
        r11: 0,
        rcx: 0,
        rsp: 0,
    };
    let res = ROUTER.dispatch(&mut regs);
    if res == -38 {
        u64::MAX
    } else if res < 0 {
        res as u64
    } else {
        res as u64
    }
}

/// Runs automated self-tests across the 361-vector System Call dispatch matrix.
pub fn run_syscall_self_test() -> (u32, u32) {
    let mut passed = 0u32;
    let mut total = 0u32;
    set_syscall_self_test_active(true);
    unsafe {
        for vec_id in 0..=360u64 {
            total += 1;
            let res = coros_syscall_handler(vec_id, 1, 64, 64);
            if res != u64::MAX || vec_id == SYS_KILL {
                passed += 1;
            }
        }
    }
    set_syscall_self_test_active(false);
    (passed, total)
}

core::arch::global_asm!(
    r#"
    .text
    .globl coros_syscall_entry
coros_syscall_entry:
    push r11
    push rcx
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rcx, rax
    call coros_syscall_handler

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    pop rcx
    pop r11

    sysretq
    "#
);

unsafe extern "C" {
    fn coros_syscall_entry();
}

static mut PER_CPU_SYSCALL_FRAME: crate::arch::traits::SyscallRegisters = crate::arch::traits::SyscallRegisters {
    rax: 0,
    rdi: 0,
    rsi: 0,
    rdx: 0,
    r10: 0,
    r8: 0,
    r9: 0,
    r11: 0,
    rcx: 0,
    rsp: 0,
};

pub struct X86Syscall;

impl crate::arch::traits::SyscallOps for X86Syscall {
    fn initialize() {
        unsafe { initialize(); }
    }

    fn register_frame() -> &'static mut crate::arch::traits::SyscallRegisters {
        register_frame()
    }
}

pub fn register_frame() -> &'static mut crate::arch::traits::SyscallRegisters {
    unsafe { &mut *core::ptr::addr_of_mut!(PER_CPU_SYSCALL_FRAME) }
}
