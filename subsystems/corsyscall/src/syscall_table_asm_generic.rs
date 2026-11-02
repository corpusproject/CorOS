//! Generic Linux (asm-generic/unistd.h) System Call Vector Table & Frame Abstraction.
//!
//! Provides the standard RISC-V 64-bit and ARM64 Linux system call ABI vectors
//! based on the unified asm-generic unistd.h standard, along with cross-architecture
//! mapping functions to translate between x86_64 and asm-generic system call numbers.

use super::syscall_table_x86 as x86;

// ============================================================================
// Linux asm-generic/unistd.h System Call Vectors (used by AArch64 & RISC-V)
// ============================================================================
pub const SYS_IO_SETUP: u64                = 0;
pub const SYS_IO_DESTROY: u64              = 1;
pub const SYS_IO_SUBMIT: u64               = 2;
pub const SYS_IO_CANCEL: u64               = 3;
pub const SYS_IO_GETEVENTS: u64            = 4;
pub const SYS_SETXATTR: u64                = 5;
pub const SYS_LSETXATTR: u64               = 6;
pub const SYS_FSETXATTR: u64               = 7;
pub const SYS_GETXATTR: u64                = 8;
pub const SYS_LGETXATTR: u64               = 9;
pub const SYS_FGETXATTR: u64               = 10;
pub const SYS_LISTXATTR: u64               = 11;
pub const SYS_LLISTXATTR: u64              = 12;
pub const SYS_FLISTXATTR: u64              = 13;
pub const SYS_REMOVEXATTR: u64             = 14;
pub const SYS_LREMOVEXATTR: u64            = 15;
pub const SYS_FREMOVEXATTR: u64            = 16;
pub const SYS_GETCWD: u64                  = 17;
pub const SYS_LOOKUP_DCOOKIE: u64          = 18;
pub const SYS_EVENTFD2: u64                = 19;
pub const SYS_EPOLL_CREATE1: u64           = 20;
pub const SYS_EPOLL_CTL: u64               = 21;
pub const SYS_EPOLL_PWAIT: u64             = 22;
pub const SYS_DUP: u64                     = 23;
pub const SYS_DUP3: u64                    = 24;
pub const SYS_FCNTL: u64                   = 25;
pub const SYS_INOTIFY_INIT1: u64           = 26;
pub const SYS_INOTIFY_ADD_WATCH: u64       = 27;
pub const SYS_INOTIFY_RM_WATCH: u64        = 28;
pub const SYS_IOCTL: u64                   = 29;
pub const SYS_IOPRIO_SET: u64              = 30;
pub const SYS_IOPRIO_GET: u64              = 31;
pub const SYS_FLOCK: u64                   = 32;
pub const SYS_MKNODAT: u64                 = 33;
pub const SYS_MKDIRAT: u64                 = 34;
pub const SYS_UNLINKAT: u64                = 35;
pub const SYS_SYMLINKAT: u64               = 36;
pub const SYS_LINKAT: u64                  = 37;
pub const SYS_RENAMEAT: u64                = 38;
pub const SYS_UMOUNT2: u64                 = 39;
pub const SYS_MOUNT: u64                   = 40;
pub const SYS_PIVOT_ROOT: u64              = 41;
pub const SYS_NFSSERVCTL: u64              = 42;
pub const SYS_STATFS: u64                  = 43;
pub const SYS_FSTATFS: u64                 = 44;
pub const SYS_TRUNCATE: u64                = 45;
pub const SYS_FTRUNCATE: u64               = 46;
pub const SYS_FALLOCATE: u64               = 47;
pub const SYS_FACCESSAT: u64               = 48;
pub const SYS_CHDIR: u64                   = 49;
pub const SYS_FCHDIR: u64                  = 50;
pub const SYS_CHROOT: u64                  = 51;
pub const SYS_FCHMOD: u64                  = 52;
pub const SYS_FCHMODAT: u64                = 53;
pub const SYS_FCHOWNAT: u64                = 54;
pub const SYS_FCHOWN: u64                  = 55;
pub const SYS_OPENAT: u64                  = 56;
pub const SYS_CLOSE: u64                   = 57;
pub const SYS_VHANGUP: u64                 = 58;
pub const SYS_PIPE2: u64                   = 59;
pub const SYS_QUOTACTL: u64                = 60;
pub const SYS_GETDENTS64: u64              = 61;
pub const SYS_LSEEK: u64                   = 62;
pub const SYS_READ: u64                    = 63;
pub const SYS_WRITE: u64                   = 64;
pub const SYS_READV: u64                   = 65;
pub const SYS_WRITEV: u64                  = 66;
pub const SYS_PREAD64: u64                 = 67;
pub const SYS_PWRITE64: u64                = 68;
pub const SYS_PREADV: u64                  = 69;
pub const SYS_PWRITEV: u64                 = 70;
pub const SYS_SENDFILE: u64                = 71;
pub const SYS_PSELECT6: u64                = 72;
pub const SYS_PPOLL: u64                   = 73;
pub const SYS_SIGNALFD4: u64               = 74;
pub const SYS_VMSPLICE: u64                = 75;
pub const SYS_SPLICE: u64                  = 76;
pub const SYS_TEE: u64                     = 77;
pub const SYS_READLINKAT: u64              = 78;
pub const SYS_NEWFSTATAT: u64              = 79;
pub const SYS_FSTAT: u64                   = 80;
pub const SYS_SYNC: u64                    = 81;
pub const SYS_FSYNC: u64                   = 82;
pub const SYS_FDATASYNC: u64               = 83;
pub const SYS_SYNC_FILE_RANGE: u64         = 84;
pub const SYS_TIMERFD_CREATE: u64          = 85;
pub const SYS_TIMERFD_SETTIME: u64         = 86;
pub const SYS_TIMERFD_GETTIME: u64         = 87;
pub const SYS_UTIMENSAT: u64               = 88;
pub const SYS_ACCT: u64                    = 89;
pub const SYS_CAPGET: u64                  = 90;
pub const SYS_CAPSET: u64                  = 91;
pub const SYS_PERSONALITY: u64             = 92;
pub const SYS_EXIT: u64                    = 93;
pub const SYS_EXIT_GROUP: u64              = 94;
pub const SYS_WAITID: u64                  = 95;
pub const SYS_SET_TID_ADDRESS: u64         = 96;
pub const SYS_UNSHARE: u64                 = 97;
pub const SYS_FUTEX: u64                   = 98;
pub const SYS_SET_ROBUST_LIST: u64         = 99;
pub const SYS_GET_ROBUST_LIST: u64         = 100;
pub const SYS_NANOSLEEP: u64               = 101;
pub const SYS_GETITIMER: u64               = 102;
pub const SYS_SETITIMER: u64               = 103;
pub const SYS_KEXEC_LOAD: u64              = 104;
pub const SYS_INIT_MODULE: u64             = 105;
pub const SYS_DELETE_MODULE: u64           = 106;
pub const SYS_TIMER_CREATE: u64            = 107;
pub const SYS_TIMER_GETTIME: u64           = 108;
pub const SYS_TIMER_GETOVERRUN: u64        = 109;
pub const SYS_TIMER_SETTIME: u64           = 110;
pub const SYS_TIMER_DELETE: u64            = 111;
pub const SYS_CLOCK_SETTIME: u64           = 112;
pub const SYS_CLOCK_GETTIME: u64           = 113;
pub const SYS_CLOCK_GETRES: u64            = 114;
pub const SYS_CLOCK_NANOSLEEP: u64         = 115;
pub const SYS_SYSLOG: u64                  = 116;
pub const SYS_PTRACE: u64                  = 117;
pub const SYS_SCHED_SETPARAM: u64          = 118;
pub const SYS_SCHED_SETSCHEDULER: u64      = 119;
pub const SYS_SCHED_GETSCHEDULER: u64      = 120;
pub const SYS_SCHED_GETPARAM: u64          = 121;
pub const SYS_SCHED_SETAFFINITY: u64       = 122;
pub const SYS_SCHED_GETAFFINITY: u64       = 123;
pub const SYS_SCHED_YIELD: u64             = 124;
pub const SYS_SCHED_GET_PRIORITY_MAX: u64  = 125;
pub const SYS_SCHED_GET_PRIORITY_MIN: u64  = 126;
pub const SYS_SCHED_RR_GET_INTERVAL: u64   = 127;
pub const SYS_RESTART_SYSCALL: u64         = 128;
pub const SYS_KILL: u64                    = 129;
pub const SYS_TKILL: u64                   = 130;
pub const SYS_TGKILL: u64                  = 131;
pub const SYS_SIGALTSTACK: u64             = 132;
pub const SYS_RT_SIGSUSPEND: u64           = 133;
pub const SYS_RT_SIGACTION: u64            = 134;
pub const SYS_RT_SIGPROCMASK: u64          = 135;
pub const SYS_RT_SIGPENDING: u64           = 136;
pub const SYS_RT_SIGTIMEDWAIT: u64         = 137;
pub const SYS_RT_SIGQUEUEINFO: u64         = 138;
pub const SYS_RT_SIGRETURN: u64            = 139;
pub const SYS_SETPRIORITY: u64             = 140;
pub const SYS_GETPRIORITY: u64             = 141;
pub const SYS_REBOOT: u64                  = 142;
pub const SYS_SETREGID: u64                = 143;
pub const SYS_SETGID: u64                  = 144;
pub const SYS_SETREUID: u64                = 145;
pub const SYS_SETUID: u64                  = 146;
pub const SYS_SETRESUID: u64               = 147;
pub const SYS_GETRESUID: u64               = 148;
pub const SYS_SETRESGID: u64               = 149;
pub const SYS_GETRESGID: u64               = 150;
pub const SYS_SETFSUID: u64                = 151;
pub const SYS_SETFSGID: u64                = 152;
pub const SYS_TIMES: u64                   = 153;
pub const SYS_SETPGID: u64                 = 154;
pub const SYS_GETPGID: u64                 = 155;
pub const SYS_GETSID: u64                  = 156;
pub const SYS_SETSID: u64                  = 157;
pub const SYS_GETGROUPS: u64               = 158;
pub const SYS_SETGROUPS: u64               = 159;
pub const SYS_UNAME: u64                   = 160;
pub const SYS_SETHOSTNAME: u64             = 161;
pub const SYS_SETDOMAINNAME: u64           = 162;
pub const SYS_GETRLIMIT: u64               = 163;
pub const SYS_SETRLIMIT: u64               = 164;
pub const SYS_GETRUSAGE: u64               = 165;
pub const SYS_UMASK: u64                   = 166;
pub const SYS_PRCTL: u64                   = 167;
pub const SYS_GETCPU: u64                  = 168;
pub const SYS_GETTIMEOFDAY: u64            = 169;
pub const SYS_SETTIMEOFDAY: u64            = 170;
pub const SYS_ADJTIMEX: u64                = 171;
pub const SYS_GETPID: u64                  = 172;
pub const SYS_GETPPID: u64                 = 173;
pub const SYS_GETUID: u64                  = 174;
pub const SYS_GETEUID: u64                 = 175;
pub const SYS_GETGID: u64                  = 176;
pub const SYS_GETEGID: u64                 = 177;
pub const SYS_GETTID: u64                  = 178;
pub const SYS_SYSINFO: u64                 = 179;
pub const SYS_MQ_OPEN: u64                 = 180;
pub const SYS_MQ_UNLINK: u64               = 181;
pub const SYS_MQ_TIMEDSEND: u64            = 182;
pub const SYS_MQ_TIMEDRECEIVE: u64         = 183;
pub const SYS_MQ_NOTIFY: u64               = 184;
pub const SYS_MQ_GETSETATTR: u64           = 185;
pub const SYS_MSGGET: u64                  = 186;
pub const SYS_MSGCTL: u64                  = 187;
pub const SYS_MSGRCV: u64                  = 188;
pub const SYS_MSGSND: u64                  = 189;
pub const SYS_SEMGET: u64                  = 190;
pub const SYS_SEMCTL: u64                  = 191;
pub const SYS_SEMTIMEDOP: u64              = 192;
pub const SYS_SEMOP: u64                   = 193;
pub const SYS_SHMGET: u64                  = 194;
pub const SYS_SHMCTL: u64                  = 195;
pub const SYS_SHMAT: u64                   = 196;
pub const SYS_SHMDT: u64                   = 197;
pub const SYS_SOCKET: u64                  = 198;
pub const SYS_SOCKETPAIR: u64              = 199;
pub const SYS_BIND: u64                    = 200;
pub const SYS_LISTEN: u64                  = 201;
pub const SYS_ACCEPT: u64                  = 202;
pub const SYS_CONNECT: u64                 = 203;
pub const SYS_GETSOCKNAME: u64             = 204;
pub const SYS_GETPEERNAME: u64             = 205;
pub const SYS_SENDTO: u64                  = 206;
pub const SYS_RECVFROM: u64                = 207;
pub const SYS_SETSOCKOPT: u64              = 208;
pub const SYS_GETSOCKOPT: u64              = 209;
pub const SYS_SHUTDOWN: u64                = 210;
pub const SYS_SENDMSG: u64                 = 211;
pub const SYS_RECVMSG: u64                 = 212;
pub const SYS_READAHEAD: u64               = 213;
pub const SYS_BRK: u64                     = 214;
pub const SYS_MUNMAP: u64                  = 215;
pub const SYS_MREMAP: u64                  = 216;
pub const SYS_ADD_KEY: u64                 = 217;
pub const SYS_REQUEST_KEY: u64             = 218;
pub const SYS_KEYCTL: u64                  = 219;
pub const SYS_CLONE: u64                   = 220;
pub const SYS_EXECVE: u64                  = 221;
pub const SYS_MMAP: u64                    = 222;
pub const SYS_FADVISE64: u64               = 223;
pub const SYS_SWAPON: u64                  = 224;
pub const SYS_SWAPOFF: u64                 = 225;
pub const SYS_MPROTECT: u64                = 226;
pub const SYS_MSYNC: u64                   = 227;
pub const SYS_MLOCK: u64                   = 228;
pub const SYS_MUNLOCK: u64                 = 229;
pub const SYS_MLOCKALL: u64                = 230;
pub const SYS_MUNLOCKALL: u64              = 231;
pub const SYS_MINCORE: u64                 = 232;
pub const SYS_MADVISE: u64                 = 233;
pub const SYS_REMAP_FILE_PAGES: u64        = 234;
pub const SYS_MBIND: u64                   = 235;
pub const SYS_GET_MEMPOLICY: u64           = 236;
pub const SYS_SET_MEMPOLICY: u64           = 237;
pub const SYS_MIGRATE_PAGES: u64           = 238;
pub const SYS_MOVE_PAGES: u64              = 239;
pub const SYS_RT_TGSIGQUEUEINFO: u64       = 240;
pub const SYS_PERF_EVENT_OPEN: u64         = 241;
pub const SYS_ACCEPT4: u64                 = 242;
pub const SYS_RECVMMSG: u64                = 243;
pub const SYS_WAIT4: u64                   = 260;
pub const SYS_PRLIMIT64: u64               = 261;
pub const SYS_FANOTIFY_INIT: u64           = 262;
pub const SYS_FANOTIFY_MARK: u64           = 263;
pub const SYS_NAME_TO_HANDLE_AT: u64       = 264;
pub const SYS_OPEN_BY_HANDLE_AT: u64       = 265;
pub const SYS_CLOCK_ADJTIME: u64           = 266;
pub const SYS_SYNCFS: u64                  = 267;
pub const SYS_SETNS: u64                   = 268;
pub const SYS_SENDMMSG: u64                = 269;
pub const SYS_PROCESS_VM_READV: u64        = 270;
pub const SYS_PROCESS_VM_WRITEV: u64       = 271;
pub const SYS_KCMP: u64                    = 272;
pub const SYS_FINIT_MODULE: u64            = 273;
pub const SYS_SCHED_SETATTR: u64           = 274;
pub const SYS_SCHED_GETATTR: u64           = 275;
pub const SYS_RENAMEAT2: u64               = 276;
pub const SYS_SECCOMP: u64                 = 277;
pub const SYS_GETRANDOM: u64               = 278;
pub const SYS_MEMFD_CREATE: u64            = 279;
pub const SYS_BPF: u64                     = 280;
pub const SYS_EXECVEAT: u64                = 281;
pub const SYS_USERFAULTFD: u64             = 282;
pub const SYS_MEMBARRIER: u64              = 283;
pub const SYS_MLOCK2: u64                  = 284;
pub const SYS_COPY_FILE_RANGE: u64         = 285;
pub const SYS_PREADV2: u64                 = 286;
pub const SYS_PWRITEV2: u64                = 287;
pub const SYS_PKEY_MPROTECT: u64           = 288;
pub const SYS_PKEY_ALLOC: u64              = 289;
pub const SYS_PKEY_FREE: u64               = 290;
pub const SYS_STATX: u64                   = 291;
pub const SYS_IO_PGETEVENTS: u64           = 292;
pub const SYS_RSEQ: u64                    = 293;
pub const SYS_KEXEC_FILE_LOAD: u64         = 294;

// io_uring & modern Linux system calls
pub const SYS_PIDFD_SEND_SIGNAL: u64       = 424;
pub const SYS_IO_URING_SETUP: u64          = 425;
pub const SYS_IO_URING_ENTER: u64          = 426;
pub const SYS_IO_URING_REGISTER: u64       = 427;
pub const SYS_OPEN_TREE: u64               = 428;
pub const SYS_MOVE_MOUNT: u64              = 429;
pub const SYS_FSOPEN: u64                  = 430;
pub const SYS_FSCONFIG: u64                = 431;
pub const SYS_FSMOUNT: u64                 = 432;
pub const SYS_FSPICK: u64                  = 433;
pub const SYS_PIDFD_OPEN: u64              = 434;
pub const SYS_CLONE3: u64                  = 435;
pub const SYS_CLOSE_RANGE: u64             = 436;
pub const SYS_OPENAT2: u64                 = 437;
pub const SYS_PIDFD_GETFD: u64             = 438;
pub const SYS_FACCESSAT2: u64              = 439;
pub const SYS_PROCESS_MADVISE: u64         = 440;
pub const SYS_EPOLL_PWAIT2: u64            = 441;
pub const SYS_MOUNT_SETATTR: u64           = 442;
pub const SYS_QUOTACTL_FD: u64             = 443;
pub const SYS_LANDLOCK_CREATE_RULESET: u64 = 444;
pub const SYS_LANDLOCK_ADD_RULE: u64       = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: u64  = 446;
pub const SYS_MEMFD_SECRET: u64            = 447;
pub const SYS_PROCESS_MRELEASE: u64        = 448;
pub const SYS_FUTEX_WAITV: u64             = 449;
pub const SYS_SET_MEMPOLICY_HOME_NODE: u64 = 450;

/// Uniform register frame abstraction for generic ABI system call invocation.
///
/// Models 64-bit calling conventions (e.g., AArch64 X8 for vector, X0..X5 for args;
/// RISC-V A7 for vector, A0..A5 for args).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenericSyscallFrame {
    pub syscall_nr: u64,
    pub args: [u64; 6],
    pub ret_code: i64,
    pub flags: u64,
    pub sp: u64,
    pub pc: u64,
}

impl GenericSyscallFrame {
    pub const fn new(syscall_nr: u64) -> Self {
        Self {
            syscall_nr,
            args: [0; 6],
            ret_code: 0,
            flags: 0,
            sp: 0,
            pc: 0,
        }
    }

    #[inline]
    pub const fn syscall_no(&self) -> u64 {
        self.syscall_nr
    }

    #[inline]
    pub const fn arg0(&self) -> u64 {
        self.args[0]
    }

    #[inline]
    pub const fn arg1(&self) -> u64 {
        self.args[1]
    }

    #[inline]
    pub const fn arg2(&self) -> u64 {
        self.args[2]
    }

    #[inline]
    pub const fn arg3(&self) -> u64 {
        self.args[3]
    }

    #[inline]
    pub const fn arg4(&self) -> u64 {
        self.args[4]
    }

    #[inline]
    pub const fn arg5(&self) -> u64 {
        self.args[5]
    }

    #[inline]
    pub fn set_return(&mut self, ret: u64) {
        self.ret_code = ret as i64;
    }
}

/// Translates an x86_64 system call vector into its standard asm-generic/unistd.h vector.
///
/// Covers core POSIX, memory management, file operations, processes, signals, and IPC.
pub fn x86_to_asm_generic(nr: u64) -> Option<u64> {
    match nr {
        x86::SYS_READ => Some(SYS_READ),
        x86::SYS_WRITE => Some(SYS_WRITE),
        x86::SYS_CLOSE => Some(SYS_CLOSE),
        x86::SYS_FSTAT => Some(SYS_FSTAT),
        x86::SYS_LSEEK => Some(SYS_LSEEK),
        x86::SYS_MMAP => Some(SYS_MMAP),
        x86::SYS_MPROTECT => Some(SYS_MPROTECT),
        x86::SYS_MUNMAP => Some(SYS_MUNMAP),
        x86::SYS_BRK => Some(SYS_BRK),
        x86::SYS_RT_SIGACTION => Some(SYS_RT_SIGACTION),
        x86::SYS_RT_SIGPROCMASK => Some(SYS_RT_SIGPROCMASK),
        x86::SYS_RT_SIGRETURN => Some(SYS_RT_SIGRETURN),
        x86::SYS_IOCTL => Some(SYS_IOCTL),
        x86::SYS_PREAD64 => Some(SYS_PREAD64),
        x86::SYS_PWRITE64 => Some(SYS_PWRITE64),
        x86::SYS_READV => Some(SYS_READV),
        x86::SYS_WRITEV => Some(SYS_WRITEV),
        x86::SYS_SCHED_YIELD => Some(SYS_SCHED_YIELD),
        x86::SYS_MREMAP => Some(SYS_MREMAP),
        x86::SYS_MSYNC => Some(SYS_MSYNC),
        x86::SYS_MINCORE => Some(SYS_MINCORE),
        x86::SYS_MADVISE => Some(SYS_MADVISE),
        x86::SYS_SHMGET => Some(SYS_SHMGET),
        x86::SYS_SHMAT => Some(SYS_SHMAT),
        x86::SYS_SHMCTL => Some(SYS_SHMCTL),
        x86::SYS_DUP => Some(SYS_DUP),
        x86::SYS_DUP3 => Some(SYS_DUP3),
        x86::SYS_NANOSLEEP => Some(SYS_NANOSLEEP),
        x86::SYS_GETITIMER => Some(SYS_GETITIMER),
        x86::SYS_SETITIMER => Some(SYS_SETITIMER),
        x86::SYS_GETPID => Some(SYS_GETPID),
        x86::SYS_SENDFILE => Some(SYS_SENDFILE),
        x86::SYS_SOCKET => Some(SYS_SOCKET),
        x86::SYS_CONNECT => Some(SYS_CONNECT),
        x86::SYS_ACCEPT => Some(SYS_ACCEPT),
        x86::SYS_SENDTO => Some(SYS_SENDTO),
        x86::SYS_RECVFROM => Some(SYS_RECVFROM),
        x86::SYS_SENDMSG => Some(SYS_SENDMSG),
        x86::SYS_RECVMSG => Some(SYS_RECVMSG),
        x86::SYS_SHUTDOWN => Some(SYS_SHUTDOWN),
        x86::SYS_BIND => Some(SYS_BIND),
        x86::SYS_LISTEN => Some(SYS_LISTEN),
        x86::SYS_GETSOCKNAME => Some(SYS_GETSOCKNAME),
        x86::SYS_GETPEERNAME => Some(SYS_GETPEERNAME),
        x86::SYS_SOCKETPAIR => Some(SYS_SOCKETPAIR),
        x86::SYS_SETSOCKOPT => Some(SYS_SETSOCKOPT),
        x86::SYS_GETSOCKOPT => Some(SYS_GETSOCKOPT),
        x86::SYS_CLONE => Some(SYS_CLONE),
        x86::SYS_EXECVE => Some(SYS_EXECVE),
        x86::SYS_EXIT => Some(SYS_EXIT),
        x86::SYS_WAIT4 => Some(SYS_WAIT4),
        x86::SYS_KILL => Some(SYS_KILL),
        x86::SYS_UNAME => Some(SYS_UNAME),
        x86::SYS_SEMGET => Some(SYS_SEMGET),
        x86::SYS_SEMOP => Some(SYS_SEMOP),
        x86::SYS_SEMCTL => Some(SYS_SEMCTL),
        x86::SYS_SHMDT => Some(SYS_SHMDT),
        x86::SYS_MSGGET => Some(SYS_MSGGET),
        x86::SYS_MSGSND => Some(SYS_MSGSND),
        x86::SYS_MSGRCV => Some(SYS_MSGRCV),
        x86::SYS_MSGCTL => Some(SYS_MSGCTL),
        x86::SYS_FCNTL => Some(SYS_FCNTL),
        x86::SYS_FLOCK => Some(SYS_FLOCK),
        x86::SYS_FSYNC => Some(SYS_FSYNC),
        x86::SYS_FDATASYNC => Some(SYS_FDATASYNC),
        x86::SYS_TRUNCATE => Some(SYS_TRUNCATE),
        x86::SYS_FTRUNCATE => Some(SYS_FTRUNCATE),
        x86::SYS_GETCWD => Some(SYS_GETCWD),
        x86::SYS_CHDIR => Some(SYS_CHDIR),
        x86::SYS_FCHDIR => Some(SYS_FCHDIR),
        x86::SYS_GETPPID => Some(SYS_GETPPID),
        x86::SYS_GETUID => Some(SYS_GETUID),
        x86::SYS_GETGID => Some(SYS_GETGID),
        x86::SYS_GETEUID => Some(SYS_GETEUID),
        x86::SYS_GETEGID => Some(SYS_GETEGID),
        x86::SYS_GETTID => Some(SYS_GETTID),
        x86::SYS_FUTEX => Some(SYS_FUTEX),
        x86::SYS_SET_TID_ADDRESS => Some(SYS_SET_TID_ADDRESS),
        x86::SYS_EXIT_GROUP => Some(SYS_EXIT_GROUP),
        x86::SYS_EPOLL_CREATE1 => Some(SYS_EPOLL_CREATE1),
        x86::SYS_EPOLL_CTL => Some(SYS_EPOLL_CTL),
        x86::SYS_EPOLL_PWAIT => Some(SYS_EPOLL_PWAIT),
        x86::SYS_PIPE2 => Some(SYS_PIPE2),
        x86::SYS_OPENAT => Some(SYS_OPENAT),
        x86::SYS_MKDIRAT => Some(SYS_MKDIRAT),
        x86::SYS_MKNODAT => Some(SYS_MKNODAT),
        x86::SYS_FCHOWNAT => Some(SYS_FCHOWNAT),
        x86::SYS_NEWFSTATAT => Some(SYS_NEWFSTATAT),
        x86::SYS_UNLINKAT => Some(SYS_UNLINKAT),
        x86::SYS_RENAMEAT => Some(SYS_RENAMEAT),
        x86::SYS_LINKAT => Some(SYS_LINKAT),
        x86::SYS_SYMLINKAT => Some(SYS_SYMLINKAT),
        x86::SYS_READLINKAT => Some(SYS_READLINKAT),
        x86::SYS_FCHMODAT => Some(SYS_FCHMODAT),
        x86::SYS_FACCESSAT => Some(SYS_FACCESSAT),
        x86::SYS_IO_URING_SETUP => Some(SYS_IO_URING_SETUP),
        x86::SYS_IO_URING_ENTER => Some(SYS_IO_URING_ENTER),
        x86::SYS_IO_URING_REGISTER => Some(SYS_IO_URING_REGISTER),
        x86::SYS_CLONE3 => Some(SYS_CLONE3),
        x86::SYS_CLOSE_RANGE => Some(SYS_CLOSE_RANGE),
        x86::SYS_OPENAT2 => Some(SYS_OPENAT2),
        x86::SYS_FACCESSAT2 => Some(SYS_FACCESSAT2),
        x86::SYS_PIVOT_ROOT => Some(SYS_PIVOT_ROOT),
        x86::SYS_CHROOT => Some(SYS_CHROOT),
        x86::SYS_UNSHARE => Some(SYS_UNSHARE),
        x86::SYS_SETNS => Some(SYS_SETNS),
        x86::SYS_SIGALTSTACK => Some(SYS_SIGALTSTACK),
        x86::SYS_TKILL => Some(SYS_TKILL),
        x86::SYS_TGKILL => Some(SYS_TGKILL),
        x86::SYS_MKNOD => Some(SYS_MKNODAT),
        x86::SYS_MQ_OPEN => Some(SYS_MQ_OPEN),
        x86::SYS_MQ_UNLINK => Some(SYS_MQ_UNLINK),
        x86::SYS_MQ_TIMEDSEND => Some(SYS_MQ_TIMEDSEND),
        x86::SYS_MQ_TIMEDRECEIVE => Some(SYS_MQ_TIMEDRECEIVE),
        x86::SYS_MQ_NOTIFY => Some(SYS_MQ_NOTIFY),
        x86::SYS_MQ_GETSETATTR => Some(SYS_MQ_GETSETATTR),
        _ => None,
    }
}

/// Translates a standard asm-generic/unistd.h system call vector into its x86_64 vector.
///
/// Inverts the mapping defined by `x86_to_asm_generic`.
pub fn asm_generic_to_x86(nr: u64) -> Option<u64> {
    match nr {
        SYS_READ => Some(x86::SYS_READ),
        SYS_WRITE => Some(x86::SYS_WRITE),
        SYS_CLOSE => Some(x86::SYS_CLOSE),
        SYS_FSTAT => Some(x86::SYS_FSTAT),
        SYS_LSEEK => Some(x86::SYS_LSEEK),
        SYS_MMAP => Some(x86::SYS_MMAP),
        SYS_MPROTECT => Some(x86::SYS_MPROTECT),
        SYS_MUNMAP => Some(x86::SYS_MUNMAP),
        SYS_BRK => Some(x86::SYS_BRK),
        SYS_RT_SIGACTION => Some(x86::SYS_RT_SIGACTION),
        SYS_RT_SIGPROCMASK => Some(x86::SYS_RT_SIGPROCMASK),
        SYS_RT_SIGRETURN => Some(x86::SYS_RT_SIGRETURN),
        SYS_IOCTL => Some(x86::SYS_IOCTL),
        SYS_PREAD64 => Some(x86::SYS_PREAD64),
        SYS_PWRITE64 => Some(x86::SYS_PWRITE64),
        SYS_READV => Some(x86::SYS_READV),
        SYS_WRITEV => Some(x86::SYS_WRITEV),
        SYS_SCHED_YIELD => Some(x86::SYS_SCHED_YIELD),
        SYS_MREMAP => Some(x86::SYS_MREMAP),
        SYS_MSYNC => Some(x86::SYS_MSYNC),
        SYS_MINCORE => Some(x86::SYS_MINCORE),
        SYS_MADVISE => Some(x86::SYS_MADVISE),
        SYS_SHMGET => Some(x86::SYS_SHMGET),
        SYS_SHMAT => Some(x86::SYS_SHMAT),
        SYS_SHMCTL => Some(x86::SYS_SHMCTL),
        SYS_DUP => Some(x86::SYS_DUP),
        SYS_DUP3 => Some(x86::SYS_DUP3),
        SYS_NANOSLEEP => Some(x86::SYS_NANOSLEEP),
        SYS_GETITIMER => Some(x86::SYS_GETITIMER),
        SYS_SETITIMER => Some(x86::SYS_SETITIMER),
        SYS_GETPID => Some(x86::SYS_GETPID),
        SYS_SENDFILE => Some(x86::SYS_SENDFILE),
        SYS_SOCKET => Some(x86::SYS_SOCKET),
        SYS_CONNECT => Some(x86::SYS_CONNECT),
        SYS_ACCEPT => Some(x86::SYS_ACCEPT),
        SYS_SENDTO => Some(x86::SYS_SENDTO),
        SYS_RECVFROM => Some(x86::SYS_RECVFROM),
        SYS_SENDMSG => Some(x86::SYS_SENDMSG),
        SYS_RECVMSG => Some(x86::SYS_RECVMSG),
        SYS_SHUTDOWN => Some(x86::SYS_SHUTDOWN),
        SYS_BIND => Some(x86::SYS_BIND),
        SYS_LISTEN => Some(x86::SYS_LISTEN),
        SYS_GETSOCKNAME => Some(x86::SYS_GETSOCKNAME),
        SYS_GETPEERNAME => Some(x86::SYS_GETPEERNAME),
        SYS_SOCKETPAIR => Some(x86::SYS_SOCKETPAIR),
        SYS_SETSOCKOPT => Some(x86::SYS_SETSOCKOPT),
        SYS_GETSOCKOPT => Some(x86::SYS_GETSOCKOPT),
        SYS_CLONE => Some(x86::SYS_CLONE),
        SYS_EXECVE => Some(x86::SYS_EXECVE),
        SYS_EXIT => Some(x86::SYS_EXIT),
        SYS_WAIT4 => Some(x86::SYS_WAIT4),
        SYS_KILL => Some(x86::SYS_KILL),
        SYS_UNAME => Some(x86::SYS_UNAME),
        SYS_SEMGET => Some(x86::SYS_SEMGET),
        SYS_SEMOP => Some(x86::SYS_SEMOP),
        SYS_SEMCTL => Some(x86::SYS_SEMCTL),
        SYS_SHMDT => Some(x86::SYS_SHMDT),
        SYS_MSGGET => Some(x86::SYS_MSGGET),
        SYS_MSGSND => Some(x86::SYS_MSGSND),
        SYS_MSGRCV => Some(x86::SYS_MSGRCV),
        SYS_MSGCTL => Some(x86::SYS_MSGCTL),
        SYS_FCNTL => Some(x86::SYS_FCNTL),
        SYS_FLOCK => Some(x86::SYS_FLOCK),
        SYS_FSYNC => Some(x86::SYS_FSYNC),
        SYS_FDATASYNC => Some(x86::SYS_FDATASYNC),
        SYS_TRUNCATE => Some(x86::SYS_TRUNCATE),
        SYS_FTRUNCATE => Some(x86::SYS_FTRUNCATE),
        SYS_GETCWD => Some(x86::SYS_GETCWD),
        SYS_CHDIR => Some(x86::SYS_CHDIR),
        SYS_FCHDIR => Some(x86::SYS_FCHDIR),
        SYS_GETPPID => Some(x86::SYS_GETPPID),
        SYS_GETUID => Some(x86::SYS_GETUID),
        SYS_GETGID => Some(x86::SYS_GETGID),
        SYS_GETEUID => Some(x86::SYS_GETEUID),
        SYS_GETEGID => Some(x86::SYS_GETEGID),
        SYS_GETTID => Some(x86::SYS_GETTID),
        SYS_FUTEX => Some(x86::SYS_FUTEX),
        SYS_SET_TID_ADDRESS => Some(x86::SYS_SET_TID_ADDRESS),
        SYS_EXIT_GROUP => Some(x86::SYS_EXIT_GROUP),
        SYS_EPOLL_CREATE1 => Some(x86::SYS_EPOLL_CREATE1),
        SYS_EPOLL_CTL => Some(x86::SYS_EPOLL_CTL),
        SYS_EPOLL_PWAIT => Some(x86::SYS_EPOLL_PWAIT),
        SYS_PIPE2 => Some(x86::SYS_PIPE2),
        SYS_OPENAT => Some(x86::SYS_OPENAT),
        SYS_MKDIRAT => Some(x86::SYS_MKDIRAT),
        SYS_MKNODAT => Some(x86::SYS_MKNODAT),
        SYS_FCHOWNAT => Some(x86::SYS_FCHOWNAT),
        SYS_NEWFSTATAT => Some(x86::SYS_NEWFSTATAT),
        SYS_UNLINKAT => Some(x86::SYS_UNLINKAT),
        SYS_RENAMEAT => Some(x86::SYS_RENAMEAT),
        SYS_LINKAT => Some(x86::SYS_LINKAT),
        SYS_SYMLINKAT => Some(x86::SYS_SYMLINKAT),
        SYS_READLINKAT => Some(x86::SYS_READLINKAT),
        SYS_FCHMODAT => Some(x86::SYS_FCHMODAT),
        SYS_FACCESSAT => Some(x86::SYS_FACCESSAT),
        SYS_IO_URING_SETUP => Some(x86::SYS_IO_URING_SETUP),
        SYS_IO_URING_ENTER => Some(x86::SYS_IO_URING_ENTER),
        SYS_IO_URING_REGISTER => Some(x86::SYS_IO_URING_REGISTER),
        SYS_CLONE3 => Some(x86::SYS_CLONE3),
        SYS_CLOSE_RANGE => Some(x86::SYS_CLOSE_RANGE),
        SYS_OPENAT2 => Some(x86::SYS_OPENAT2),
        SYS_FACCESSAT2 => Some(x86::SYS_FACCESSAT2),
        SYS_PIVOT_ROOT => Some(x86::SYS_PIVOT_ROOT),
        SYS_CHROOT => Some(x86::SYS_CHROOT),
        SYS_UNSHARE => Some(x86::SYS_UNSHARE),
        SYS_SETNS => Some(x86::SYS_SETNS),
        SYS_SIGALTSTACK => Some(x86::SYS_SIGALTSTACK),
        SYS_TKILL => Some(x86::SYS_TKILL),
        SYS_TGKILL => Some(x86::SYS_TGKILL),
        SYS_MQ_OPEN => Some(x86::SYS_MQ_OPEN),
        SYS_MQ_UNLINK => Some(x86::SYS_MQ_UNLINK),
        SYS_MQ_TIMEDSEND => Some(x86::SYS_MQ_TIMEDSEND),
        SYS_MQ_TIMEDRECEIVE => Some(x86::SYS_MQ_TIMEDRECEIVE),
        SYS_MQ_NOTIFY => Some(x86::SYS_MQ_NOTIFY),
        SYS_MQ_GETSETATTR => Some(x86::SYS_MQ_GETSETATTR),
        _ => None,
    }
}

/// Unit validation for asm-generic syscall mappings and frame accessors.
pub fn verify_domain_syscall_tables() -> u32 {
    let mut tests_passed = 0u32;

    // Verify frame construction and argument getters
    let mut frame = GenericSyscallFrame::new(SYS_WRITE);
    frame.args[0] = 1; // stdout
    frame.args[1] = 0x1000; // buffer
    frame.args[2] = 42; // count
    if frame.syscall_no() == 64 && frame.arg0() == 1 && frame.arg1() == 0x1000 && frame.arg2() == 42 {
        tests_passed += 1;
    }

    frame.set_return(42);
    if frame.ret_code == 42 {
        tests_passed += 1;
    }

    // Verify bidirectional translation between x86_64 and asm-generic
    let sample_x86_syscalls = [
        x86::SYS_READ,
        x86::SYS_WRITE,
        x86::SYS_CLOSE,
        x86::SYS_MMAP,
        x86::SYS_MUNMAP,
        x86::SYS_BRK,
        x86::SYS_CLONE,
        x86::SYS_EXECVE,
        x86::SYS_EXIT,
        x86::SYS_GETPID,
        x86::SYS_FUTEX,
        x86::SYS_OPENAT,
        x86::SYS_IO_URING_SETUP,
        x86::SYS_MQ_OPEN,
    ];

    let mut translation_success = true;
    for &sc in &sample_x86_syscalls {
        if let Some(generic_nr) = x86_to_asm_generic(sc) {
            if let Some(back_x86) = asm_generic_to_x86(generic_nr) {
                if back_x86 != sc {
                    translation_success = false;
                    break;
                }
            } else {
                translation_success = false;
                break;
            }
        } else {
            translation_success = false;
            break;
        }
    }

    if translation_success {
        tests_passed += 1;
    }

    tests_passed
}
