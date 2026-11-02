//! Linux x86_64 System Call Vector Table & Register Frame Abstraction.
//!
//! Provides the complete Linux x86_64 ABI system call number matrix (0..450)
//! and the hardware register frame mapping (RAX, RDI, RSI, RDX, R10, R8, R9).

pub const ARCH_X86_64: u32 = 1;

// ============================================================================
// Core Linux x86_64 System Call Vectors (0..100)
// ============================================================================
pub const SYS_READ: u64                  = 0;
pub const SYS_WRITE: u64                 = 1;
pub const SYS_OPEN: u64                  = 2;
pub const SYS_CLOSE: u64                 = 3;
pub const SYS_STAT: u64                  = 4;
pub const SYS_FSTAT: u64                 = 5;
pub const SYS_LSTAT: u64                 = 6;
pub const SYS_POLL: u64                  = 7;
pub const SYS_LSEEK: u64                 = 8;
pub const SYS_MMAP: u64                  = 9;
pub const SYS_MPROTECT: u64              = 10;
pub const SYS_MUNMAP: u64                = 11;
pub const SYS_BRK: u64                   = 12;
pub const SYS_RT_SIGACTION: u64          = 13;
pub const SYS_RT_SIGPROCMASK: u64        = 14;
pub const SYS_RT_SIGRETURN: u64          = 15;
pub const SYS_IOCTL: u64                 = 16;
pub const SYS_PREAD64: u64               = 17;
pub const SYS_PWRITE64: u64              = 18;
pub const SYS_READV: u64                 = 19;
pub const SYS_WRITEV: u64                = 20;
pub const SYS_ACCESS: u64                = 21;
pub const SYS_PIPE: u64                  = 22;
pub const SYS_SELECT: u64                = 23;
pub const SYS_SCHED_YIELD: u64           = 24;
pub const SYS_MREMAP: u64                = 25;
pub const SYS_MSYNC: u64                 = 26;
pub const SYS_MINCORE: u64               = 27;
pub const SYS_MADVISE: u64               = 28;
pub const SYS_SHMGET: u64                = 29;
pub const SYS_SHMAT: u64                 = 30;
pub const SYS_SHMCTL: u64                = 31;
pub const SYS_DUP: u64                   = 32;
pub const SYS_DUP2: u64                  = 33;
pub const SYS_PAUSE: u64                 = 34;
pub const SYS_NANOSLEEP: u64             = 35;
pub const SYS_GETITIMER: u64             = 36;
pub const SYS_ALARM: u64                 = 37;
pub const SYS_SETITIMER: u64             = 38;
pub const SYS_GETPID: u64                = 39;
pub const SYS_SENDFILE: u64              = 40;
pub const SYS_SOCKET: u64                = 41;
pub const SYS_CONNECT: u64               = 42;
pub const SYS_ACCEPT: u64                = 43;
pub const SYS_SENDTO: u64                = 44;
pub const SYS_RECVFROM: u64              = 45;
pub const SYS_SENDMSG: u64               = 46;
pub const SYS_RECVMSG: u64               = 47;
pub const SYS_SHUTDOWN: u64              = 48;
pub const SYS_BIND: u64                  = 49;
pub const SYS_LISTEN: u64                = 50;
pub const SYS_GETSOCKNAME: u64           = 51;
pub const SYS_GETPEERNAME: u64           = 52;
pub const SYS_SOCKETPAIR: u64            = 53;
pub const SYS_SETSOCKOPT: u64            = 54;
pub const SYS_GETSOCKOPT: u64            = 55;
pub const SYS_CLONE: u64                 = 56;
pub const SYS_FORK: u64                  = 57;
pub const SYS_VFORK: u64                 = 58;
pub const SYS_EXECVE: u64                = 59;
pub const SYS_EXIT: u64                  = 60;
pub const SYS_WAIT4: u64                 = 61;
pub const SYS_KILL: u64                  = 62;
pub const SYS_UNAME: u64                 = 63;
pub const SYS_SEMGET: u64                = 64;
pub const SYS_SEMOP: u64                 = 65;
pub const SYS_SEMCTL: u64                = 66;
pub const SYS_SHMDT: u64                 = 67;
pub const SYS_MSGGET: u64                = 68;
pub const SYS_MSGSND: u64                = 69;
pub const SYS_MSGRCV: u64                = 70;
pub const SYS_MSGCTL: u64                = 71;
pub const SYS_FCNTL: u64                 = 72;
pub const SYS_FLOCK: u64                 = 73;
pub const SYS_FSYNC: u64                 = 74;
pub const SYS_FDATASYNC: u64             = 75;
pub const SYS_TRUNCATE: u64              = 76;
pub const SYS_FTRUNCATE: u64             = 77;
pub const SYS_GETDENTS: u64              = 78;
pub const SYS_GETCWD: u64                = 79;
pub const SYS_CHDIR: u64                 = 80;
pub const SYS_FCHDIR: u64                = 81;
pub const SYS_RENAME: u64                = 82;
pub const SYS_MKDIR: u64                 = 83;
pub const SYS_RMDIR: u64                 = 84;
pub const SYS_CREAT: u64                 = 85;
pub const SYS_LINK: u64                  = 86;
pub const SYS_UNLINK: u64                = 87;
pub const SYS_SYMLINK: u64               = 88;
pub const SYS_READLINK: u64              = 89;
pub const SYS_CHMOD: u64                 = 90;
pub const SYS_FCHMOD: u64                = 91;
pub const SYS_CHOWN: u64                 = 92;
pub const SYS_FCHOWN: u64                = 93;
pub const SYS_LCHOWN: u64                = 94;
pub const SYS_UMASK: u64                 = 95;
pub const SYS_GETTIMEOFDAY: u64          = 96;
pub const SYS_GETRLIMIT: u64             = 97;
pub const SYS_GETRUSAGE: u64             = 98;
pub const SYS_SYSINFO: u64               = 99;
pub const SYS_TIMES: u64                 = 100;

// ============================================================================
// Extended Linux x86_64 Vectors (101..300)
// ============================================================================
pub const SYS_GETUID: u64                = 102;
pub const SYS_SYSLOG: u64                = 103;
pub const SYS_GETGID: u64                = 104;
pub const SYS_SETUID: u64                = 105;
pub const SYS_SETGID: u64                = 106;
pub const SYS_GETEUID: u64               = 107;
pub const SYS_GETEGID: u64               = 108;
pub const SYS_SETPGID: u64               = 109;
pub const SYS_GETPPID: u64               = 110;
pub const SYS_SETSID: u64                = 112;
pub const SYS_CAPGET: u64                = 125;
pub const SYS_CAPSET: u64                = 126;
pub const SYS_SIGALTSTACK: u64           = 131;
pub const SYS_MKNOD: u64                 = 133;
pub const SYS_STATFS: u64                = 137;
pub const SYS_FSTATFS: u64               = 138;
pub const SYS_PRCTL: u64                 = 157;
pub const SYS_ARCH_PRCTL: u64            = 158;
pub const SYS_PIVOT_ROOT: u64            = 155;
pub const SYS_CHROOT: u64                = 161;
pub const SYS_SYNC: u64                  = 162;
pub const SYS_MOUNT: u64                 = 165;
pub const SYS_UMOUNT2: u64               = 166;
pub const SYS_REBOOT: u64                = 169;
pub const SYS_INIT_MODULE: u64           = 175;
pub const SYS_DELETE_MODULE: u64         = 176;
pub const SYS_GETTID: u64                = 186;
pub const SYS_TKILL: u64                 = 200;
pub const SYS_TIME: u64                  = 201;
pub const SYS_FUTEX: u64                 = 202;
pub const SYS_EPOLL_CREATE: u64          = 213;
pub const SYS_GETDENTS64: u64            = 217;
pub const SYS_SET_TID_ADDRESS: u64       = 218;
pub const SYS_CLOCK_GETTIME: u64         = 228;
pub const SYS_EXIT_GROUP: u64            = 231;
pub const SYS_EPOLL_WAIT: u64            = 232;
pub const SYS_EPOLL_CTL: u64             = 233;
pub const SYS_TGKILL: u64                = 234;
pub const SYS_MQ_OPEN: u64               = 240;
pub const SYS_MQ_UNLINK: u64             = 241;
pub const SYS_MQ_TIMEDSEND: u64          = 242;
pub const SYS_MQ_TIMEDRECEIVE: u64       = 243;
pub const SYS_MQ_NOTIFY: u64             = 244;
pub const SYS_MQ_GETSETATTR: u64         = 245;
pub const SYS_OPENAT: u64                = 257;
pub const SYS_MKDIRAT: u64               = 258;
pub const SYS_MKNODAT: u64               = 259;
pub const SYS_FCHOWNAT: u64              = 260;
pub const SYS_NEWFSTATAT: u64            = 262;
pub const SYS_UNLINKAT: u64              = 263;
pub const SYS_RENAMEAT: u64              = 264;
pub const SYS_LINKAT: u64                = 265;
pub const SYS_SYMLINKAT: u64             = 266;
pub const SYS_READLINKAT: u64            = 267;
pub const SYS_FCHMODAT: u64              = 268;
pub const SYS_FACCESSAT: u64             = 269;
pub const SYS_PSELECT6: u64              = 270;
pub const SYS_PPOLL: u64                 = 271;
pub const SYS_UNSHARE: u64               = 272;
pub const SYS_EPOLL_PWAIT: u64           = 281;
pub const SYS_FALLOCATE: u64             = 285;
pub const SYS_ACCEPT4: u64               = 288;
pub const SYS_EPOLL_CREATE1: u64         = 291;
pub const SYS_DUP3: u64                  = 292;
pub const SYS_PIPE2: u64                 = 293;

// ============================================================================
// Modern Linux x86_64 Vectors (301..450)
// ============================================================================
pub const SYS_PRLIMIT64: u64             = 302;
pub const SYS_SYNCFS: u64                = 306;
pub const SYS_SETNS: u64                 = 308;
pub const SYS_GETCPU: u64                = 309;
pub const SYS_FINIT_MODULE: u64          = 313;
pub const SYS_SECCOMP: u64               = 317;
pub const SYS_GETRANDOM: u64             = 318;
pub const SYS_MEMFD_CREATE: u64          = 319;
pub const SYS_BPF: u64                   = 321;
pub const SYS_EXECVEAT: u64              = 322;
pub const SYS_STATX: u64                 = 332;
pub const SYS_IO_URING_SETUP: u64        = 425;
pub const SYS_IO_URING_ENTER: u64        = 426;
pub const SYS_IO_URING_REGISTER: u64     = 427;
pub const SYS_CLONE3: u64                = 435;
pub const SYS_CLOSE_RANGE: u64           = 436;
pub const SYS_OPENAT2: u64               = 437;
pub const SYS_FACCESSAT2: u64            = 439;

/// Hardware register state for an incoming x86_64 SYSCALL instruction.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86SyscallFrame {
    pub rax: u64, // Syscall vector on entry / return value on exit
    pub rdi: u64, // Arg 1
    pub rsi: u64, // Arg 2
    pub rdx: u64, // Arg 3
    pub r10: u64, // Arg 4 (POSIX kernel uses r10, userspace rcx)
    pub r8:  u64, // Arg 5
    pub r9:  u64, // Arg 6
    pub r11: u64, // Saved RFLAGS
    pub rcx: u64, // Saved user RIP
    pub rsp: u64, // Saved user RSP
}

impl X86SyscallFrame {
    pub const fn new() -> Self {
        Self {
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
        }
    }

    #[inline]
    pub const fn syscall_no(&self) -> u64 {
        self.rax
    }

    #[inline]
    pub const fn arg0(&self) -> u64 {
        self.rdi
    }

    #[inline]
    pub const fn arg1(&self) -> u64 {
        self.rsi
    }

    #[inline]
    pub const fn arg2(&self) -> u64 {
        self.rdx
    }

    #[inline]
    pub const fn arg3(&self) -> u64 {
        self.r10
    }

    #[inline]
    pub const fn arg4(&self) -> u64 {
        self.r8
    }

    #[inline]
    pub const fn arg5(&self) -> u64 {
        self.r9
    }

    #[inline]
    pub fn set_return(&mut self, ret: u64) {
        self.rax = ret;
    }
}
