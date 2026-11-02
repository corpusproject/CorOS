//! Pure Native Virtual File System (VFS) and Synthetic Device Subsystem for CorOS.
//! Provides abstract file nodes, /dev device files, /proc dynamic telemetry files,
//! and RDRAND hardware true random number generation.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::fs::fat32::GLOBAL_FS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeType {
    File,
    Directory,
    CharDevice,
    BlockDevice,
}

pub trait VfsNode: Send + Sync {
    fn name(&self) -> &str;
    fn node_type(&self) -> NodeType;
    fn size(&self) -> usize;
    fn read(&self, offset: usize, buf: &mut [u8]) -> usize;
    fn write(&mut self, offset: usize, buf: &[u8]) -> usize;
}

/// Dynamic /proc file node generating live telemetry strings
pub struct ProcFile {
    pub name: &'static str,
    pub generator: fn() -> String,
}

impl VfsNode for ProcFile {
    fn name(&self) -> &str {
        self.name
    }

    fn node_type(&self) -> NodeType {
        NodeType::File
    }

    fn size(&self) -> usize {
        (self.generator)().len()
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let content = (self.generator)();
        let bytes = content.as_bytes();
        if offset >= bytes.len() {
            return 0;
        }
        let available = bytes.len() - offset;
        let to_read = available.min(buf.len());
        buf[..to_read].copy_from_slice(&bytes[offset..offset + to_read]);
        to_read
    }

    fn write(&mut self, _offset: usize, _buf: &[u8]) -> usize {
        0 // /proc nodes are read-only
    }
}

/// /dev/null device - discards all writes, returns EOF on read
pub struct DevNull;

impl VfsNode for DevNull {
    fn name(&self) -> &str { "null" }
    fn node_type(&self) -> NodeType { NodeType::CharDevice }
    fn size(&self) -> usize { 0 }
    fn read(&self, _offset: usize, _buf: &mut [u8]) -> usize { 0 }
    fn write(&mut self, _offset: usize, buf: &[u8]) -> usize { buf.len() }
}

/// /dev/zero device - returns endless stream of 0x00 bytes
pub struct DevZero;

impl VfsNode for DevZero {
    fn name(&self) -> &str { "zero" }
    fn node_type(&self) -> NodeType { NodeType::CharDevice }
    fn size(&self) -> usize { usize::MAX }
    fn read(&self, _offset: usize, buf: &mut [u8]) -> usize {
        buf.fill(0);
        buf.len()
    }
    fn write(&mut self, _offset: usize, buf: &[u8]) -> usize { buf.len() }
}

/// /dev/random & /dev/urandom device - Hardware True Random via CPU RDRAND instruction
pub struct DevRandom;

impl DevRandom {
    /// Reads a 64-bit hardware random integer via x86_64 RDRAND instruction
    pub fn rdrand64() -> u64 {
        let mut val: u64 = 0;
        let mut success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) val,
                out(reg_byte) success,
                options(nomem, nostack)
            );
        }
        if success != 0 {
            val
        } else {
            // Fallback PRNG if CPU doesn't support RDRAND
            crate::time::TscCounter::read_ticks().0.wrapping_mul(6364136223846793005).wrapping_add(1)
        }
    }
}

impl VfsNode for DevRandom {
    fn name(&self) -> &str { "random" }
    fn node_type(&self) -> NodeType { NodeType::CharDevice }
    fn size(&self) -> usize { usize::MAX }
    fn read(&self, _offset: usize, buf: &mut [u8]) -> usize {
        let mut chunks = buf.chunks_exact_mut(8);
        for chunk in &mut chunks {
            let rnd = Self::rdrand64();
            chunk.copy_from_slice(&rnd.to_le_bytes());
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let rnd = Self::rdrand64();
            let bytes = rnd.to_le_bytes();
            rem.copy_from_slice(&bytes[..rem.len()]);
        }
        buf.len()
    }
    fn write(&mut self, _offset: usize, buf: &[u8]) -> usize { buf.len() }
}

/// Global Virtual File System router
pub struct VfsRouter {
    proc_entries: Vec<ProcFile>,
}

impl VfsRouter {
    pub fn new() -> Self {
        let mut router = Self {
            proc_entries: Vec::new(),
        };

        // Register /proc/cpuinfo
        router.proc_entries.push(ProcFile {
            name: "cpuinfo",
            generator: || {
                format!(
                    "processor\t: 0\r\nvendor_id\t: GenuineIntel / CorOS-SMP\r\nmodel name\t: x86_64 SMP 4-Core Processor\r\ncpu MHz\t\t: 2600.000\r\ncache size\t: 4096 KB\r\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm rdrand\r\n"
                )
            },
        });

        // Register /proc/meminfo
        router.proc_entries.push(ProcFile {
            name: "meminfo",
            generator: || {
                let (alloc_bytes, _cap) = crate::memory::heap::heap_stats();
                format!(
                    "MemTotal:\t 1048576 kB\r\nMemFree:\t {} kB\r\nMemAvailable:\t 1024000 kB\r\nBuffers:\t    4096 kB\r\nCached:\t   16384 kB\r\nHeapAlloc:\t   {} kB\r\n",
                    1048576 - (alloc_bytes / 1024),
                    alloc_bytes / 1024
                )
            },
        });

        // Register /proc/uptime
        router.proc_entries.push(ProcFile {
            name: "uptime",
            generator: || {
                let ticks = crate::time::TscCounter::read_ticks().0;
                let secs = ticks / 2_600_000_000;
                let centis = (ticks % 2_600_000_000) / 26_000_000;
                format!("{}.{:02} {}.00\r\n", secs, centis, secs * 4)
            },
        });

        // Register /proc/version
        router.proc_entries.push(ProcFile {
            name: "version",
            generator: || {
                format!("CorOS version 0.1.0-ultra (coros@silicon) (rustc 1.90.0-nightly) #1 SMP 2026\r\n")
            },
        });

        // Register /proc/modules (Linux Dynamic Kernel Modules)
        router.proc_entries.push(ProcFile {
            name: "modules",
            generator: || {
                let mut out = String::new();
                for m in crate::kmod::MODULE_MANAGER.list_modules() {
                    let dep_str = if m.dependencies.is_empty() { String::from("-") } else { m.dependencies.join(",") };
                    out.push_str(&format!("{:<14} {:>6}  Live 0x{:08X} [{}]\r\n", m.name, m.size, m.init_address, dep_str));
                }
                out
            },
        });

        // Register /proc/ipc (POSIX Pipes and Unix Sockets)
        router.proc_entries.push(ProcFile {
            name: "ipc",
            generator: || crate::ipc::IPC_MANAGER.lock().proc_summary(),
        });

        // Register /proc/signals (POSIX Signals)
        router.proc_entries.push(ProcFile {
            name: "signals",
            generator: || crate::signal::SIGNAL_MANAGER.lock().list_signals_proc(),
        });

        // Register /proc/services (Systemd Units)
        router.proc_entries.push(ProcFile {
            name: "services",
            generator: || crate::service::SERVICE_MANAGER.lock().list_services(),
        });

        router
    }

    /// Reads a file from VFS paths like "/proc/cpuinfo", "/dev/random", "/etc/os-release", or delegates to FAT32 C:\
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let clean = path.trim_start_matches('/').trim_start_matches('\\');

        if clean.starts_with("proc/") || clean.starts_with("proc\\") {
            let proc_name = &clean[5..];
            for entry in &self.proc_entries {
                if entry.name.eq_ignore_ascii_case(proc_name) {
                    let mut buf = alloc::vec![0u8; entry.size()];
                    let read_len = entry.read(0, &mut buf);
                    buf.truncate(read_len);
                    return Some(buf);
                }
            }
            return None;
        }

        if clean.starts_with("etc/") || clean.starts_with("etc\\") {
            let etc_name = &clean[4..];
            if etc_name.eq_ignore_ascii_case("os-release") {
                let text = "NAME=\"CorOS\"\nVERSION=\"0.1.0-ultra (Bare-Metal Linux Compat)\"\nID=coros\nID_LIKE=linux\nPRETTY_NAME=\"CorOS Ultra Bare-Metal Linux Compatibility System\"\nANSI_COLOR=\"0;36\"\n";
                return Some(text.as_bytes().to_vec());
            } else if etc_name.eq_ignore_ascii_case("hostname") {
                return Some(b"silicon-coros\n".to_vec());
            } else if etc_name.eq_ignore_ascii_case("passwd") {
                let text = "root:x:0:0:root:/root:/bin/coros-sh\ncoros:x:1000:1000:CorOS User:/home/coros:/bin/coros-sh\n";
                return Some(text.as_bytes().to_vec());
            } else if etc_name.eq_ignore_ascii_case("environment") {
                let text = crate::env::ENV_MANAGER.lock().print_all();
                return Some(text.into_bytes());
            }
            return None;
        }

        if clean.starts_with("dev/") || clean.starts_with("dev\\") {
            let dev_name = &clean[4..];
            if dev_name.eq_ignore_ascii_case("null") {
                return Some(Vec::new());
            } else if dev_name.eq_ignore_ascii_case("zero") {
                return Some(alloc::vec![0u8; 64]);
            } else if dev_name.eq_ignore_ascii_case("random") || dev_name.eq_ignore_ascii_case("urandom") {
                let mut buf = alloc::vec![0u8; 32];
                let dev = DevRandom;
                dev.read(0, &mut buf);
                return Some(buf);
            }
            return None;
        }

        // Delegate to native FAT32 storage disk
        unsafe {
            if let Some(fs) = (*core::ptr::addr_of_mut!(GLOBAL_FS)).as_mut() {
                let disk_path = if clean.starts_with("EFI/") || clean.starts_with("EFI\\") {
                    String::from(clean)
                } else {
                    format!("EFI/COROS/{}", clean)
                };
                return fs.read_file(&disk_path).ok();
            }
        }

        None
    }
}

pub static mut GLOBAL_VFS: Option<VfsRouter> = None;

pub fn initialize() {
    unsafe {
        GLOBAL_VFS = Some(VfsRouter::new());
        crate::diagnostics::serial::write_str("[VFS] Virtual File System (/proc, /dev, /dev/random RDRAND) online!\r\n");
    }
}
