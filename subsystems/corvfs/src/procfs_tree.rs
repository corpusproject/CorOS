//! CorOS VFS Module: `procfs_tree`
//!
//! Dynamic `/proc` pseudo-filesystem generator synthesizing live kernel and process
//! telemetry (`/proc/cpuinfo`, `/proc/meminfo`, `/proc/uptime`, `/proc/version`,
//! `/proc/mounts`, `/proc/interrupts`, `/proc/stat`, `/proc/<pid>/status`, and `/proc/<pid>/maps`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Snapshot of system-wide hardware and kernel metrics used to synthesize `/proc` files.
#[derive(Clone, Debug)]
pub struct ProcSystemTelemetry {
    pub cpu_vendor: &'static str,
    pub cpu_model_name: &'static str,
    pub logical_cores: u32,
    pub cpu_mhz: u32,
    pub cache_size_kb: u32,
    pub total_ram_kb: u64,
    pub free_ram_kb: u64,
    pub cached_ram_kb: u64,
    pub slab_ram_kb: u64,
    pub uptime_ticks_ms: u64,
    pub idle_ticks_ms: u64,
    pub context_switches: u64,
    pub boot_epoch_sec: u64,
    pub timer_irqs: u64,
    pub nvme_irqs: u64,
    pub xhci_irqs: u64,
}

impl ProcSystemTelemetry {
    pub const fn coros_default() -> Self {
        Self {
            cpu_vendor: "GenuineIntel",
            cpu_model_name: "CorOS x86_64 Virtual SMP Processor @ 3.60GHz",
            logical_cores: 4,
            cpu_mhz: 3600,
            cache_size_kb: 16384,
            total_ram_kb: 4 * 1024 * 1024, // 4 GiB
            free_ram_kb: 3 * 1024 * 1024,
            cached_ram_kb: 262_144,
            slab_ram_kb: 65_536,
            uptime_ticks_ms: 142_850,
            idle_ticks_ms: 520_100,
            context_switches: 98_412,
            boot_epoch_sec: 1_761_500_000,
            timer_irqs: 142_850,
            nvme_irqs: 4_128,
            xhci_irqs: 1_904,
        }
    }
}

/// Process execution state exposed in `/proc/<pid>/status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcTaskState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
}

impl ProcTaskState {
    pub const fn as_proc_str(self) -> &'static str {
        match self {
            Self::Running => "R (running)",
            Self::Sleeping => "S (sleeping)",
            Self::DiskSleep => "D (disk sleep)",
            Self::Zombie => "Z (zombie)",
            Self::Stopped => "T (stopped)",
        }
    }
}

/// Virtual memory region descriptor exposed in `/proc/<pid>/maps`.
#[derive(Clone, Debug)]
pub struct ProcVmMapRegion {
    pub start_va: u64,
    pub end_va: u64,
    pub perms: [u8; 4], // e.g., *b"r-xp"
    pub file_offset: u64,
    pub inode: u64,
    pub pathname: &'static str,
}

/// Per-process telemetry record for `/proc/<pid>/*`.
#[derive(Clone, Debug)]
pub struct ProcTaskRecord {
    pub pid: u32,
    pub ppid: u32,
    pub name: &'static str,
    pub state: ProcTaskState,
    pub uid: u32,
    pub gid: u32,
    pub threads: u32,
    pub vm_size_kb: u64,
    pub vm_rss_kb: u64,
    pub regions: Vec<ProcVmMapRegion>,
}

/// Dynamic `/proc` Virtual File System Generator.
pub struct ProcFsTree {
    pub sys: ProcSystemTelemetry,
    pub tasks: Vec<ProcTaskRecord>,
}

impl ProcFsTree {
    pub fn with_defaults() -> Self {
        let mut tasks = Vec::new();
        tasks.push(ProcTaskRecord {
            pid: 1,
            ppid: 0,
            name: "corinit",
            state: ProcTaskState::Sleeping,
            uid: 0,
            gid: 0,
            threads: 1,
            vm_size_kb: 16384,
            vm_rss_kb: 4096,
            regions: alloc::vec![
                ProcVmMapRegion {
                    start_va: 0x0000_0000_0040_0000,
                    end_va: 0x0000_0000_0048_0000,
                    perms: *b"r-xp",
                    file_offset: 0,
                    inode: 102,
                    pathname: "/sbin/corinit",
                },
                ProcVmMapRegion {
                    start_va: 0x0000_7FFF_FFFE_0000,
                    end_va: 0x0000_7FFF_FFFF_F000,
                    perms: *b"rw-p",
                    file_offset: 0,
                    inode: 0,
                    pathname: "[stack]",
                },
            ],
        });

        tasks.push(ProcTaskRecord {
            pid: 2,
            ppid: 1,
            name: "corshell",
            state: ProcTaskState::Running,
            uid: 1000,
            gid: 1000,
            threads: 2,
            vm_size_kb: 24576,
            vm_rss_kb: 6144,
            regions: alloc::vec![
                ProcVmMapRegion {
                    start_va: 0x0000_0000_0080_0000,
                    end_va: 0x0000_0000_0089_0000,
                    perms: *b"r-xp",
                    file_offset: 0,
                    inode: 205,
                    pathname: "/bin/corshell",
                },
            ],
        });

        Self {
            sys: ProcSystemTelemetry::coros_default(),
            tasks,
        }
    }

    /// Generates the contents of a relative path inside `/proc` (e.g. `"/cpuinfo"`, `"/1/status"`).
    pub fn read_proc_node(&self, rel_path: &str) -> Option<String> {
        let trimmed = rel_path.trim_matches('/');
        match trimmed {
            "cpuinfo" => Some(self.gen_cpuinfo()),
            "meminfo" => Some(self.gen_meminfo()),
            "uptime" => Some(self.gen_uptime()),
            "version" => Some(self.gen_version()),
            "mounts" => Some(self.gen_mounts()),
            "interrupts" => Some(self.gen_interrupts()),
            "stat" => Some(self.gen_stat()),
            _ => {
                let mut parts = trimmed.split('/');
                let pid_str = parts.next()?;
                let leaf = parts.next()?;
                if parts.next().is_some() {
                    return None;
                }
                let pid: u32 = pid_str.parse().ok()?;
                let task = self.tasks.iter().find(|t| t.pid == pid)?;
                match leaf {
                    "status" => Some(self.gen_task_status(task)),
                    "maps" => Some(self.gen_task_maps(task)),
                    _ => None,
                }
            }
        }
    }

    fn gen_cpuinfo(&self) -> String {
        let mut out = String::new();
        for core in 0..self.sys.logical_cores {
            out.push_str(&format!(
                "processor\t: {}\nvendor_id\t: {}\nmodel name\t: {}\ncpu MHz\t\t: {}.000\ncache size\t: {} KB\nfpu\t\t: yes\n\n",
                core,
                self.sys.cpu_vendor,
                self.sys.cpu_model_name,
                self.sys.cpu_mhz,
                self.sys.cache_size_kb
            ));
        }
        out
    }

    fn gen_meminfo(&self) -> String {
        let avail = self.sys.free_ram_kb + self.sys.cached_ram_kb;
        format!(
            "MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\nCached:         {:8} kB\nSlab:           {:8} kB\n",
            self.sys.total_ram_kb,
            self.sys.free_ram_kb,
            avail,
            self.sys.cached_ram_kb,
            self.sys.slab_ram_kb
        )
    }

    fn gen_uptime(&self) -> String {
        let up_sec = self.sys.uptime_ticks_ms / 1000;
        let up_rem = (self.sys.uptime_ticks_ms % 1000) / 10;
        let idle_sec = self.sys.idle_ticks_ms / 1000;
        let idle_rem = (self.sys.idle_ticks_ms % 1000) / 10;
        format!("{}.{:02} {}.{:02}\n", up_sec, up_rem, idle_sec, idle_rem)
    }

    fn gen_version(&self) -> String {
        String::from("CorOS version 1.0.0-x86_64-uefi (rustc #![no_std]) #1 SMP PREEMPT\n")
    }

    fn gen_mounts(&self) -> String {
        String::from(
            "/dev/nvme0n1p2 / corfs rw,relatime 0 0\n\
             /dev/nvme0n1p1 /boot/efi vfat rw,relatime 0 0\n\
             proc /proc proc rw,nosuid,nodev,noexec,noatime 0 0\n\
             sysfs /sys sysfs rw,nosuid,nodev,noexec,noatime 0 0\n\
             devtmpfs /dev devtmpfs rw,nosuid,noexec,noatime 0 0\n\
             tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n",
        )
    }

    fn gen_interrupts(&self) -> String {
        format!(
            "           CPU0       CPU1       CPU2       CPU3\n\
             32: {:10} {:10} {:10} {:10}   APIC-edge  lapic_timer\n\
             48: {:10}          0          0          0   PCI-MSI    nvme0q0\n\
             56:          0 {:10}          0          0   PCI-MSI    xhci_hcd\n",
            self.sys.timer_irqs,
            self.sys.timer_irqs,
            self.sys.timer_irqs,
            self.sys.timer_irqs,
            self.sys.nvme_irqs,
            self.sys.xhci_irqs
        )
    }

    fn gen_stat(&self) -> String {
        let running = self.tasks.iter().filter(|t| t.state == ProcTaskState::Running).count();
        format!(
            "cpu  12400 0 4320 {} 0 180 40 0 0 0\nctxt {}\nbtime {}\nprocesses {}\nprocs_running {}\n",
            self.sys.idle_ticks_ms / 10,
            self.sys.context_switches,
            self.sys.boot_epoch_sec,
            self.tasks.len(),
            running
        )
    }

    fn gen_task_status(&self, task: &ProcTaskRecord) -> String {
        format!(
            "Name:\t{}\nState:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nVmSize:\t{:8} kB\nVmRSS:\t{:8} kB\nThreads:\t{}\n",
            task.name,
            task.state.as_proc_str(),
            task.pid,
            task.ppid,
            task.uid, task.uid, task.uid, task.uid,
            task.gid, task.gid, task.gid, task.gid,
            task.vm_size_kb,
            task.vm_rss_kb,
            task.threads
        )
    }

    fn gen_task_maps(&self, task: &ProcTaskRecord) -> String {
        let mut out = String::new();
        for r in &task.regions {
            let p_str = core::str::from_utf8(&r.perms).unwrap_or("r--p");
            out.push_str(&format!(
                "{:012x}-{:012x} {} {:08x} 08:02 {:<8} {}\n",
                r.start_va, r.end_va, p_str, r.file_offset, r.inode, r.pathname
            ));
        }
        out
    }
}

/// Self-test suite for `procfs_tree`.
pub fn verify_vfs_procfs_tree() -> u32 {
    let mut passed = 0u32;
    let procfs = ProcFsTree::with_defaults();

    if let Some(cpuinfo) = procfs.read_proc_node("/cpuinfo") {
        if cpuinfo.contains("processor\t: 3") && cpuinfo.contains("CorOS x86_64 Virtual SMP") {
            passed += 1;
        }
    }

    if let Some(meminfo) = procfs.read_proc_node("/meminfo") {
        if meminfo.contains("MemTotal:") && meminfo.contains("MemAvailable:") {
            passed += 1;
        }
    }

    if let Some(status1) = procfs.read_proc_node("/1/status") {
        if status1.contains("Name:\tcorinit") && status1.contains("VmRSS:\t    4096 kB") {
            passed += 1;
        }
    }

    if let Some(maps1) = procfs.read_proc_node("/1/maps") {
        if maps1.contains("/sbin/corinit") && maps1.contains("[stack]") {
            passed += 1;
        }
    }

    if procfs.read_proc_node("/9999/status").is_none() {
        passed += 1;
    }

    passed
}
