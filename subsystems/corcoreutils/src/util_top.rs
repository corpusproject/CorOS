//! CorOS Userland Coreutil: `top`
//! SMP per-core CPU usage bar renderer, load average formatter, memory/swap summary header,
//! and CPU-sorted real-time task table generator.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug)]
pub struct CoreCpuTelemetry {
    pub core_id: u32,
    pub user_pct_tenths: u16,
    pub sys_pct_tenths: u16,
    pub irq_pct_tenths: u16,
}

impl CoreCpuTelemetry {
    pub const fn busy_tenths(self) -> u16 {
        let sum = self.user_pct_tenths + self.sys_pct_tenths + self.irq_pct_tenths;
        if sum > 1000 { 1000 } else { sum }
    }

    pub const fn idle_tenths(self) -> u16 {
        1000 - self.busy_tenths()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TopSystemSummary {
    pub uptime_seconds: u64,
    pub load_1m_hundredths: u32,
    pub load_5m_hundredths: u32,
    pub load_15m_hundredths: u32,
    pub mem_total_mib: u32,
    pub mem_free_mib: u32,
    pub mem_used_mib: u32,
    pub mem_buff_cache_mib: u32,
    pub swap_total_mib: u32,
    pub swap_used_mib: u32,
}

#[derive(Clone, Debug)]
pub struct TopTaskEntry {
    pub pid: u32,
    pub user: &'static str,
    pub priority: i8,
    pub nice: i8,
    pub virt_kib: u64,
    pub res_kib: u64,
    pub shr_kib: u64,
    pub state_char: char,
    pub cpu_tenths: u16,
    pub mem_tenths: u16,
    pub time_hundredths: u64,
    pub command: &'static str,
}

/// Renders an `htop`/`top` style ASCII utilization bar of width `bar_width` (e.g., `[||||||    42.5%]`).
pub fn render_core_usage_bar(core: CoreCpuTelemetry, bar_width: usize) -> String {
    let busy = core.busy_tenths() as usize;
    let filled = ((busy * bar_width) + 500) / 1000;
    let user_bars = ((core.user_pct_tenths as usize * bar_width) + 500) / 1000;
    let mut bar = String::new();
    bar.push_str(&format!("%%Cpu{:<2} [", core.core_id));
    for i in 0..bar_width {
        if i < user_bars {
            bar.push('|');
        } else if i < filled {
            bar.push('#');
        } else {
            bar.push(' ');
        }
    }
    let idle = core.idle_tenths();
    bar.push_str(&format!(
        "] {:>3}.{}% busy ({:>3}.{}% id)",
        busy / 10,
        busy % 10,
        idle / 10,
        idle % 10
    ));
    bar
}

/// Generates a full `top` snapshot report with load averages, task states, SMP core bars, memory header, and CPU-sorted tasks.
pub fn render_top_snapshot(
    summary: &TopSystemSummary,
    cores: &[CoreCpuTelemetry],
    tasks: &[TopTaskEntry],
) -> String {
    let mut out = String::new();
    let hours = summary.uptime_seconds / 3600;
    let mins = (summary.uptime_seconds % 3600) / 60;
    out.push_str(&format!(
        "top - up {:02}:{:02},  load average: {}.{:02}, {}.{:02}, {}.{:02}\n",
        hours,
        mins,
        summary.load_1m_hundredths / 100,
        summary.load_1m_hundredths % 100,
        summary.load_5m_hundredths / 100,
        summary.load_5m_hundredths % 100,
        summary.load_15m_hundredths / 100,
        summary.load_15m_hundredths % 100
    ));

    let total_tasks = tasks.len();
    let running = tasks.iter().filter(|t| t.state_char == 'R').count();
    let sleeping = tasks.iter().filter(|t| t.state_char == 'S' || t.state_char == 'D').count();
    let stopped = tasks.iter().filter(|t| t.state_char == 'T').count();
    let zombie = tasks.iter().filter(|t| t.state_char == 'Z').count();
    out.push_str(&format!(
        "Tasks: {:>3} total, {:>3} running, {:>3} sleeping, {:>3} stopped, {:>3} zombie\n",
        total_tasks, running, sleeping, stopped, zombie
    ));

    for core in cores {
        out.push_str(&render_core_usage_bar(*core, 20));
        out.push('\n');
    }

    let swap_free = summary.swap_total_mib.saturating_sub(summary.swap_used_mib);
    out.push_str(&format!(
        "MiB Mem : {:>6} total, {:>6} free, {:>6} used, {:>6} buff/cache\n",
        summary.mem_total_mib, summary.mem_free_mib, summary.mem_used_mib, summary.mem_buff_cache_mib
    ));
    out.push_str(&format!(
        "MiB Swap: {:>6} total, {:>6} free, {:>6} used\n\n",
        summary.swap_total_mib, swap_free, summary.swap_used_mib
    ));

    out.push_str("  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n");

    let mut sorted: Vec<&TopTaskEntry> = tasks.iter().collect();
    sorted.sort_by(|a, b| b.cpu_tenths.cmp(&a.cpu_tenths).then_with(|| a.pid.cmp(&b.pid)));

    for t in sorted {
        let mins_t = t.time_hundredths / 6000;
        let secs_t = (t.time_hundredths % 6000) / 100;
        let hund_t = t.time_hundredths % 100;
        out.push_str(&format!(
            "{:>5} {:<8} {:>3} {:>3} {:>7} {:>6} {:>6} {} {:>3}.{} {:>3}.{} {:>3}:{:02}.{:02} {}\n",
            t.pid,
            t.user,
            t.priority,
            t.nice,
            t.virt_kib,
            t.res_kib,
            t.shr_kib,
            t.state_char,
            t.cpu_tenths / 10,
            t.cpu_tenths % 10,
            t.mem_tenths / 10,
            t.mem_tenths % 10,
            mins_t,
            secs_t,
            hund_t,
            t.command
        ));
    }

    out
}

pub fn verify_util_top() -> u32 {
    let mut passed = 0u32;

    let c0 = CoreCpuTelemetry {
        core_id: 0,
        user_pct_tenths: 300,
        sys_pct_tenths: 200,
        irq_pct_tenths: 0,
    };
    let bar = render_core_usage_bar(c0, 10);
    if bar.contains("50.0% busy") && bar.contains("50.0% id") && bar.contains("[|||##     ]") {
        passed += 1;
    }

    let summary = TopSystemSummary {
        uptime_seconds: 3720,
        load_1m_hundredths: 42,
        load_5m_hundredths: 35,
        load_15m_hundredths: 18,
        mem_total_mib: 4096,
        mem_free_mib: 3200,
        mem_used_mib: 512,
        mem_buff_cache_mib: 384,
        swap_total_mib: 1024,
        swap_used_mib: 0,
    };

    let tasks = [
        TopTaskEntry {
            pid: 10,
            user: "root",
            priority: 20,
            nice: 0,
            virt_kib: 12000,
            res_kib: 3200,
            shr_kib: 1600,
            state_char: 'S',
            cpu_tenths: 15,
            mem_tenths: 4,
            time_hundredths: 425,
            command: "kworker/0:1",
        },
        TopTaskEntry {
            pid: 88,
            user: "coros",
            priority: 20,
            nice: -5,
            virt_kib: 98000,
            res_kib: 24000,
            shr_kib: 8000,
            state_char: 'R',
            cpu_tenths: 245,
            mem_tenths: 58,
            time_hundredths: 9850,
            command: "corwm-render",
        },
    ];

    let snap = render_top_snapshot(&summary, &[c0], &tasks);
    if snap.contains("load average: 0.42, 0.35, 0.18")
        && snap.contains("Tasks:   2 total,   1 running,   1 sleeping")
    {
        passed += 1;
    }

    // Verify PID 88 (24.5% CPU) is sorted before PID 10 (1.5% CPU)
    if let (Some(pos88), Some(pos10)) = (snap.find("corwm-render"), snap.find("kworker/0:1")) {
        if pos88 < pos10 {
            passed += 1;
        }
    }

    passed
}
