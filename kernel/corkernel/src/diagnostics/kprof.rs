//! Kernel Function Call Latency Profiler & Histogram for CorOS.
//! 100% in-house implementation supporting:
//! - High-precision TSC timestamp delta profiling
//! - 6-bucket logarithmic latency distribution histogram (<1us, <10us, <100us, <1ms, <10ms, >10ms)
//! - Kernel hot-spot function tracking (call counts, min/max/average duration)

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, Default)]
pub struct FunctionProfile {
    pub name: String,
    pub call_count: u64,
    pub total_cycles: u64,
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub buckets: [u64; 6], // <1us, <10us, <100us, <1ms, <10ms, >10ms
}

pub struct KernelProfiler {
    pub profiles: BTreeMap<String, FunctionProfile>,
    pub is_enabled: bool,
    pub tsc_freq_mhz: u64,
}

impl KernelProfiler {
    pub fn new(tsc_freq_mhz: u64) -> Self {
        Self {
            profiles: BTreeMap::new(),
            is_enabled: true,
            tsc_freq_mhz: if tsc_freq_mhz == 0 { 2000 } else { tsc_freq_mhz },
        }
    }

    /// Record a function execution interval.
    pub fn record_call(&mut self, func_name: &str, start_tsc: u64, end_tsc: u64) {
        if !self.is_enabled || end_tsc < start_tsc {
            return;
        }

        let delta = end_tsc - start_tsc;
        let entry = self.profiles.entry(String::from(func_name)).or_insert_with(|| FunctionProfile {
            name: String::from(func_name),
            call_count: 0,
            total_cycles: 0,
            min_cycles: u64::MAX,
            max_cycles: 0,
            buckets: [0; 6],
        });

        entry.call_count += 1;
        entry.total_cycles += delta;
        if delta < entry.min_cycles { entry.min_cycles = delta; }
        if delta > entry.max_cycles { entry.max_cycles = delta; }

        // Convert cycles to microseconds (delta / tsc_freq_mhz)
        let us = delta / self.tsc_freq_mhz;
        if us < 1 {
            entry.buckets[0] += 1;
        } else if us < 10 {
            entry.buckets[1] += 1;
        } else if us < 100 {
            entry.buckets[2] += 1;
        } else if us < 1000 {
            entry.buckets[3] += 1;
        } else if us < 10000 {
            entry.buckets[4] += 1;
        } else {
            entry.buckets[5] += 1;
        }
    }

    /// Format summary report of top profiling hotspots.
    pub fn format_report(&self) -> String {
        let mut report = String::from("=== COROS KERNEL PROFILER REPORT ===\n");
        report.push_str("Function                         Calls     Total(ms)   Avg(us)   Max(us)\n");
        report.push_str("--------------------------------------------------------------------\n");

        for (name, prof) in &self.profiles {
            let total_ms = (prof.total_cycles / (self.tsc_freq_mhz * 1000)) as f64;
            let avg_us = if prof.call_count > 0 {
                (prof.total_cycles / (prof.call_count * self.tsc_freq_mhz)) as f64
            } else {
                0.0
            };
            let max_us = (prof.max_cycles / self.tsc_freq_mhz) as f64;

            let line = format!(
                "{:<32} {:>8} {:>11.2} {:>9.2} {:>9.2}\n",
                name, prof.call_count, total_ms, avg_us, max_us
            );
            report.push_str(&line);
        }

        report
    }
}
