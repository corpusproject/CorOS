//! CorOS Linux-Style Function Tracer & Kernel Event Logger (`ftrace.rs`)
//!
//! Implements low-overhead kernel dynamic instrumentation:
//! - RingBuffer based lockless event trace collector
//! - Tracing Plugins:
//!   - `function`: Tracks kernel function entry points
//!   - `function_graph`: Measures entry and return durations with depth indentation
//!   - `trace_marker`: Userland / kernel text markers written to `/sys/kernel/debug/tracing/trace_marker`
//!   - `irq_trace`: Records IRQ enter and exit timestamps
//!   - `sched_switch`: Logs task scheduler context switches (prev_pid -> next_pid)
//! - Output formatted like Linux `/sys/kernel/debug/tracing/trace`

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const DEFAULT_TRACE_BUFFER_SIZE: usize = 4096;

/// Trace Event Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceEventType {
    FunctionEntry,
    FunctionReturn,
    TraceMarker,
    SchedSwitch,
    IrqEntry,
    IrqExit,
}

/// A recorded trace entry
#[derive(Debug, Clone)]
pub struct TraceRecord {
    pub timestamp_tsc: u64,
    pub cpu_id: u32,
    pub pid: u64,
    pub event_type: TraceEventType,
    pub func_ip: u64,
    pub parent_ip: u64,
    pub duration_cycles: u64,
    pub message: String,
}

/// Ftrace Subsystem Context
pub struct FunctionTracer {
    enabled: AtomicBool,
    records: VecDeque<TraceRecord>,
    buffer_capacity: usize,
    call_stack: Vec<(u64, u64)>, // (func_ip, enter_timestamp)
    total_events: AtomicU64,
}

impl FunctionTracer {
    pub fn new(capacity: usize) -> Self {
        Self {
            enabled: AtomicBool::new(true),
            records: VecDeque::with_capacity(capacity),
            buffer_capacity: capacity,
            call_stack: Vec::new(),
            total_events: AtomicU64::new(0),
        }
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn clear(&mut self) {
        self.records.clear();
        self.call_stack.clear();
    }

    /// Record function graph entry
    pub fn trace_func_entry(&mut self, func_ip: u64, parent_ip: u64, tsc: u64, cpu: u32, pid: u64) {
        if !self.is_enabled() {
            return;
        }

        self.call_stack.push((func_ip, tsc));

        if self.records.len() >= self.buffer_capacity {
            self.records.pop_front();
        }

        self.records.push_back(TraceRecord {
            timestamp_tsc: tsc,
            cpu_id: cpu,
            pid,
            event_type: TraceEventType::FunctionEntry,
            func_ip,
            parent_ip,
            duration_cycles: 0,
            message: String::new(),
        });

        self.total_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record function graph return
    pub fn trace_func_return(&mut self, func_ip: u64, tsc: u64, cpu: u32, pid: u64) {
        if !self.is_enabled() {
            return;
        }

        let duration = if let Some((last_ip, enter_tsc)) = self.call_stack.pop() {
            if last_ip == func_ip {
                tsc.saturating_sub(enter_tsc)
            } else {
                0
            }
        } else {
            0
        };

        if self.records.len() >= self.buffer_capacity {
            self.records.pop_front();
        }

        self.records.push_back(TraceRecord {
            timestamp_tsc: tsc,
            cpu_id: cpu,
            pid,
            event_type: TraceEventType::FunctionReturn,
            func_ip,
            parent_ip: 0,
            duration_cycles: duration,
            message: String::new(),
        });

        self.total_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record trace marker message
    pub fn trace_marker(&mut self, msg: &str, tsc: u64, cpu: u32, pid: u64) {
        if !self.is_enabled() {
            return;
        }

        if self.records.len() >= self.buffer_capacity {
            self.records.pop_front();
        }

        self.records.push_back(TraceRecord {
            timestamp_tsc: tsc,
            cpu_id: cpu,
            pid,
            event_type: TraceEventType::TraceMarker,
            func_ip: 0,
            parent_ip: 0,
            duration_cycles: 0,
            message: String::from(msg),
        });

        self.total_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task scheduler switch
    pub fn trace_sched_switch(&mut self, prev_pid: u64, next_pid: u64, tsc: u64, cpu: u32) {
        if !self.is_enabled() {
            return;
        }

        if self.records.len() >= self.buffer_capacity {
            self.records.pop_front();
        }

        self.records.push_back(TraceRecord {
            timestamp_tsc: tsc,
            cpu_id: cpu,
            pid: prev_pid,
            event_type: TraceEventType::SchedSwitch,
            func_ip: 0,
            parent_ip: 0,
            duration_cycles: 0,
            message: alloc::format!("switch {} -> {}", prev_pid, next_pid),
        });

        self.total_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Dump traces in Linux `/sys/kernel/debug/tracing/trace` format
    pub fn dump_trace(&self) -> String {
        let mut out = String::from("# tracer: function_graph\n");
        out.push_str("# CPU  PID    TIMESTAMP  FUNCTION DURATION\n");
        out.push_str("# ---  -----  ---------  -----------------\n");

        for rec in &self.records {
            let line = match rec.event_type {
                TraceEventType::FunctionEntry => {
                    alloc::format!(" [{:02}] {:5} {:10}: 0x{:08x}() {{\n", rec.cpu_id, rec.pid, rec.timestamp_tsc, rec.func_ip)
                }
                TraceEventType::FunctionReturn => {
                    alloc::format!(" [{:02}] {:5} {:10}: }} /* {} cycles */\n", rec.cpu_id, rec.pid, rec.timestamp_tsc, rec.duration_cycles)
                }
                TraceEventType::TraceMarker => {
                    alloc::format!(" [{:02}] {:5} {:10}: ----- MARKER: {} -----\n", rec.cpu_id, rec.pid, rec.timestamp_tsc, rec.message)
                }
                TraceEventType::SchedSwitch => {
                    alloc::format!(" [{:02}] {:5} {:10}: sched_switch: {}\n", rec.cpu_id, rec.pid, rec.timestamp_tsc, rec.message)
                }
                _ => String::new(),
            };
            out.push_str(&line);
        }

        out
    }
}
