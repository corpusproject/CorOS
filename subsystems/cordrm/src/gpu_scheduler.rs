//! DRM GPU Job Scheduler, Priority Queues, Ring Credits & Timeout Detection (TDR).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// GPU Job Scheduling Priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GpuPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Kernel = 3,
}

/// GPU Job packet queued for hardware submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuJob {
    pub job_id: u64,
    pub context_id: u32,
    pub priority: GpuPriority,
    pub credits_required: u32,
    pub submission_time_ms: u64,
}

/// DRM GPU Scheduler with ring credit management and TDR timeout detector.
pub struct DrmGpuScheduler {
    pub ring_capacity_credits: u32,
    pub ring_available_credits: u32,
    pub timeout_limit_ms: u64,
    pub pending_queue: VecDeque<GpuJob>,
    pub in_flight_jobs: Vec<GpuJob>,
}

impl DrmGpuScheduler {
    pub fn new(ring_capacity_credits: u32, timeout_limit_ms: u64) -> Self {
        Self {
            ring_capacity_credits,
            ring_available_credits: ring_capacity_credits,
            timeout_limit_ms,
            pending_queue: VecDeque::new(),
            in_flight_jobs: Vec::new(),
        }
    }

    pub fn submit_job(&mut self, job: GpuJob) {
        self.pending_queue.push_back(job);
    }

    /// Attempts to dispatch pending jobs to the hardware ring if sufficient credits exist.
    pub fn dispatch_pending(&mut self, current_time_ms: u64) -> usize {
        let mut dispatched = 0;
        while let Some(front) = self.pending_queue.front() {
            if front.credits_required <= self.ring_available_credits {
                let mut job = self.pending_queue.pop_front().unwrap();
                self.ring_available_credits -= job.credits_required;
                job.submission_time_ms = current_time_ms;
                self.in_flight_jobs.push(job);
                dispatched += 1;
            } else {
                break;
            }
        }
        dispatched
    }

    /// Retires a finished job and recovers ring credits.
    pub fn complete_job(&mut self, job_id: u64) -> bool {
        if let Some(pos) = self.in_flight_jobs.iter().position(|j| j.job_id == job_id) {
            let job = self.in_flight_jobs.remove(pos);
            self.ring_available_credits =
                (self.ring_available_credits + job.credits_required).min(self.ring_capacity_credits);
            true
        } else {
            false
        }
    }

    /// Checks whether any in-flight job has exceeded `timeout_limit_ms` (GPU hang).
    pub fn check_hang_timeout(&self, current_time_ms: u64) -> Option<u64> {
        for job in &self.in_flight_jobs {
            if current_time_ms.saturating_sub(job.submission_time_ms) > self.timeout_limit_ms {
                return Some(job.job_id);
            }
        }
        None
    }
}
