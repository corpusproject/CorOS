//! Linux Out-Of-Memory (`OomVictimSelector`) Badness Heuristic & Victim Selector.
//!
//! Implements Linux `oom_badness()` scoring based on Resident Set Size (RSS),
//! swap usage, page table memory footprint, and user-tunable `oom_score_adj`
//! (`[-1000..=1000]`), while enforcing immunity for `PID 1` (`init`), kernel
//! threads, and tasks with `OOM_SCORE_ADJ_MIN` (`-1000`).

use alloc::vec::Vec;

/// Minimum `oom_score_adj` value granting complete immunity from the OOM killer.
pub const OOM_SCORE_ADJ_MIN: i16 = -1000;

/// Maximum `oom_score_adj` value forcing maximum OOM badness penalty.
pub const OOM_SCORE_ADJ_MAX: i16 = 1000;

/// Memory footprint and OOM tuning descriptor for a single task (`task_struct`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskOomProfile {
    pub pid: u32,
    pub comm: &'static str,
    pub is_kernel_thread: bool,
    pub rss_pages: u64,
    pub swap_pages: u64,
    pub pgtables_bytes: u64,
    pub oom_score_adj: i16,
}

impl TaskOomProfile {
    /// Creates a new `TaskOomProfile` with `oom_score_adj` clamped to `[-1000..=1000]`.
    pub fn new(
        pid: u32,
        comm: &'static str,
        is_kernel_thread: bool,
        rss_pages: u64,
        swap_pages: u64,
        pgtables_bytes: u64,
        oom_score_adj: i16,
    ) -> Self {
        let clamped_adj = oom_score_adj.clamp(OOM_SCORE_ADJ_MIN, OOM_SCORE_ADJ_MAX);
        Self {
            pid,
            comm,
            is_kernel_thread,
            rss_pages,
            swap_pages,
            pgtables_bytes,
            oom_score_adj: clamped_adj,
        }
    }

    /// Returns `true` if this task is immune to OOM selection (`PID 1`, kernel thread,
    /// or `oom_score_adj == -1000`).
    pub const fn is_oom_immune(&self) -> bool {
        self.pid == 1 || self.is_kernel_thread || self.oom_score_adj == OOM_SCORE_ADJ_MIN
    }
}

/// Selected OOM victim report produced by `OomVictimSelector`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OomKillDecision {
    pub victim_pid: u32,
    pub victim_comm: &'static str,
    pub badness_points: u64,
    pub freed_pages_estimate: u64,
}

/// Linux-style `oom_badness()` evaluator and victim selector.
#[derive(Debug, Clone)]
pub struct OomVictimSelector {
    totalpages: u64,
    kill_count: u64,
}

impl OomVictimSelector {
    /// Creates an `OomVictimSelector` parameterized by `totalpages` (RAM + swap pages).
    pub const fn new(totalpages: u64) -> Self {
        Self {
            totalpages: if totalpages == 0 { 1 } else { totalpages },
            kill_count: 0,
        }
    }

    /// Computes the Linux `oom_badness()` score in the range `0..=1000` (where `0` means
    /// immune/never kill and `1000` is highest badness).
    pub const fn compute_badness(&self, task: &TaskOomProfile) -> u64 {
        if task.is_oom_immune() {
            return 0;
        }

        let pagetable_pages = task.pgtables_bytes / 4096;
        let used_pages = task
            .rss_pages
            .saturating_add(task.swap_pages)
            .saturating_add(pagetable_pages);

        // Base points scaled to [0..1000] relative to system totalpages
        let base_points = (used_pages.saturating_mul(1000)) / self.totalpages;
        let adjusted = (base_points as i64) + (task.oom_score_adj as i64);

        if adjusted <= 0 {
            1
        } else if adjusted > 1000 {
            1000
        } else {
            adjusted as u64
        }
    }

    /// Scans `tasks` and selects the highest-badness victim (breaking ties by larger
    /// memory footprint, then higher PID).
    pub fn select_victim(&mut self, tasks: &[TaskOomProfile]) -> Option<OomKillDecision> {
        let mut best: Option<(u64, u64, &TaskOomProfile)> = None;

        for task in tasks {
            let points = self.compute_badness(task);
            if points == 0 {
                continue;
            }
            let footprint = task.rss_pages + task.swap_pages + (task.pgtables_bytes / 4096);
            match best {
                None => best = Some((points, footprint, task)),
                Some((best_pts, best_fp, best_task)) => {
                    if points > best_pts
                        || (points == best_pts && footprint > best_fp)
                        || (points == best_pts && footprint == best_fp && task.pid > best_task.pid)
                    {
                        best = Some((points, footprint, task));
                    }
                }
            }
        }

        let (badness_points, _, victim) = best?;
        self.kill_count += 1;
        Some(OomKillDecision {
            victim_pid: victim.pid,
            victim_comm: victim.comm,
            badness_points,
            freed_pages_estimate: victim.rss_pages + (victim.pgtables_bytes / 4096),
        })
    }

    /// Returns total OOM kills executed by this selector.
    pub const fn kill_count(&self) -> u64 {
        self.kill_count
    }

    /// Ranks all non-immune tasks in descending order of OOM badness.
    pub fn rank_candidates(&self, tasks: &[TaskOomProfile]) -> Vec<(u32, u64)> {
        let mut ranked: Vec<(u32, u64)> = tasks
            .iter()
            .filter_map(|t| {
                let pts = self.compute_badness(t);
                if pts > 0 {
                    Some((t.pid, pts))
                } else {
                    None
                }
            })
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        ranked
    }
}
