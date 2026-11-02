//! `io_scheduler.rs` — I/O Schedulers for CorOS Block Layer.
//! Implements Deadline and BFQ (Budget Fair Queueing) schedulers with
//! latency guarantees, elevator seek optimization, and fair bandwidth distribution.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Standard I/O priority classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoPriorityClass {
    RealTime,
    BestEffort,
    Idle,
}

/// Schedulable I/O request representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedRequest {
    pub id: u64,
    pub sector: u64,
    pub nr_sectors: u32,
    pub is_write: bool,
    pub priority: IoPriorityClass,
    pub weight: u32,
    pub arrival_time_ns: u64,
    pub deadline_ns: u64,
    pub entity_id: u32,
}

impl SchedRequest {
    pub fn new(
        id: u64,
        sector: u64,
        nr_sectors: u32,
        is_write: bool,
        arrival_time_ns: u64,
    ) -> Self {
        // Default deadlines: 500ms for reads, 5000ms for writes
        let timeout_ns = if is_write {
            5_000_000_000u64
        } else {
            500_000_000u64
        };

        Self {
            id,
            sector,
            nr_sectors,
            is_write,
            priority: IoPriorityClass::BestEffort,
            weight: 100,
            arrival_time_ns,
            deadline_ns: arrival_time_ns.saturating_add(timeout_ns),
            entity_id: 0,
        }
    }

    pub fn with_priority(mut self, priority: IoPriorityClass, weight: u32) -> Self {
        self.priority = priority;
        self.weight = weight;
        self
    }

    pub fn with_entity(mut self, entity_id: u32) -> Self {
        self.entity_id = entity_id;
        self
    }
}

/// Common trait for all I/O schedulers in CorOS.
pub trait IoScheduler {
    fn name(&self) -> &'static str;
    fn insert_request(&mut self, req: SchedRequest);
    fn dispatch_next(&mut self, current_time_ns: u64) -> Option<SchedRequest>;
    fn has_pending(&self) -> bool;
    fn pending_count(&self) -> usize;
}

/// Deadline I/O Scheduler.
/// Maintains FIFO queues for read/write deadlines, plus sector-sorted elevator lists.
#[derive(Debug, Clone)]
pub struct DeadlineScheduler {
    read_fifo: VecDeque<SchedRequest>,
    write_fifo: VecDeque<SchedRequest>,
    read_sort: Vec<SchedRequest>,
    write_sort: Vec<SchedRequest>,
    last_sector: u64,
    writes_starved: u32,
    writes_starve_limit: u32,
}

impl DeadlineScheduler {
    pub fn new(writes_starve_limit: u32) -> Self {
        Self {
            read_fifo: VecDeque::new(),
            write_fifo: VecDeque::new(),
            read_sort: Vec::new(),
            write_sort: Vec::new(),
            last_sector: 0,
            writes_starved: 0,
            writes_starve_limit,
        }
    }

    fn insert_sorted(list: &mut Vec<SchedRequest>, req: SchedRequest) {
        let idx = list.partition_point(|item| item.sector < req.sector);
        list.insert(idx, req);
    }

    fn remove_by_id(list: &mut Vec<SchedRequest>, id: u64) -> Option<SchedRequest> {
        if let Some(pos) = list.iter().position(|r| r.id == id) {
            Some(list.remove(pos))
        } else {
            None
        }
    }

    fn find_next_sorted(list: &mut Vec<SchedRequest>, last_sector: u64) -> Option<SchedRequest> {
        if list.is_empty() {
            return None;
        }

        // Search for nearest request with sector >= last_sector
        let idx = list.partition_point(|r| r.sector < last_sector);
        if idx < list.len() {
            Some(list.remove(idx))
        } else {
            // Wrap around elevator sweep to the lowest sector
            Some(list.remove(0))
        }
    }
}

impl Default for DeadlineScheduler {
    fn default() -> Self {
        Self::new(4)
    }
}

impl IoScheduler for DeadlineScheduler {
    fn name(&self) -> &'static str {
        "deadline"
    }

    fn insert_request(&mut self, req: SchedRequest) {
        if req.is_write {
            self.write_fifo.push_back(req.clone());
            Self::insert_sorted(&mut self.write_sort, req);
        } else {
            self.read_fifo.push_back(req.clone());
            Self::insert_sorted(&mut self.read_sort, req);
        }
    }

    fn dispatch_next(&mut self, current_time_ns: u64) -> Option<SchedRequest> {
        // Step 1: Check if read FIFO deadline expired
        if let Some(front) = self.read_fifo.front() {
            if current_time_ns >= front.deadline_ns {
                let expired = self.read_fifo.pop_front()?;
                Self::remove_by_id(&mut self.read_sort, expired.id);
                self.last_sector = expired.sector + expired.nr_sectors as u64;
                self.writes_starved = self.writes_starved.saturating_add(1);
                return Some(expired);
            }
        }

        // Step 2: Check if write FIFO deadline expired
        if let Some(front) = self.write_fifo.front() {
            if current_time_ns >= front.deadline_ns {
                let expired = self.write_fifo.pop_front()?;
                Self::remove_by_id(&mut self.write_sort, expired.id);
                self.last_sector = expired.sector + expired.nr_sectors as u64;
                self.writes_starved = 0;
                return Some(expired);
            }
        }

        // Step 3: Handle writes starvation threshold
        if self.writes_starved >= self.writes_starve_limit && !self.write_sort.is_empty() {
            if let Some(req) = Self::find_next_sorted(&mut self.write_sort, self.last_sector) {
                if let Some(pos) = self.write_fifo.iter().position(|r| r.id == req.id) {
                    self.write_fifo.remove(pos);
                }
                self.last_sector = req.sector + req.nr_sectors as u64;
                self.writes_starved = 0;
                return Some(req);
            }
        }

        // Step 4: Normal elevator sweep: Prefer reads for interactive latency
        if !self.read_sort.is_empty() {
            if let Some(req) = Self::find_next_sorted(&mut self.read_sort, self.last_sector) {
                if let Some(pos) = self.read_fifo.iter().position(|r| r.id == req.id) {
                    self.read_fifo.remove(pos);
                }
                self.last_sector = req.sector + req.nr_sectors as u64;
                self.writes_starved = self.writes_starved.saturating_add(1);
                return Some(req);
            }
        }

        // Step 5: If no reads, dispatch elevator writes
        if !self.write_sort.is_empty() {
            if let Some(req) = Self::find_next_sorted(&mut self.write_sort, self.last_sector) {
                if let Some(pos) = self.write_fifo.iter().position(|r| r.id == req.id) {
                    self.write_fifo.remove(pos);
                }
                self.last_sector = req.sector + req.nr_sectors as u64;
                self.writes_starved = 0;
                return Some(req);
            }
        }

        None
    }

    fn has_pending(&self) -> bool {
        !self.read_sort.is_empty() || !self.write_sort.is_empty()
    }

    fn pending_count(&self) -> usize {
        self.read_sort.len() + self.write_sort.len()
    }
}

/// Budget Fair Queueing (BFQ) Entity Queue.
#[derive(Debug, Clone)]
pub struct BfqQueue {
    pub entity_id: u32,
    pub priority: IoPriorityClass,
    pub weight: u32,
    pub allocated_budget_sectors: u32,
    pub consumed_budget_sectors: u32,
    pub virtual_time: u64,
    pub requests: VecDeque<SchedRequest>,
}

impl BfqQueue {
    pub fn new(entity_id: u32, priority: IoPriorityClass, weight: u32) -> Self {
        let base_budget = match priority {
            IoPriorityClass::RealTime => 1024,
            IoPriorityClass::BestEffort => 256,
            IoPriorityClass::Idle => 64,
        };

        Self {
            entity_id,
            priority,
            weight: weight.max(1),
            allocated_budget_sectors: base_budget,
            consumed_budget_sectors: 0,
            virtual_time: 0,
            requests: VecDeque::new(),
        }
    }

    pub fn is_budget_exhausted(&self) -> bool {
        self.consumed_budget_sectors >= self.allocated_budget_sectors
    }

    pub fn reset_budget(&mut self) {
        self.consumed_budget_sectors = 0;
    }
}

/// Budget Fair Queueing (BFQ) Scheduler.
/// Divides bandwidth proportionally to entity weights while guaranteeing low latency.
#[derive(Debug, Clone)]
pub struct BfqScheduler {
    queues: Vec<BfqQueue>,
    active_queue_idx: Option<usize>,
    system_virtual_time: u64,
    default_weight: u32,
}

impl BfqScheduler {
    pub fn new(default_weight: u32) -> Self {
        Self {
            queues: Vec::new(),
            active_queue_idx: None,
            system_virtual_time: 0,
            default_weight: default_weight.max(1),
        }
    }

    fn get_or_create_queue(&mut self, entity_id: u32, priority: IoPriorityClass, weight: u32) -> usize {
        if let Some(idx) = self.queues.iter().position(|q| q.entity_id == entity_id) {
            return idx;
        }

        let mut queue = BfqQueue::new(entity_id, priority, weight.max(self.default_weight));
        queue.virtual_time = self.system_virtual_time;
        self.queues.push(queue);
        self.queues.len() - 1
    }

    fn select_next_active_queue(&mut self) -> Option<usize> {
        // Find queue with pending requests and minimum virtual time
        let mut best_idx = None;
        let mut min_vtime = u64::MAX;

        for (idx, q) in self.queues.iter().enumerate() {
            if !q.requests.is_empty() {
                // RealTime priorities receive priority boost over BestEffort/Idle
                let effective_vtime = if q.priority == IoPriorityClass::RealTime {
                    q.virtual_time / 4
                } else if q.priority == IoPriorityClass::Idle {
                    q.virtual_time.saturating_mul(4)
                } else {
                    q.virtual_time
                };

                if effective_vtime < min_vtime {
                    min_vtime = effective_vtime;
                    best_idx = Some(idx);
                }
            }
        }

        if let Some(idx) = best_idx {
            self.queues[idx].reset_budget();
            self.system_virtual_time = self.queues[idx].virtual_time;
        }

        best_idx
    }
}

impl Default for BfqScheduler {
    fn default() -> Self {
        Self::new(100)
    }
}

impl IoScheduler for BfqScheduler {
    fn name(&self) -> &'static str {
        "bfq"
    }

    fn insert_request(&mut self, req: SchedRequest) {
        let q_idx = self.get_or_create_queue(req.entity_id, req.priority, req.weight);
        self.queues[q_idx].requests.push_back(req);
    }

    fn dispatch_next(&mut self, _current_time_ns: u64) -> Option<SchedRequest> {
        // Step 1: Ensure we have an active queue
        let active_idx = match self.active_queue_idx {
            Some(idx) => {
                let q = &self.queues[idx];
                if q.requests.is_empty() || q.is_budget_exhausted() {
                    // Sched slice ended: advance virtual time
                    let consumed = q.consumed_budget_sectors as u64;
                    let weight = q.weight as u64;
                    let vtime_delta = (consumed * 1000) / weight;
                    self.queues[idx].virtual_time = self.queues[idx].virtual_time.saturating_add(vtime_delta);

                    self.select_next_active_queue()
                } else {
                    Some(idx)
                }
            }
            None => self.select_next_active_queue(),
        };

        self.active_queue_idx = active_idx;

        // Step 2: Dispatch from selected active queue
        if let Some(idx) = active_idx {
            let q = &mut self.queues[idx];
            if let Some(req) = q.requests.pop_front() {
                q.consumed_budget_sectors += req.nr_sectors;
                return Some(req);
            }
        }

        None
    }

    fn has_pending(&self) -> bool {
        self.queues.iter().any(|q| !q.requests.is_empty())
    }

    fn pending_count(&self) -> usize {
        self.queues.iter().map(|q| q.requests.len()).sum()
    }
}
