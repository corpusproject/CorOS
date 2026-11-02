//! Block I/O Elevators and Request Schedulers for CorOS Storage.
//! 100% in-house implementation modeled after the Linux block layer (`block/blk-core.c`).
//! Features request merging, Deadline Scheduler (starvation prevention),
//! and sector-sorted elevator dispatching.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoDirection {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct BlockRequest {
    pub id: u64,
    pub sector: u64,
    pub count: u16,
    pub direction: IoDirection,
    pub submit_time_ms: u64,
    pub deadline_ms: u64,
    pub data: Vec<u8>,
}

impl BlockRequest {
    pub fn new(id: u64, sector: u64, count: u16, direction: IoDirection, now_ms: u64) -> Self {
        // Reads are latency critical: 500ms deadline. Writes have 5000ms deadline.
        let timeout = if direction == IoDirection::Read { 500 } else { 5000 };
        Self {
            id,
            sector,
            count,
            direction,
            submit_time_ms: now_ms,
            deadline_ms: now_ms + timeout,
            data: Vec::new(),
        }
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.deadline_ms
    }

    pub fn end_sector(&self) -> u64 {
        self.sector + self.count as u64
    }
}

/// Linux-style Deadline I/O Scheduler
pub struct DeadlineScheduler {
    pub read_fifo: VecDeque<BlockRequest>,
    pub write_fifo: VecDeque<BlockRequest>,
    pub sorted_queue: Vec<BlockRequest>, // Sorted by starting sector
    pub writes_starved_limit: u32,
    pub writes_starved: u32,
}

impl DeadlineScheduler {
    pub const fn new() -> Self {
        Self {
            read_fifo: VecDeque::new(),
            write_fifo: VecDeque::new(),
            sorted_queue: Vec::new(),
            writes_starved_limit: 4, // Serve at least 1 write batch every 4 read batches
            writes_starved: 0,
        }
    }

    /// Attempt to merge an incoming request with existing queued requests.
    pub fn try_merge(&mut self, req: &mut BlockRequest) -> bool {
        // Back merge: req starts right where existing ends
        for existing in &mut self.sorted_queue {
            if existing.direction == req.direction && existing.end_sector() == req.sector {
                existing.count += req.count;
                existing.data.extend_from_slice(&req.data);
                return true;
            }
        }

        // Front merge: req ends right where existing starts
        for existing in &mut self.sorted_queue {
            if existing.direction == req.direction && req.end_sector() == existing.sector {
                existing.sector = req.sector;
                existing.count += req.count;
                let mut new_data = req.data.clone();
                new_data.extend_from_slice(&existing.data);
                existing.data = new_data;
                return true;
            }
        }

        false
    }

    /// Insert a new request into the scheduler.
    pub fn insert_request(&mut self, mut req: BlockRequest) {
        if self.try_merge(&mut req) {
            return;
        }

        // Add to respective FIFO
        match req.direction {
            IoDirection::Read => self.read_fifo.push_back(req.clone()),
            IoDirection::Write => self.write_fifo.push_back(req.clone()),
        }

        // Add to sector-sorted elevator list
        let pos = self.sorted_queue.binary_search_by_key(&req.sector, |r| r.sector).unwrap_or_else(|e| e);
        self.sorted_queue.insert(pos, req);
    }

    /// Dispatch the next request to hardware.
    pub fn dispatch_next(&mut self, now_ms: u64) -> Option<BlockRequest> {
        if self.sorted_queue.is_empty() {
            return None;
        }

        // 1. Check if any Read has expired its deadline
        if let Some(front) = self.read_fifo.front() {
            if front.is_expired(now_ms) {
                let req = self.read_fifo.pop_front().unwrap();
                self.remove_from_sorted(req.id);
                return Some(req);
            }
        }

        // 2. Check if any Write has expired its deadline
        if let Some(front) = self.write_fifo.front() {
            if front.is_expired(now_ms) {
                let req = self.write_fifo.pop_front().unwrap();
                self.remove_from_sorted(req.id);
                return Some(req);
            }
        }

        // 3. Prioritize Reads unless Writes are starved
        if !self.read_fifo.is_empty() && self.writes_starved < self.writes_starved_limit {
            self.writes_starved += 1;
            let req = self.read_fifo.pop_front().unwrap();
            self.remove_from_sorted(req.id);
            return Some(req);
        }

        // 4. Dispatch next Write
        if !self.write_fifo.is_empty() {
            self.writes_starved = 0;
            let req = self.write_fifo.pop_front().unwrap();
            self.remove_from_sorted(req.id);
            return Some(req);
        }

        // 5. Fallback: take next elevator sorted request
        let req = self.sorted_queue.remove(0);
        Some(req)
    }

    fn remove_from_sorted(&mut self, id: u64) {
        if let Some(pos) = self.sorted_queue.iter().position(|r| r.id == id) {
            self.sorted_queue.remove(pos);
        }
    }
}
