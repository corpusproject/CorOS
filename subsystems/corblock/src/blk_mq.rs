//! `blk_mq.rs` — Multi-Queue Block Layer (`blk-mq`) implementation for CorOS.
//! Provides per-core software staging, hardware submission/completion rings,
//! lockless bitmap tag allocation, and hardware context management (`BlkMqHctx`).

use alloc::vec;
use alloc::vec::Vec;
use crate::bio::{Bio, BioStatus};

/// Block MQ error definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlkMqError {
    QueueFull,
    InvalidTag(u32),
    TagNotAllocated(u32),
    RequestNotActive(u32),
    InvalidHctxIndex(usize),
    RingEmpty,
    RingFull,
}

/// Lifecycle state of a block multi-queue request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Idle,
    Allocated,
    Queued,
    Dispatched,
    Completed,
}

/// A completion entry produced by hardware and placed into completion rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlkMqCompletion {
    pub tag: u32,
    pub status: BioStatus,
}

/// Hardware context tag allocator using a 64-bit bitmap.
#[derive(Debug, Clone)]
pub struct BlkMqTagSet {
    bitmap: Vec<u64>,
    depth: u32,
    busy_count: u32,
}

impl BlkMqTagSet {
    pub fn new(depth: u32) -> Self {
        let words = ((depth + 63) / 64) as usize;
        Self {
            bitmap: vec![0u64; words],
            depth,
            busy_count: 0,
        }
    }

    pub fn alloc_tag(&mut self) -> Option<u32> {
        if self.busy_count >= self.depth {
            return None;
        }

        for (word_idx, word) in self.bitmap.iter_mut().enumerate() {
            if *word != !0u64 {
                let trailing_zeros = (!*word).trailing_zeros() as u32;
                let tag = (word_idx as u32 * 64) + trailing_zeros;
                if tag < self.depth {
                    *word |= 1u64 << trailing_zeros;
                    self.busy_count += 1;
                    return Some(tag);
                }
            }
        }

        None
    }

    pub fn free_tag(&mut self, tag: u32) -> Result<(), BlkMqError> {
        if tag >= self.depth {
            return Err(BlkMqError::InvalidTag(tag));
        }

        let word_idx = (tag / 64) as usize;
        let bit = tag % 64;
        let mask = 1u64 << bit;

        if (self.bitmap[word_idx] & mask) == 0 {
            return Err(BlkMqError::TagNotAllocated(tag));
        }

        self.bitmap[word_idx] &= !mask;
        self.busy_count = self.busy_count.saturating_sub(1);
        Ok(())
    }

    pub fn is_allocated(&self, tag: u32) -> bool {
        if tag >= self.depth {
            return false;
        }
        let word_idx = (tag / 64) as usize;
        let bit = tag % 64;
        (self.bitmap[word_idx] & (1u64 << bit)) != 0
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn busy_count(&self) -> u32 {
        self.busy_count
    }
}

/// Generic bounded circular ring buffer for ring-based queue operations.
#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    buffer: Vec<Option<T>>,
    head: usize,
    tail: usize,
    count: usize,
    capacity: usize,
}

impl<T: Clone> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![None; capacity],
            head: 0,
            tail: 0,
            count: 0,
            capacity,
        }
    }

    pub fn push(&mut self, item: T) -> Result<(), BlkMqError> {
        if self.count >= self.capacity {
            return Err(BlkMqError::RingFull);
        }
        self.buffer[self.tail] = Some(item);
        self.tail = (self.tail + 1) % self.capacity;
        self.count += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Result<T, BlkMqError> {
        if self.count == 0 {
            return Err(BlkMqError::RingEmpty);
        }
        let item = self.buffer[self.head].take().ok_or(BlkMqError::RingEmpty)?;
        self.head = (self.head + 1) % self.capacity;
        self.count -= 1;
        Ok(item)
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn is_full(&self) -> bool {
        self.count >= self.capacity
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// In-flight block multi-queue request tracking metadata.
#[derive(Debug, Clone)]
pub struct BlkMqRequest {
    pub tag: u32,
    pub bio: Bio,
    pub state: RequestState,
    pub submit_time_ns: u64,
    pub deadline_ns: u64,
}

/// Hardware context statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlkMqStats {
    pub submitted: u64,
    pub dispatched: u64,
    pub completed: u64,
    pub timeouts: u64,
}

/// Hardware dispatch queue context (`BlkMqHctx`).
#[derive(Debug, Clone)]
pub struct BlkMqHctx {
    pub queue_id: u32,
    pub cpu_affinity: u32,
    tag_set: BlkMqTagSet,
    requests: Vec<Option<BlkMqRequest>>,
    submission_ring: RingBuffer<u32>,
    completion_ring: RingBuffer<BlkMqCompletion>,
    pub stats: BlkMqStats,
}

impl BlkMqHctx {
    pub fn new(queue_id: u32, cpu_affinity: u32, queue_depth: u32) -> Self {
        Self {
            queue_id,
            cpu_affinity,
            tag_set: BlkMqTagSet::new(queue_depth),
            requests: vec![None; queue_depth as usize],
            submission_ring: RingBuffer::new(queue_depth as usize),
            completion_ring: RingBuffer::new(queue_depth as usize),
            stats: BlkMqStats::default(),
        }
    }

    /// Submits a `Bio` into this hardware queue context, acquiring a tag and enqueueing in the submission ring.
    pub fn submit_bio(
        &mut self,
        bio: Bio,
        current_time_ns: u64,
        timeout_ns: u64,
    ) -> Result<u32, BlkMqError> {
        let tag = self.tag_set.alloc_tag().ok_or(BlkMqError::QueueFull)?;

        let req = BlkMqRequest {
            tag,
            bio,
            state: RequestState::Queued,
            submit_time_ns: current_time_ns,
            deadline_ns: current_time_ns.saturating_add(timeout_ns),
        };

        self.requests[tag as usize] = Some(req);
        if let Err(e) = self.submission_ring.push(tag) {
            let _ = self.tag_set.free_tag(tag);
            self.requests[tag as usize] = None;
            return Err(e);
        }

        self.stats.submitted += 1;
        Ok(tag)
    }

    /// Dispatches a batch of requests from the submission ring to hardware driver queues.
    pub fn dispatch_batch(&mut self, max_batch: usize) -> Vec<u32> {
        let mut dispatched = Vec::new();
        for _ in 0..max_batch {
            match self.submission_ring.pop() {
                Ok(tag) => {
                    if let Some(req) = &mut self.requests[tag as usize] {
                        req.state = RequestState::Dispatched;
                        dispatched.push(tag);
                        self.stats.dispatched += 1;
                    }
                }
                Err(_) => break,
            }
        }
        dispatched
    }

    /// Completes a request signaled by hardware interrupt or polling.
    pub fn complete_request(
        &mut self,
        tag: u32,
        status: BioStatus,
    ) -> Result<Bio, BlkMqError> {
        if tag >= self.tag_set.depth() {
            return Err(BlkMqError::InvalidTag(tag));
        }

        let mut req = self.requests[tag as usize]
            .take()
            .ok_or(BlkMqError::RequestNotActive(tag))?;

        req.state = RequestState::Completed;
        req.bio.complete(status);
        self.tag_set.free_tag(tag)?;

        let completion = BlkMqCompletion { tag, status };
        let _ = self.completion_ring.push(completion);

        self.stats.completed += 1;
        Ok(req.bio)
    }

    /// Drains pending completions from the completion ring.
    pub fn poll_completions(&mut self) -> Vec<BlkMqCompletion> {
        let mut results = Vec::new();
        while let Ok(c) = self.completion_ring.pop() {
            results.push(c);
        }
        results
    }

    /// Checks in-flight requests against the deadline and returns tags of timed-out requests.
    pub fn check_timeouts(&mut self, current_time_ns: u64) -> Vec<u32> {
        let mut timed_out = Vec::new();
        for req_opt in self.requests.iter_mut() {
            if let Some(req) = req_opt {
                if req.state == RequestState::Dispatched && current_time_ns > req.deadline_ns {
                    timed_out.push(req.tag);
                    self.stats.timeouts += 1;
                }
            }
        }
        timed_out
    }

    pub fn queue_depth(&self) -> u32 {
        self.tag_set.depth()
    }

    pub fn busy_count(&self) -> u32 {
        self.tag_set.busy_count()
    }

    pub fn get_request(&self, tag: u32) -> Option<&BlkMqRequest> {
        if (tag as usize) < self.requests.len() {
            self.requests[tag as usize].as_ref()
        } else {
            None
        }
    }
}

/// Multi-queue controller mapping CPUs to hardware contexts.
#[derive(Debug, Clone)]
pub struct BlkMqController {
    hctx_list: Vec<BlkMqHctx>,
}

impl BlkMqController {
    pub fn new(hctx_count: usize, queue_depth: u32) -> Self {
        let mut hctx_list = Vec::with_capacity(hctx_count);
        for i in 0..hctx_count {
            hctx_list.push(BlkMqHctx::new(i as u32, i as u32, queue_depth));
        }
        Self { hctx_list }
    }

    pub fn hctx_for_cpu(&mut self, cpu_id: u32) -> &mut BlkMqHctx {
        let idx = (cpu_id as usize) % self.hctx_list.len();
        &mut self.hctx_list[idx]
    }

    pub fn submit(
        &mut self,
        cpu_id: u32,
        bio: Bio,
        current_time_ns: u64,
        timeout_ns: u64,
    ) -> Result<(usize, u32), BlkMqError> {
        let idx = (cpu_id as usize) % self.hctx_list.len();
        let tag = self.hctx_list[idx].submit_bio(bio, current_time_ns, timeout_ns)?;
        Ok((idx, tag))
    }

    pub fn complete(
        &mut self,
        hctx_idx: usize,
        tag: u32,
        status: BioStatus,
    ) -> Result<Bio, BlkMqError> {
        if hctx_idx >= self.hctx_list.len() {
            return Err(BlkMqError::InvalidHctxIndex(hctx_idx));
        }
        self.hctx_list[hctx_idx].complete_request(tag, status)
    }

    pub fn total_stats(&self) -> BlkMqStats {
        let mut sum = BlkMqStats::default();
        for hctx in &self.hctx_list {
            sum.submitted += hctx.stats.submitted;
            sum.dispatched += hctx.stats.dispatched;
            sum.completed += hctx.stats.completed;
            sum.timeouts += hctx.stats.timeouts;
        }
        sum
    }

    pub fn hctx_count(&self) -> usize {
        self.hctx_list.len()
    }
}
