//! Explicit GPU synchronization: DMA Fences, syncobj timelines & multi-fence mergers.

use alloc::vec::Vec;

/// State of an individual DMA Fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceStatus {
    Pending,
    Signaled,
    Error(i32),
}

/// Synchronization Fence primitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmaFence {
    pub context_id: u64,
    pub seqno: u64,
    pub status: FenceStatus,
}

impl DmaFence {
    pub fn new(context_id: u64, seqno: u64) -> Self {
        Self {
            context_id,
            seqno,
            status: FenceStatus::Pending,
        }
    }

    #[inline]
    pub fn is_signaled(&self) -> bool {
        self.status == FenceStatus::Signaled
    }

    #[inline]
    pub fn signal(&mut self) {
        self.status = FenceStatus::Signaled;
    }
}

/// Monotonic Syncobj Timeline.
pub struct SyncTimeline {
    pub timeline_id: u64,
    pub current_point: u64,
    pub signaled_point: u64,
}

impl SyncTimeline {
    pub fn new(timeline_id: u64) -> Self {
        Self {
            timeline_id,
            current_point: 0,
            signaled_point: 0,
        }
    }

    /// Emits a new timeline fence point.
    pub fn create_fence_point(&mut self) -> DmaFence {
        self.current_point += 1;
        DmaFence::new(self.timeline_id, self.current_point)
    }

    /// Advances the timeline signaled point.
    pub fn signal_up_to(&mut self, point: u64) {
        if point > self.signaled_point {
            self.signaled_point = point.min(self.current_point);
        }
    }

    pub fn is_point_signaled(&self, point: u64) -> bool {
        point <= self.signaled_point
    }
}

/// Multi-fence merger array (e.g., waiting for multiple GPU pipelines).
pub struct FenceArrayMerger {
    pub fences: Vec<DmaFence>,
}

impl FenceArrayMerger {
    pub fn new() -> Self {
        Self { fences: Vec::new() }
    }

    pub fn add(&mut self, fence: DmaFence) {
        self.fences.push(fence);
    }

    pub fn all_signaled(&self) -> bool {
        self.fences.iter().all(|f| f.is_signaled())
    }
}
