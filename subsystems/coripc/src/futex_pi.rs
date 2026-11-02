//! Priority-Inheritance Futex (`PiFutexState`, `PiWaiter`, `lock_pi`, `unlock_pi`,
//! transitive priority boosting of lock owners along waiter-to-owner chains, and
//! cycle/deadlock detection).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Bit in the user-space futex word indicating that one or more waiters are queued in the kernel.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
/// Bit in the user-space futex word indicating that the previous owner exited without unlocking.
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// Mask extracting the owner TID (`0..0x3FFF_FFFF`) from a PI futex word.
pub const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

/// Errors returned by Priority-Inheritance Futex operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PiFutexError {
    /// Task does not exist in the scheduler registry.
    TaskNotFound,
    /// Futex does not exist.
    FutexNotFound,
    /// Task attempted to `lock_pi` a futex it already owns, or a cycle was detected in the wait-for graph (`EDEADLK`).
    DeadlockDetected,
    /// Task attempted to `unlock_pi` a futex it does not own (`EPERM`).
    NotOwner,
}

/// Waiter entry queued on a `PiFutexState`, ordered by descending effective priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PiWaiter {
    pub tid: u32,
    pub priority: u32,
    pub enqueue_seq: u64,
}

/// Kernel state of a single Priority-Inheritance Futex (`FUTEX_LOCK_PI` / `FUTEX_UNLOCK_PI`).
#[derive(Clone, Debug)]
pub struct PiFutexState {
    pub uaddr: u64,
    /// User-space futex word (`owner_tid | FUTEX_WAITERS`).
    pub futex_word: u32,
    pub owner_tid: Option<u32>,
    /// Waiters sorted by descending `priority`, then ascending `enqueue_seq` (FIFO tie-break).
    pub waiters: Vec<PiWaiter>,
    next_seq: u64,
}

impl PiFutexState {
    pub fn new(uaddr: u64) -> Self {
        Self {
            uaddr,
            futex_word: 0,
            owner_tid: None,
            waiters: Vec::new(),
            next_seq: 1,
        }
    }

    pub fn highest_waiter_priority(&self) -> Option<u32> {
        self.waiters.first().map(|w| w.priority)
    }

    fn sync_futex_word(&mut self) {
        match self.owner_tid {
            None => {
                self.futex_word = 0;
            }
            Some(tid) => {
                let waiters_bit = if self.waiters.is_empty() {
                    0
                } else {
                    FUTEX_WAITERS
                };
                self.futex_word = (tid & FUTEX_TID_MASK) | waiters_bit;
            }
        }
    }

    fn insert_or_resort_waiter(&mut self, tid: u32, priority: u32) {
        if let Some(pos) = self.waiters.iter().position(|w| w.tid == tid) {
            let seq = self.waiters[pos].enqueue_seq;
            self.waiters.remove(pos);
            let ins = self
                .waiters
                .iter()
                .position(|w| {
                    w.priority < priority || (w.priority == priority && w.enqueue_seq > seq)
                })
                .unwrap_or(self.waiters.len());
            self.waiters.insert(
                ins,
                PiWaiter {
                    tid,
                    priority,
                    enqueue_seq: seq,
                },
            );
        } else {
            let seq = self.next_seq;
            self.next_seq += 1;
            let ins = self
                .waiters
                .iter()
                .position(|w| w.priority < priority)
                .unwrap_or(self.waiters.len());
            self.waiters.insert(
                ins,
                PiWaiter {
                    tid,
                    priority,
                    enqueue_seq: seq,
                },
            );
        }
        self.sync_futex_word();
    }
}

/// Per-task PI scheduling state (`base_priority`, `effective_priority`, blocked futex, held futexes).
#[derive(Clone, Debug)]
pub struct PiTaskInfo {
    pub tid: u32,
    pub base_priority: u32,
    pub effective_priority: u32,
    /// `Some(uaddr)` if this task is currently blocked waiting to acquire `uaddr`.
    pub blocked_on_uaddr: Option<u64>,
    /// Futex addresses currently owned by this task.
    pub held_futexes: Vec<u64>,
}

/// Outcome of calling `lock_pi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockPiOutcome {
    /// Futex was uncontended and immediately acquired.
    AcquiredImmediately,
    /// Futex was contended; caller was queued and owner chain was transitively boosted.
    QueuedAndBoostedOwner { owner_tid: u32 },
}

/// Priority-Inheritance Futex Manager supporting transitive priority boosting and deadlock detection.
pub struct PiFutexManager {
    tasks: BTreeMap<u32, PiTaskInfo>,
    futexes: BTreeMap<u64, PiFutexState>,
}

impl Default for PiFutexManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PiFutexManager {
    pub fn new() -> Self {
        Self {
            tasks: BTreeMap::new(),
            futexes: BTreeMap::new(),
        }
    }

    pub fn register_task(&mut self, tid: u32, base_priority: u32) {
        self.tasks.insert(
            tid,
            PiTaskInfo {
                tid,
                base_priority,
                effective_priority: base_priority,
                blocked_on_uaddr: None,
                held_futexes: Vec::new(),
            },
        );
    }

    pub fn get_task(&self, tid: u32) -> Option<&PiTaskInfo> {
        self.tasks.get(&tid)
    }

    pub fn get_futex(&self, uaddr: u64) -> Option<&PiFutexState> {
        self.futexes.get(&uaddr)
    }

    /// Recompute `effective_priority` of `tid` as `max(base_priority, max_waiter_across_held_futexes)`.
    fn recompute_task_priority(&mut self, tid: u32) -> Option<u32> {
        let (base, held) = {
            let t = self.tasks.get(&tid)?;
            (t.base_priority, t.held_futexes.clone())
        };
        let mut max_prio = base;
        for uaddr in held {
            if let Some(f) = self.futexes.get(&uaddr) {
                if let Some(wp) = f.highest_waiter_priority() {
                    if wp > max_prio {
                        max_prio = wp;
                    }
                }
            }
        }
        if let Some(t) = self.tasks.get_mut(&tid) {
            t.effective_priority = max_prio;
        }
        Some(max_prio)
    }

    /// Attempt to acquire the PI futex at `uaddr` on behalf of `caller_tid` (`FUTEX_LOCK_PI`).
    /// Performs deadlock detection along the wait-for chain (`T -> F -> Owner -> F2 -> Owner2 ...`)
    /// and transitively boosts every owner along the chain if `caller_tid` has higher priority.
    pub fn lock_pi(&mut self, uaddr: u64, caller_tid: u32) -> Result<LockPiOutcome, PiFutexError> {
        let caller_prio = self
            .tasks
            .get(&caller_tid)
            .ok_or(PiFutexError::TaskNotFound)?
            .effective_priority;

        let futex = self
            .futexes
            .entry(uaddr)
            .or_insert_with(|| PiFutexState::new(uaddr));

        let current_owner = match futex.owner_tid {
            None => {
                futex.owner_tid = Some(caller_tid);
                futex.sync_futex_word();
                if let Some(t) = self.tasks.get_mut(&caller_tid) {
                    t.held_futexes.push(uaddr);
                }
                return Ok(LockPiOutcome::AcquiredImmediately);
            }
            Some(owner) => owner,
        };

        if current_owner == caller_tid {
            return Err(PiFutexError::DeadlockDetected);
        }

        // Walk the wait-for graph starting from `current_owner` to detect cycles before queuing.
        let mut cursor_tid = current_owner;
        while let Some(blocked_uaddr) = self
            .tasks
            .get(&cursor_tid)
            .and_then(|t| t.blocked_on_uaddr)
        {
            if let Some(next_owner) = self.futexes.get(&blocked_uaddr).and_then(|f| f.owner_tid) {
                if next_owner == caller_tid {
                    return Err(PiFutexError::DeadlockDetected);
                }
                cursor_tid = next_owner;
            } else {
                break;
            }
        }

        // Queue caller on `uaddr`.
        if let Some(t) = self.tasks.get_mut(&caller_tid) {
            t.blocked_on_uaddr = Some(uaddr);
        }
        if let Some(f) = self.futexes.get_mut(&uaddr) {
            f.insert_or_resort_waiter(caller_tid, caller_prio);
        }

        // Transitively propagate priority boost up the owner chain.
        let mut chain_owner = current_owner;
        loop {
            let new_eff = match self.recompute_task_priority(chain_owner) {
                Some(p) => p,
                None => break,
            };
            let next_uaddr = match self
                .tasks
                .get(&chain_owner)
                .and_then(|t| t.blocked_on_uaddr)
            {
                Some(u) => u,
                None => break,
            };
            if let Some(f) = self.futexes.get_mut(&next_uaddr) {
                f.insert_or_resort_waiter(chain_owner, new_eff);
                match f.owner_tid {
                    Some(next_owner) => chain_owner = next_owner,
                    None => break,
                }
            } else {
                break;
            }
        }

        Ok(LockPiOutcome::QueuedAndBoostedOwner {
            owner_tid: current_owner,
        })
    }

    /// Release the PI futex at `uaddr` held by `caller_tid` (`FUTEX_UNLOCK_PI`).
    /// Transfers ownership directly to the highest-priority waiter (if any) and restores
    /// `caller_tid`'s effective priority to the maximum of its remaining held futexes or base priority.
    pub fn unlock_pi(&mut self, uaddr: u64, caller_tid: u32) -> Result<Option<u32>, PiFutexError> {
        let next_owner = {
            let futex = self
                .futexes
                .get_mut(&uaddr)
                .ok_or(PiFutexError::FutexNotFound)?;
            if futex.owner_tid != Some(caller_tid) {
                return Err(PiFutexError::NotOwner);
            }
            let woken = if futex.waiters.is_empty() {
                None
            } else {
                Some(futex.waiters.remove(0).tid)
            };
            futex.owner_tid = woken;
            futex.sync_futex_word();
            woken
        };

        if let Some(caller) = self.tasks.get_mut(&caller_tid) {
            caller.held_futexes.retain(|&u| u != uaddr);
        }
        self.recompute_task_priority(caller_tid);

        if let Some(woken_tid) = next_owner {
            if let Some(wt) = self.tasks.get_mut(&woken_tid) {
                wt.blocked_on_uaddr = None;
                wt.held_futexes.push(uaddr);
            }
            self.recompute_task_priority(woken_tid);
        }

        Ok(next_owner)
    }
}

/// Self-test verifying 3-task transitive priority inheritance (`Low` holds `L1`, `Med` holds `L2`
/// and blocks on `L1`, `High` blocks on `L2` -> both `Med` and `Low` boosted to `High`'s priority),
/// cycle deadlock detection (`EDEADLK`), and priority restoration on `unlock_pi`.
pub fn self_test() -> bool {
    let mut mgr = PiFutexManager::new();
    let tid_low = 10;
    let tid_med = 20;
    let tid_high = 30;

    mgr.register_task(tid_low, 10);
    mgr.register_task(tid_med, 50);
    mgr.register_task(tid_high, 95);

    let lock_a = 0x1000;
    let lock_b = 0x2000;

    // Low acquires lock_a; Med acquires lock_b.
    if mgr.lock_pi(lock_a, tid_low) != Ok(LockPiOutcome::AcquiredImmediately)
        || mgr.lock_pi(lock_b, tid_med) != Ok(LockPiOutcome::AcquiredImmediately)
    {
        return false;
    }

    // Med blocks on lock_a -> Low is boosted from 10 to 50.
    if mgr.lock_pi(lock_a, tid_med)
        != Ok(LockPiOutcome::QueuedAndBoostedOwner { owner_tid: tid_low })
    {
        return false;
    }
    if mgr.get_task(tid_low).map(|t| t.effective_priority) != Some(50) {
        return false;
    }

    // If Low now tries to lock lock_b (held by Med, which is waiting on Low), deadlock must be detected!
    if mgr.lock_pi(lock_b, tid_low) != Err(PiFutexError::DeadlockDetected) {
        return false;
    }

    // High (priority 95) blocks on lock_b (held by Med) -> transitively boosts Med AND Low to 95!
    if mgr.lock_pi(lock_b, tid_high)
        != Ok(LockPiOutcome::QueuedAndBoostedOwner { owner_tid: tid_med })
    {
        return false;
    }
    if mgr.get_task(tid_med).map(|t| t.effective_priority) != Some(95)
        || mgr.get_task(tid_low).map(|t| t.effective_priority) != Some(95)
    {
        return false;
    }

    // Low unlocks lock_a -> Low drops back to base priority 10, Med wakes and acquires lock_a (staying at 95 due to lock_b).
    if mgr.unlock_pi(lock_a, tid_low) != Ok(Some(tid_med)) {
        return false;
    }
    if mgr.get_task(tid_low).map(|t| t.effective_priority) != Some(10)
        || mgr.get_task(tid_med).map(|t| t.effective_priority) != Some(95)
    {
        return false;
    }

    // Med unlocks lock_b -> Med drops back to base priority 50, High wakes and acquires lock_b.
    if mgr.unlock_pi(lock_b, tid_med) != Ok(Some(tid_high)) {
        return false;
    }
    mgr.get_task(tid_med).map(|t| t.effective_priority) == Some(50)
}
