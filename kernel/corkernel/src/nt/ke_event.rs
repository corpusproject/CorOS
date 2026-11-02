//! CorOS Windows NT Kernel Synchronization Primitives (`ke_event.rs`)
//!
//! Implements core NT synchronization objects based on DISPATCHER_HEADER:
//! - Notification Event (ManualResetEvent) & Synchronization Event (AutoResetEvent)
//! - Semaphore (Counting semaphore with initial and maximum limit)
//! - Mutant / Mutex (Recursive ownership, thread ownership tracking, abandonment)
//! - Timer (Notification & Synchronization timers, absolute and relative due-times)
//! - Wait block queues and KeWaitForSingleObject / KeWaitForMultipleObjects logic

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

/// NT Object Dispatcher Header Types
pub const EVENT_NOTIFICATION: u8 = 0;
pub const EVENT_SYNCHRONIZATION: u8 = 1;
pub const MUTANT_OBJECT: u8 = 2;
pub const SEMAPHORE_OBJECT: u8 = 5;
pub const TIMER_NOTIFICATION: u8 = 8;
pub const TIMER_SYNCHRONIZATION: u8 = 9;

/// NT Wait Return Statuses
pub const STATUS_SUCCESS: i32 = 0x00000000;
pub const STATUS_TIMEOUT: i32 = 0x00000102;
pub const STATUS_ABANDONED_WAIT_0: i32 = 0x00000080;
pub const STATUS_MUTANT_NOT_OWNED: i32 = -1073741757; // 0xC0000043
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: i32 = -1073741769; // 0xC0000047

/// Common Dispatcher Header for all NT Kernel waitable objects
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DispatcherHeader {
    pub object_type: u8,
    pub absolute: u8,
    pub size: u8,
    pub inserted: u8,
    pub signal_state: i32,
    pub wait_list_count: u32,
}

impl DispatcherHeader {
    pub fn new(obj_type: u8, initial_state: i32) -> Self {
        Self {
            object_type: obj_type,
            absolute: 0,
            size: core::mem::size_of::<Self>() as u8,
            inserted: 0,
            signal_state: initial_state,
            wait_list_count: 0,
        }
    }
}

/// Wait Block representing a thread waiting on a dispatcher object
#[derive(Debug, Clone)]
pub struct WaitBlock {
    pub thread_id: u64,
    pub wait_key: u32,
    pub wait_type: u8, // 0 = WaitAny, 1 = WaitAll
}

/// Windows NT Event Object (`KEVENT`)
pub struct KeEvent {
    pub header: DispatcherHeader,
    pub wait_queue: VecDeque<WaitBlock>,
}

impl KeEvent {
    pub fn new(event_type: u8, initial_state: bool) -> Self {
        let signal = if initial_state { 1 } else { 0 };
        Self {
            header: DispatcherHeader::new(event_type, signal),
            wait_queue: VecDeque::new(),
        }
    }

    /// `KeSetEvent` - Sets the event to signaled state and wakes up waiters
    pub fn set_event(&mut self, increment: i32) -> i32 {
        let prev = self.header.signal_state;
        self.header.signal_state = 1;

        if self.header.object_type == EVENT_SYNCHRONIZATION {
            // Auto-reset event: wake only the first waiting thread and reset state
            if let Some(_waiter) = self.wait_queue.pop_front() {
                self.header.signal_state = 0;
            }
        } else {
            // Manual-reset event: wake all waiters, state stays signaled until reset
            self.wait_queue.clear();
        }

        let _ = increment;
        prev
    }

    /// `KeResetEvent` - Sets event to non-signaled state
    pub fn reset_event(&mut self) -> i32 {
        let prev = self.header.signal_state;
        self.header.signal_state = 0;
        prev
    }

    /// `KeClearEvent` - Clears signal state directly
    pub fn clear_event(&mut self) {
        self.header.signal_state = 0;
    }

    /// `KeReadStateEvent` - Reads current signal state
    pub fn read_state(&self) -> bool {
        self.header.signal_state != 0
    }

    /// Wait on event
    pub fn wait(&mut self, thread_id: u64) -> bool {
        if self.header.signal_state > 0 {
            if self.header.object_type == EVENT_SYNCHRONIZATION {
                self.header.signal_state = 0; // Auto reset
            }
            true
        } else {
            self.wait_queue.push_back(WaitBlock {
                thread_id,
                wait_key: 0,
                wait_type: 0,
            });
            false
        }
    }
}

/// Windows NT Semaphore Object (`KSEMAPHORE`)
pub struct KeSemaphore {
    pub header: DispatcherHeader,
    pub limit: i32,
    pub wait_queue: VecDeque<WaitBlock>,
}

impl KeSemaphore {
    pub fn new(initial_count: i32, maximum_count: i32) -> Self {
        Self {
            header: DispatcherHeader::new(SEMAPHORE_OBJECT, initial_count),
            limit: maximum_count,
            wait_queue: VecDeque::new(),
        }
    }

    /// `KeReleaseSemaphore` - Releases semaphore count
    pub fn release(&mut self, release_count: i32) -> Result<i32, i32> {
        let prev = self.header.signal_state;
        if prev + release_count > self.limit {
            return Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED);
        }

        self.header.signal_state += release_count;

        // Wake up eligible waiters
        while self.header.signal_state > 0 && !self.wait_queue.is_empty() {
            self.wait_queue.pop_front();
            self.header.signal_state -= 1;
        }

        Ok(prev)
    }

    /// Try acquire semaphore without blocking
    pub fn try_acquire(&mut self) -> bool {
        if self.header.signal_state > 0 {
            self.header.signal_state -= 1;
            true
        } else {
            false
        }
    }

    pub fn wait(&mut self, thread_id: u64) -> bool {
        if self.header.signal_state > 0 {
            self.header.signal_state -= 1;
            true
        } else {
            self.wait_queue.push_back(WaitBlock {
                thread_id,
                wait_key: 0,
                wait_type: 0,
            });
            false
        }
    }
}

/// Windows NT Mutant / Mutex Object (`KMUTANT`)
pub struct KeMutant {
    pub header: DispatcherHeader,
    pub owner_thread: Option<u64>,
    pub recursion_count: u32,
    pub abandoned: bool,
    pub wait_queue: VecDeque<WaitBlock>,
}

impl KeMutant {
    pub fn new(initially_owned: bool, initial_owner_tid: u64) -> Self {
        if initially_owned {
            Self {
                header: DispatcherHeader::new(MUTANT_OBJECT, 0), // 0 = acquired
                owner_thread: Some(initial_owner_tid),
                recursion_count: 1,
                abandoned: false,
                wait_queue: VecDeque::new(),
            }
        } else {
            Self {
                header: DispatcherHeader::new(MUTANT_OBJECT, 1), // 1 = signaled (unowned)
                owner_thread: None,
                recursion_count: 0,
                abandoned: false,
                wait_queue: VecDeque::new(),
            }
        }
    }

    /// `KeReleaseMutant` - Release mutant by owner thread
    pub fn release(&mut self, thread_id: u64, abandon: bool) -> Result<i32, i32> {
        let prev = self.header.signal_state;
        if self.owner_thread != Some(thread_id) {
            return Err(STATUS_MUTANT_NOT_OWNED);
        }

        self.recursion_count -= 1;
        if self.recursion_count == 0 {
            self.owner_thread = None;
            if abandon {
                self.abandoned = true;
            }

            // Transfer ownership to next waiting thread if any
            if let Some(next_waiter) = self.wait_queue.pop_front() {
                self.owner_thread = Some(next_waiter.thread_id);
                self.recursion_count = 1;
                self.header.signal_state = 0;
            } else {
                self.header.signal_state = 1; // Unowned
            }
        }

        Ok(prev)
    }

    /// Acquire mutant
    pub fn acquire(&mut self, thread_id: u64) -> Result<bool, i32> {
        if self.owner_thread == Some(thread_id) {
            self.recursion_count += 1;
            return Ok(true);
        }

        if self.header.signal_state > 0 {
            self.header.signal_state = 0;
            self.owner_thread = Some(thread_id);
            self.recursion_count = 1;
            if self.abandoned {
                self.abandoned = false;
                return Err(STATUS_ABANDONED_WAIT_0);
            }
            Ok(true)
        } else {
            self.wait_queue.push_back(WaitBlock {
                thread_id,
                wait_key: 0,
                wait_type: 0,
            });
            Ok(false)
        }
    }
}

/// Windows NT Timer Object (`KTIMER`)
pub struct KeTimer {
    pub header: DispatcherHeader,
    pub due_time_ms: u64,
    pub period_ms: u32,
    pub dpc_routine: Option<u64>,
}

impl KeTimer {
    pub fn new(timer_type: u8) -> Self {
        Self {
            header: DispatcherHeader::new(timer_type, 0),
            due_time_ms: 0,
            period_ms: 0,
            dpc_routine: None,
        }
    }

    /// `KeSetTimerEx` - Arm timer
    pub fn set(&mut self, current_time_ms: u64, due_time_ms: u64, period_ms: u32, dpc: Option<u64>) {
        self.due_time_ms = current_time_ms + due_time_ms;
        self.period_ms = period_ms;
        self.dpc_routine = dpc;
        self.header.signal_state = 0;
        self.header.inserted = 1;
    }

    /// `KeCancelTimer`
    pub fn cancel(&mut self) -> bool {
        let was_inserted = self.header.inserted != 0;
        self.header.inserted = 0;
        self.due_time_ms = 0;
        was_inserted
    }

    /// Timer tick inspection
    pub fn tick(&mut self, now_ms: u64) -> bool {
        if self.header.inserted != 0 && now_ms >= self.due_time_ms {
            self.header.signal_state = 1;
            if self.period_ms > 0 {
                self.due_time_ms = now_ms + (self.period_ms as u64);
            } else {
                self.header.inserted = 0;
            }
            return true;
        }
        false
    }
}

/// Registry of kernel dispatcher objects
pub struct DispatcherRegistry {
    events: BTreeMap<u32, KeEvent>,
    semaphores: BTreeMap<u32, KeSemaphore>,
    mutants: BTreeMap<u32, KeMutant>,
    timers: BTreeMap<u32, KeTimer>,
    next_id: AtomicI32,
}

impl DispatcherRegistry {
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
            semaphores: BTreeMap::new(),
            mutants: BTreeMap::new(),
            timers: BTreeMap::new(),
            next_id: AtomicI32::new(1),
        }
    }

    pub fn create_event(&mut self, event_type: u8, initial_state: bool) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u32;
        self.events.insert(id, KeEvent::new(event_type, initial_state));
        id
    }

    pub fn create_semaphore(&mut self, initial: i32, limit: i32) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u32;
        self.semaphores.insert(id, KeSemaphore::new(initial, limit));
        id
    }

    pub fn create_mutant(&mut self, initially_owned: bool, tid: u64) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u32;
        self.mutants.insert(id, KeMutant::new(initially_owned, tid));
        id
    }

    pub fn create_timer(&mut self, timer_type: u8) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u32;
        self.timers.insert(id, KeTimer::new(timer_type));
        id
    }

    pub fn get_event_mut(&mut self, id: u32) -> Option<&mut KeEvent> {
        self.events.get_mut(&id)
    }

    pub fn get_semaphore_mut(&mut self, id: u32) -> Option<&mut KeSemaphore> {
        self.semaphores.get_mut(&id)
    }

    pub fn get_mutant_mut(&mut self, id: u32) -> Option<&mut KeMutant> {
        self.mutants.get_mut(&id)
    }

    pub fn get_timer_mut(&mut self, id: u32) -> Option<&mut KeTimer> {
        self.timers.get_mut(&id)
    }
}
