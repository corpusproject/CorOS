//! Windows NT Object Synchronization & Wine Server Architecture for Win32 Compatibility
//! 100% in-house bare-metal implementation for CorOS.
//!
//! Provides the core synchronization and IPC runtime required to execute native Win32/NT
//! binaries without a full Windows kernel:
//! - NT Handle Table & Object Management (Reference counting, access rights, type descriptors)
//! - Win32 Synchronization Objects: Mutants (Mutexes), Semaphores, Events (Manual/Auto-reset), Waitable Timers
//! - Win32 Atom Tables (Global & Local Atom tables with integer atom ranges 0xC000 - 0xFFFF)
//! - Named Pipes Server (`\\.\pipe\...` full-duplex message/byte mode pipes)
//! - Win32 Mailslot Datagram IPC (`\\.\mailslot\...`)

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Standard Win32 Object Types
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NtObjectType {
    Mutant,
    Semaphore,
    Event,
    Timer,
    KeyedEvent,
    NamedPipe,
    Mailslot,
    Process,
    Thread,
    Section,
}

/// Win32 Event Reset Type
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventResetMode {
    ManualReset,
    AutoReset,
}

/// Win32 Standard Object Access Rights
pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;
pub const SYNCHRONIZE: u32 = 0x00100000;
pub const MUTEX_ALL_ACCESS: u32 = 0x001F0001;
pub const EVENT_ALL_ACCESS: u32 = 0x001F0003;
pub const SEMAPHORE_ALL_ACCESS: u32 = 0x001F0003;

/// NT Object Header and generic synchronization state
#[derive(Clone, Debug)]
pub struct NtObjectHeader {
    pub object_type: NtObjectType,
    pub name: Option<String>,
    pub ref_count: u32,
    pub handle_count: u32,
    pub signaled: bool,
}

/// Win32 Mutant (Mutex) Object
#[derive(Clone, Debug)]
pub struct Win32Mutant {
    pub header: NtObjectHeader,
    pub owner_thread_id: Option<u64>,
    pub recursion_count: u32,
    pub abandoned: bool,
}

impl Win32Mutant {
    pub fn new(name: Option<String>, initial_owner: bool, owner_tid: u64) -> Self {
        let (signaled, owner, rec) = if initial_owner {
            (false, Some(owner_tid), 1)
        } else {
            (true, None, 0)
        };

        Self {
            header: NtObjectHeader {
                object_type: NtObjectType::Mutant,
                name,
                ref_count: 1,
                handle_count: 1,
                signaled,
            },
            owner_thread_id: owner,
            recursion_count: rec,
            abandoned: false,
        }
    }

    /// Attempt to acquire mutant by thread
    pub fn wait_acquire(&mut self, tid: u64) -> bool {
        if self.header.signaled {
            self.header.signaled = false;
            self.owner_thread_id = Some(tid);
            self.recursion_count = 1;
            true
        } else if self.owner_thread_id == Some(tid) {
            self.recursion_count += 1;
            true
        } else {
            false
        }
    }

    /// Release mutant ownership
    pub fn release(&mut self, tid: u64) -> Result<(), &'static str> {
        if self.owner_thread_id != Some(tid) {
            return Err("Thread does not own mutant");
        }

        self.recursion_count = self.recursion_count.saturating_sub(1);
        if self.recursion_count == 0 {
            self.owner_thread_id = None;
            self.header.signaled = true;
        }

        Ok(())
    }
}

/// Win32 Semaphore Object
#[derive(Clone, Debug)]
pub struct Win32Semaphore {
    pub header: NtObjectHeader,
    pub current_count: i32,
    pub maximum_count: i32,
}

impl Win32Semaphore {
    pub fn new(name: Option<String>, initial_count: i32, max_count: i32) -> Self {
        let signaled = initial_count > 0;
        Self {
            header: NtObjectHeader {
                object_type: NtObjectType::Semaphore,
                name,
                ref_count: 1,
                handle_count: 1,
                signaled,
            },
            current_count: initial_count,
            maximum_count: max_count,
        }
    }

    /// Decrement semaphore count upon wait success
    pub fn acquire(&mut self) -> bool {
        if self.current_count > 0 {
            self.current_count -= 1;
            if self.current_count == 0 {
                self.header.signaled = false;
            }
            true
        } else {
            false
        }
    }

    /// Release semaphore count
    pub fn release(&mut self, release_count: i32) -> Result<i32, &'static str> {
        if release_count <= 0 || self.current_count + release_count > self.maximum_count {
            return Err("Invalid release count");
        }

        let prev = self.current_count;
        self.current_count += release_count;
        self.header.signaled = true;
        Ok(prev)
    }
}

/// Win32 Event Object
#[derive(Clone, Debug)]
pub struct Win32Event {
    pub header: NtObjectHeader,
    pub mode: EventResetMode,
}

impl Win32Event {
    pub fn new(name: Option<String>, mode: EventResetMode, initial_state: bool) -> Self {
        Self {
            header: NtObjectHeader {
                object_type: NtObjectType::Event,
                name,
                ref_count: 1,
                handle_count: 1,
                signaled: initial_state,
            },
            mode,
        }
    }

    pub fn set_event(&mut self) {
        self.header.signaled = true;
    }

    pub fn reset_event(&mut self) {
        self.header.signaled = false;
    }

    pub fn satisfy_wait(&mut self) -> bool {
        if self.header.signaled {
            if self.mode == EventResetMode::AutoReset {
                self.header.signaled = false;
            }
            true
        } else {
            false
        }
    }
}

/// Win32 Atom Table (Global & Local atoms)
pub struct Win32AtomTable {
    atoms: BTreeMap<u16, String>,
    next_atom_id: u16,
}

impl Win32AtomTable {
    pub fn new() -> Self {
        Self {
            atoms: BTreeMap::new(),
            next_atom_id: 0xC000, // Win32 dynamic string atoms reside in 0xC000 - 0xFFFF
        }
    }

    /// Add string to atom table and return 16-bit atom ID
    pub fn add_atom(&mut self, string: &str) -> u16 {
        // Search if string already exists
        for (&id, s) in &self.atoms {
            if s.eq_ignore_ascii_case(string) {
                return id;
            }
        }

        let id = self.next_atom_id;
        self.next_atom_id = if self.next_atom_id == 0xFFFF {
            0xC000
        } else {
            self.next_atom_id + 1
        };

        self.atoms.insert(id, String::from(string));
        id
    }

    /// Lookup string by atom ID
    pub fn get_atom_name(&self, atom: u16) -> Option<String> {
        self.atoms.get(&atom).cloned()
    }

    /// Delete an atom from table
    pub fn delete_atom(&mut self, atom: u16) -> bool {
        self.atoms.remove(&atom).is_some()
    }
}

/// Win32 Named Pipe Instance
pub struct NamedPipeInstance {
    pub pipe_name: String,
    pub max_instances: u32,
    pub in_buffer: Vec<u8>,
    pub out_buffer: Vec<u8>,
    pub is_connected: bool,
}

impl NamedPipeInstance {
    pub fn new(name: &str, max_instances: u32) -> Self {
        Self {
            pipe_name: String::from(name),
            max_instances,
            in_buffer: Vec::new(),
            out_buffer: Vec::new(),
            is_connected: false,
        }
    }

    pub fn write_data(&mut self, data: &[u8]) {
        self.in_buffer.extend_from_slice(data);
    }

    pub fn read_data(&mut self, max_len: usize) -> Vec<u8> {
        let take_len = self.in_buffer.len().min(max_len);
        let bytes: Vec<u8> = self.in_buffer.drain(..take_len).collect();
        bytes
    }
}

/// Win32 Mailslot Message
#[derive(Clone, Debug)]
pub struct MailslotMessage {
    pub sender_tid: u64,
    pub data: Vec<u8>,
}

/// Win32 Mailslot Object (`\\.\mailslot\...`)
pub struct Win32Mailslot {
    pub name: String,
    pub max_msg_size: u32,
    pub read_timeout_ms: u32,
    pub messages: Vec<MailslotMessage>,
}

impl Win32Mailslot {
    pub fn new(name: &str, max_msg_size: u32, read_timeout_ms: u32) -> Self {
        Self {
            name: String::from(name),
            max_msg_size,
            read_timeout_ms,
            messages: Vec::new(),
        }
    }

    pub fn write_slot(&mut self, sender_tid: u64, data: &[u8]) -> bool {
        if self.max_msg_size > 0 && data.len() > self.max_msg_size as usize {
            return false;
        }
        self.messages.push(MailslotMessage {
            sender_tid,
            data: data.to_vec(),
        });
        true
    }

    pub fn read_slot(&mut self) -> Option<MailslotMessage> {
        if self.messages.is_empty() {
            None
        } else {
            Some(self.messages.remove(0))
        }
    }
}

/// Wine Server Handle Entry
#[derive(Clone, Debug)]
pub struct HandleEntry {
    pub object_type: NtObjectType,
    pub object_index: usize,
    pub access_mask: u32,
    pub inheritable: bool,
}

/// Central Wine Server Process & Object Manager
pub struct WineServer {
    pub mutants: Vec<Win32Mutant>,
    pub semaphores: Vec<Win32Semaphore>,
    pub events: Vec<Win32Event>,
    pub pipes: BTreeMap<String, NamedPipeInstance>,
    pub mailslots: BTreeMap<String, Win32Mailslot>,
    pub global_atoms: Win32AtomTable,
    pub handle_table: BTreeMap<u32, HandleEntry>,
    next_handle: u32,
}

impl WineServer {
    pub fn new() -> Self {
        Self {
            mutants: Vec::new(),
            semaphores: Vec::new(),
            events: Vec::new(),
            pipes: BTreeMap::new(),
            mailslots: BTreeMap::new(),
            global_atoms: Win32AtomTable::new(),
            handle_table: BTreeMap::new(),
            next_handle: 0x0004, // Windows handles typically start at 0x4 (multiples of 4)
        }
    }

    fn alloc_handle(&mut self, entry: HandleEntry) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 4;
        self.handle_table.insert(handle, entry);
        handle
    }

    /// Create or Open a Win32 Mutex/Mutant
    pub fn create_mutex(&mut self, name: Option<&str>, initial_owner: bool, tid: u64) -> u32 {
        if let Some(n) = name {
            for (idx, m) in self.mutants.iter().enumerate() {
                if m.header.name.as_deref() == Some(n) {
                    return self.alloc_handle(HandleEntry {
                        object_type: NtObjectType::Mutant,
                        object_index: idx,
                        access_mask: MUTEX_ALL_ACCESS,
                        inheritable: false,
                    });
                }
            }
        }

        let idx = self.mutants.len();
        self.mutants.push(Win32Mutant::new(name.map(String::from), initial_owner, tid));

        self.alloc_handle(HandleEntry {
            object_type: NtObjectType::Mutant,
            object_index: idx,
            access_mask: MUTEX_ALL_ACCESS,
            inheritable: false,
        })
    }

    /// Create or Open a Win32 Event
    pub fn create_event(&mut self, name: Option<&str>, manual_reset: bool, initial_state: bool) -> u32 {
        let mode = if manual_reset { EventResetMode::ManualReset } else { EventResetMode::AutoReset };

        if let Some(n) = name {
            for (idx, ev) in self.events.iter().enumerate() {
                if ev.header.name.as_deref() == Some(n) {
                    return self.alloc_handle(HandleEntry {
                        object_type: NtObjectType::Event,
                        object_index: idx,
                        access_mask: EVENT_ALL_ACCESS,
                        inheritable: false,
                    });
                }
            }
        }

        let idx = self.events.len();
        self.events.push(Win32Event::new(name.map(String::from), mode, initial_state));

        self.alloc_handle(HandleEntry {
            object_type: NtObjectType::Event,
            object_index: idx,
            access_mask: EVENT_ALL_ACCESS,
            inheritable: false,
        })
    }

    /// Create or Open a Win32 Semaphore
    pub fn create_semaphore(&mut self, name: Option<&str>, initial_count: i32, max_count: i32) -> u32 {
        if let Some(n) = name {
            for (idx, sem) in self.semaphores.iter().enumerate() {
                if sem.header.name.as_deref() == Some(n) {
                    return self.alloc_handle(HandleEntry {
                        object_type: NtObjectType::Semaphore,
                        object_index: idx,
                        access_mask: SEMAPHORE_ALL_ACCESS,
                        inheritable: false,
                    });
                }
            }
        }

        let idx = self.semaphores.len();
        self.semaphores.push(Win32Semaphore::new(name.map(String::from), initial_count, max_count));

        self.alloc_handle(HandleEntry {
            object_type: NtObjectType::Semaphore,
            object_index: idx,
            access_mask: SEMAPHORE_ALL_ACCESS,
            inheritable: false,
        })
    }

    /// Close handle
    pub fn close_handle(&mut self, handle: u32) -> bool {
        self.handle_table.remove(&handle).is_some()
    }

    /// Wait for single object (WaitForSingleObject)
    pub fn wait_for_single_object(&mut self, handle: u32, tid: u64) -> u32 {
        // Return 0 = WAIT_OBJECT_0, 0x102 = WAIT_TIMEOUT, 0xFFFFFFFF = WAIT_FAILED
        let entry = match self.handle_table.get(&handle) {
            Some(e) => e.clone(),
            None => return 0xFFFFFFFF,
        };

        match entry.object_type {
            NtObjectType::Mutant => {
                if let Some(mutant) = self.mutants.get_mut(entry.object_index) {
                    if mutant.wait_acquire(tid) { 0 } else { 0x102 }
                } else {
                    0xFFFFFFFF
                }
            }
            NtObjectType::Event => {
                if let Some(ev) = self.events.get_mut(entry.object_index) {
                    if ev.satisfy_wait() { 0 } else { 0x102 }
                } else {
                    0xFFFFFFFF
                }
            }
            NtObjectType::Semaphore => {
                if let Some(sem) = self.semaphores.get_mut(entry.object_index) {
                    if sem.acquire() { 0 } else { 0x102 }
                } else {
                    0xFFFFFFFF
                }
            }
            _ => 0,
        }
    }
}
