//! Windows NT Process Handle Table Subsystem
//!
//! Provides thread-safe translation from integer user handles (0x4, 0x8...)
//! to internal kernel objects, with access validation and handle inheritance.

use alloc::vec::Vec;
use super::object::{KernelObject, ObjectManager};
use crate::security::acl::AccessMask;

pub type Handle = u32;

pub const INVALID_HANDLE_VALUE: Handle = 0;

pub struct HandleEntry {
    pub object: KernelObject,
    pub granted_access: AccessMask,
    pub inherit: bool,
    pub protect_from_close: bool,
}

pub struct HandleTable {
    entries: Vec<Option<HandleEntry>>,
    free_list: Vec<usize>,
}

impl HandleTable {
    pub fn new() -> Self {
        // Slot 0 is always reserved (NULL / INVALID_HANDLE_VALUE)
        let mut entries = Vec::with_capacity(32);
        entries.push(None);

        Self {
            entries,
            free_list: Vec::new(),
        }
    }

    /// Creates a new handle pointing to a kernel object
    pub fn create_handle(&mut self, object: KernelObject, granted_access: AccessMask, inherit: bool) -> Handle {
        ObjectManager::reference_object(&object);
        {
            let mut guard = object.lock();
            guard.handle_count = guard.handle_count.saturating_add(1);
        }

        let entry = HandleEntry {
            object,
            granted_access,
            inherit,
            protect_from_close: false,
        };

        if let Some(recycled_idx) = self.free_list.pop() {
            self.entries[recycled_idx] = Some(entry);
            (recycled_idx * 4) as Handle
        } else {
            let idx = self.entries.len();
            self.entries.push(Some(entry));
            (idx * 4) as Handle
        }
    }

    /// Resolves an integer handle into the underlying KernelObject
    pub fn reference_handle(&self, handle: Handle, desired_access: AccessMask) -> Option<KernelObject> {
        let idx = (handle / 4) as usize;
        if idx == 0 || idx >= self.entries.len() {
            return None;
        }

        if let Some(ref entry) = self.entries[idx] {
            // Verify access rights
            if (entry.granted_access & desired_access) == desired_access {
                ObjectManager::reference_object(&entry.object);
                Some(entry.object.clone())
            } else {
                None // Access Denied
            }
        } else {
            None
        }
    }

    /// Closes and destroys an open handle
    pub fn close_handle(&mut self, handle: Handle) -> bool {
        let idx = (handle / 4) as usize;
        if idx == 0 || idx >= self.entries.len() {
            return false;
        }

        if let Some(entry) = self.entries[idx].take() {
            if entry.protect_from_close {
                // Restore protected handle
                self.entries[idx] = Some(entry);
                return false;
            }

            {
                let mut guard = entry.object.lock();
                guard.handle_count = guard.handle_count.saturating_sub(1);
            }
            ObjectManager::dereference_object(&entry.object);
            self.free_list.push(idx);
            true
        } else {
            false
        }
    }

    /// Duplicates the handle table for a child process (`sys_fork` / `NtCreateProcessEx`)
    pub fn duplicate_inheritable(&self) -> Self {
        let mut child_table = Self::new();
        for (i, entry_opt) in self.entries.iter().enumerate() {
            if i == 0 { continue; }
            if let Some(ref e) = entry_opt {
                if e.inherit {
                    child_table.create_handle(e.object.clone(), e.granted_access, true);
                }
            }
        }
        child_table
    }
}
