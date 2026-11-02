//! Windows NT Process & Thread Structure Models (EPROCESS, ETHREAD, PEB, TEB) for CorOS.
//! 100% in-house implementation modeled after Windows Internals & ReactOS NT executive.

use alloc::string::String;
use alloc::vec::Vec;
use crate::nt::handle::HandleTable;
use crate::security::token::SecurityToken;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct ClientId {
    pub unique_process: u64,
    pub unique_thread: u64,
}

#[derive(Clone, Debug)]
pub struct Peb {
    pub image_base_address: u64,
    pub being_debugged: bool,
    pub number_of_processors: u32,
    pub session_id: u32,
    pub command_line: String,
    pub current_directory: String,
}

impl Default for Peb {
    fn default() -> Self {
        Self {
            image_base_address: 0x0000_7FF6_0000_0000,
            being_debugged: false,
            number_of_processors: 4,
            session_id: 1,
            command_line: String::from("coros.exe"),
            current_directory: String::from("C:\\Windows\\System32"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Teb {
    pub client_id: ClientId,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub current_locale: u32,
    pub tls_slots: [u64; 64],
}

impl Default for Teb {
    fn default() -> Self {
        Self {
            client_id: ClientId::default(),
            stack_base: 0,
            stack_limit: 0,
            current_locale: 1055, // Turkish LCID (or 1033 en-US)
            tls_slots: [0; 64],
        }
    }
}

pub struct Eprocess {
    pub pid: u64,
    pub parent_pid: u64,
    pub image_filename: [u8; 15],
    pub token: SecurityToken,
    pub peb: Peb,
    pub handle_table: HandleTable,
    pub active_threads: Vec<Ethread>,
    pub exit_status: i32,
    pub is_active: bool,
}

impl Eprocess {
    pub fn new(pid: u64, parent_pid: u64, name: &str, token: SecurityToken) -> Self {
        let mut image_filename = [0u8; 15];
        let bytes = name.as_bytes();
        let len = bytes.len().min(14);
        image_filename[..len].copy_from_slice(&bytes[..len]);

        Self {
            pid,
            parent_pid,
            image_filename,
            token,
            peb: Peb::default(),
            handle_table: HandleTable::new(),
            active_threads: Vec::new(),
            exit_status: 0,
            is_active: true,
        }
    }

    pub fn name(&self) -> String {
        let len = self.image_filename.iter().position(|&b| b == 0).unwrap_or(self.image_filename.len());
        String::from_utf8_lossy(&self.image_filename[..len]).into_owned()
    }
}

pub struct Ethread {
    pub tid: u64,
    pub owner_pid: u64,
    pub priority: i8, // 0..31 Windows priority levels
    pub teb: Teb,
    pub kernel_stack_base: u64,
    pub user_stack_base: u64,
    pub is_suspended: bool,
}

impl Ethread {
    pub fn new(tid: u64, owner_pid: u64, priority: i8) -> Self {
        let mut teb = Teb::default();
        teb.client_id = ClientId {
            unique_process: owner_pid,
            unique_thread: tid,
        };

        Self {
            tid,
            owner_pid,
            priority: priority.clamp(0, 31),
            teb,
            kernel_stack_base: 0,
            user_stack_base: 0,
            is_suspended: false,
        }
    }
}
