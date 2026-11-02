//! Windows NT Object Manager (Ob) Engine for CorOS
//!
//! Provides unified lifetime management, reference counting, security association,
//! and a single hierarchical namespace for all kernel resources.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::Spinlock;
use crate::security::acl::Acl;
use crate::security::sid::Sid;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Directory,
    SymbolicLink,
    Device,
    Driver,
    Process,
    Thread,
    Section,
    File,
    Event,
    Mutant,
    Semaphore,
    Timer,
    Key,
    Port,
}

impl ObjectType {
    pub fn name(&self) -> &'static str {
        match self {
            ObjectType::Directory => "Directory",
            ObjectType::SymbolicLink => "SymbolicLink",
            ObjectType::Device => "Device",
            ObjectType::Driver => "Driver",
            ObjectType::Process => "Process",
            ObjectType::Thread => "Thread",
            ObjectType::Section => "Section",
            ObjectType::File => "File",
            ObjectType::Event => "Event",
            ObjectType::Mutant => "Mutant",
            ObjectType::Semaphore => "Semaphore",
            ObjectType::Timer => "Timer",
            ObjectType::Key => "Key",
            ObjectType::Port => "Port",
        }
    }
}

pub struct SecurityDescriptor {
    pub owner: Sid,
    pub group: Sid,
    pub dacl: Option<Acl>,
}

pub struct ObjectHeader {
    pub pointer_count: usize,
    pub handle_count: usize,
    pub obj_type: ObjectType,
    pub name: Option<String>,
    pub security_descriptor: SecurityDescriptor,
    pub body: KernelObjectBody,
}

pub enum KernelObjectBody {
    Directory(Vec<Arc<Spinlock<ObjectHeader>>>),
    SymbolicLink(String),
    Event { signaled: bool, manual_reset: bool },
    Mutant { owner_tid: Option<usize>, count: usize },
    Semaphore { count: usize, max_count: usize },
    Device { name: String, major_version: u32 },
    Driver { entry_point: usize },
    Section { size_bytes: usize, page_count: usize },
    Raw(Vec<u8>),
}

pub type KernelObject = Arc<Spinlock<ObjectHeader>>;

pub struct ObjectManager {
    root_directory: KernelObject,
}

impl ObjectManager {
    pub fn new() -> Self {
        let root = Arc::new(Spinlock::new(ObjectHeader {
            pointer_count: 1,
            handle_count: 0,
            obj_type: ObjectType::Directory,
            name: Some(String::from("\\")),
            security_descriptor: SecurityDescriptor {
                owner: Sid::local_system(),
                group: Sid::administrators(),
                dacl: None,
            },
            body: KernelObjectBody::Directory(Vec::new()),
        }));

        let mut ob = Self { root_directory: root };
        ob.init_standard_directories();
        ob
    }

    fn init_standard_directories(&mut self) {
        let dirs = [
            "Device",
            "Driver",
            "BaseNamedObjects",
            "KernelObjects",
            "DosDevices",
            "FileSystem",
            "Security",
        ];

        for d in &dirs {
            let _ = self.create_directory(d);
        }
    }

    pub fn create_directory(&mut self, name: &str) -> KernelObject {
        let dir_obj = Arc::new(Spinlock::new(ObjectHeader {
            pointer_count: 1,
            handle_count: 0,
            obj_type: ObjectType::Directory,
            name: Some(String::from(name)),
            security_descriptor: SecurityDescriptor {
                owner: Sid::local_system(),
                group: Sid::administrators(),
                dacl: None,
            },
            body: KernelObjectBody::Directory(Vec::new()),
        }));

        let mut root_guard = self.root_directory.lock();
        if let KernelObjectBody::Directory(ref mut list) = root_guard.body {
            list.push(dir_obj.clone());
        }

        dir_obj
    }

    pub fn insert_object(&mut self, dir_path: &str, obj: KernelObject) -> bool {
        let mut root_guard = self.root_directory.lock();
        if let KernelObjectBody::Directory(ref mut list) = root_guard.body {
            for item in list.iter() {
                let mut guard = item.lock();
                if let Some(ref dname) = guard.name {
                    if dname == dir_path {
                        if let KernelObjectBody::Directory(ref mut sub_list) = guard.body {
                            sub_list.push(obj.clone());
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn reference_object(obj: &KernelObject) {
        let mut guard = obj.lock();
        guard.pointer_count = guard.pointer_count.saturating_add(1);
    }

    pub fn dereference_object(obj: &KernelObject) -> usize {
        let mut guard = obj.lock();
        guard.pointer_count = guard.pointer_count.saturating_sub(1);
        guard.pointer_count
    }
}
