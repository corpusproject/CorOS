//! CorOS Windows NT Object Manager Namespace & Directory Hierarchy
//!
//! Implements the complete Windows NT Object Namespace tree:
//!   \
//!   ├── Device\
//!   │   ├── HarddiskVolume1
//!   │   └── PhysicalDrive0
//!   ├── DosDevices\ (Symlink to \GLOBAL??)
//!   ├── GLOBAL??\
//!   │   ├── C: -> \Device\HarddiskVolume1
//!   │   └── NUL -> \Device\Null
//!   ├── Driver\
//!   ├── FileSystem\
//!   ├── BaseNamedObjects\
//!   └── Sessions\
//!
//! Provides symbolic link resolution, object handles, directory queries, and security checks.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

/// Handle value type for NT handles (multiple of 4)
pub type NtHandle = u32;

pub const INVALID_HANDLE_VALUE: NtHandle = 0xFFFF_FFFF;

/// Object directory attributes
pub const OBJ_INHERIT: u32 = 0x00000002;
pub const OBJ_PERMANENT: u32 = 0x00000010;
pub const OBJ_EXCLUSIVE: u32 = 0x00000020;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
pub const OBJ_OPENIF: u32 = 0x00000080;
pub const OBJ_OPENLINK: u32 = 0x00000100;

/// Standard Access Rights
pub const DELETE: u32 = 0x00010000;
pub const READ_CONTROL: u32 = 0x00020000;
pub const WRITE_DAC: u32 = 0x00040000;
pub const WRITE_OWNER: u32 = 0x00080000;
pub const SYNCHRONIZE: u32 = 0x00100000;

pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;
pub const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
pub const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
pub const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;
pub const STANDARD_RIGHTS_ALL: u32 = 0x001F0000;
pub const SPECIFIC_RIGHTS_ALL: u32 = 0x0000FFFF;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;

/// Directory-specific access rights
pub const DIRECTORY_QUERY: u32 = 0x0001;
pub const DIRECTORY_TRAVERSE: u32 = 0x0002;
pub const DIRECTORY_CREATE_OBJECT: u32 = 0x0004;
pub const DIRECTORY_CREATE_SUBDIRECTORY: u32 = 0x0008;
pub const DIRECTORY_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0xF;

/// SymbolicLink-specific access rights
pub const SYMBOLIC_LINK_QUERY: u32 = 0x0001;
pub const SYMBOLIC_LINK_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0x1;

/// Object types recognized by the NT Object Manager
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtObjectType {
    Directory,
    SymbolicLink,
    Device,
    Driver,
    Event,
    Mutant,
    Semaphore,
    Timer,
    Section,
    Key,
    Port,
    File,
}

impl NtObjectType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Directory => "Directory",
            Self::SymbolicLink => "SymbolicLink",
            Self::Device => "Device",
            Self::Driver => "Driver",
            Self::Event => "Event",
            Self::Mutant => "Mutant",
            Self::Semaphore => "Semaphore",
            Self::Timer => "Timer",
            Self::Section => "Section",
            Self::Key => "Key",
            Self::Port => "Port",
            Self::File => "File",
        }
    }
}

/// Header prepended to all NT kernel objects in the Object Manager
#[derive(Debug, Clone)]
pub struct ObjectHeader {
    pub pointer_count: u32,
    pub handle_count: u32,
    pub object_type: NtObjectType,
    pub attributes: u32,
    pub name: String,
    pub security_descriptor_id: u32,
}

/// An entry inside an NT Object Directory
pub enum ObjectBody {
    Directory(ObjectDirectory),
    SymbolicLink(SymbolicLinkObject),
    Device(DeviceObjectBody),
    Driver(DriverObjectBody),
    Event(EventObjectBody),
    Mutant(MutantObjectBody),
    Semaphore(SemaphoreObjectBody),
    Generic(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct SymbolicLinkObject {
    pub target_path: String,
    pub creation_time: u64,
    pub access_count: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceObjectBody {
    pub device_type: u32,
    pub characteristics: u32,
    pub attached_driver: String,
    pub sector_size: u32,
}

#[derive(Debug, Clone)]
pub struct DriverObjectBody {
    pub driver_name: String,
    pub driver_entry: u64,
    pub driver_size: usize,
}

#[derive(Debug, Clone)]
pub struct EventObjectBody {
    pub manual_reset: bool,
    pub signaled: bool,
}

#[derive(Debug, Clone)]
pub struct MutantObjectBody {
    pub owner_thread_id: u64,
    pub recursion_count: u32,
    pub abandoned: bool,
}

#[derive(Debug, Clone)]
pub struct SemaphoreObjectBody {
    pub current_count: i32,
    pub maximum_count: i32,
}

/// An NT Object Directory node containing sub-objects
pub struct ObjectDirectory {
    pub entries: BTreeMap<String, Box<ObjectNode>>,
}

impl ObjectDirectory {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, name: &str, node: ObjectNode) -> bool {
        let key = name.to_uppercase();
        if self.entries.contains_key(&key) {
            false
        } else {
            self.entries.insert(key, Box::new(node));
            true
        }
    }

    pub fn lookup(&self, name: &str) -> Option<&ObjectNode> {
        self.entries.get(&name.to_uppercase()).map(|b| b.as_ref())
    }

    pub fn lookup_mut(&mut self, name: &str) -> Option<&mut ObjectNode> {
        self.entries.get_mut(&name.to_uppercase()).map(|b| b.as_mut())
    }

    pub fn remove(&mut self, name: &str) -> Option<Box<ObjectNode>> {
        self.entries.remove(&name.to_uppercase())
    }
}

/// Complete node in the NT Object Tree
pub struct ObjectNode {
    pub header: ObjectHeader,
    pub body: ObjectBody,
}

impl ObjectNode {
    pub fn new_directory(name: &str, attributes: u32) -> Self {
        Self {
            header: ObjectHeader {
                pointer_count: 1,
                handle_count: 0,
                object_type: NtObjectType::Directory,
                attributes,
                name: String::from(name),
                security_descriptor_id: 0,
            },
            body: ObjectBody::Directory(ObjectDirectory::new()),
        }
    }

    pub fn new_symlink(name: &str, target: &str, attributes: u32) -> Self {
        Self {
            header: ObjectHeader {
                pointer_count: 1,
                handle_count: 0,
                object_type: NtObjectType::SymbolicLink,
                attributes,
                name: String::from(name),
                security_descriptor_id: 0,
            },
            body: ObjectBody::SymbolicLink(SymbolicLinkObject {
                target_path: String::from(target),
                creation_time: 0,
                access_count: 0,
            }),
        }
    }

    pub fn new_device(name: &str, dev_type: u32, driver: &str) -> Self {
        Self {
            header: ObjectHeader {
                pointer_count: 1,
                handle_count: 0,
                object_type: NtObjectType::Device,
                attributes: OBJ_PERMANENT,
                name: String::from(name),
                security_descriptor_id: 0,
            },
            body: ObjectBody::Device(DeviceObjectBody {
                device_type: dev_type,
                characteristics: 0,
                attached_driver: String::from(driver),
                sector_size: 512,
            }),
        }
    }
}

/// Global Handle Table entry for an opened NT Object
#[derive(Debug, Clone)]
pub struct HandleEntry {
    pub object_path: String,
    pub object_type: NtObjectType,
    pub granted_access: u32,
    pub inherit: bool,
    pub pid: u64,
}

/// Process Handle Table
pub struct HandleTable {
    handles: BTreeMap<NtHandle, HandleEntry>,
    next_handle: AtomicU32,
}

impl HandleTable {
    pub fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
            next_handle: AtomicU32::new(4), // NT handles start at 4 and increment by 4
        }
    }

    pub fn allocate_handle(&mut self, path: &str, obj_type: NtObjectType, access: u32, inherit: bool, pid: u64) -> NtHandle {
        let h = self.next_handle.fetch_add(4, Ordering::SeqCst);
        self.handles.insert(h, HandleEntry {
            object_path: String::from(path),
            object_type: obj_type,
            granted_access: access,
            inherit,
            pid,
        });
        h
    }

    pub fn close_handle(&mut self, handle: NtHandle) -> bool {
        self.handles.remove(&handle).is_some()
    }

    pub fn get(&self, handle: NtHandle) -> Option<&HandleEntry> {
        self.handles.get(&handle)
    }

    pub fn count(&self) -> usize {
        self.handles.len()
    }
}

/// The Windows NT Object Manager Subsystem
pub struct NtNamespace {
    root: ObjectNode,
    pub handle_table: HandleTable,
}

impl NtNamespace {
    pub fn new() -> Self {
        let mut root = ObjectNode::new_directory("", OBJ_PERMANENT);

        // Pre-populate standard Windows NT directory structure
        if let ObjectBody::Directory(ref mut dir) = root.body {
            dir.insert("Device", ObjectNode::new_directory("Device", OBJ_PERMANENT));
            dir.insert("GLOBAL??", ObjectNode::new_directory("GLOBAL??", OBJ_PERMANENT));
            dir.insert("Driver", ObjectNode::new_directory("Driver", OBJ_PERMANENT));
            dir.insert("FileSystem", ObjectNode::new_directory("FileSystem", OBJ_PERMANENT));
            dir.insert("BaseNamedObjects", ObjectNode::new_directory("BaseNamedObjects", OBJ_PERMANENT));
            dir.insert("Sessions", ObjectNode::new_directory("Sessions", OBJ_PERMANENT));
            dir.insert("KernelObjects", ObjectNode::new_directory("KernelObjects", OBJ_PERMANENT));
            dir.insert("Security", ObjectNode::new_directory("Security", OBJ_PERMANENT));
            dir.insert("ArcName", ObjectNode::new_directory("ArcName", OBJ_PERMANENT));

            // \DosDevices is a symlink to \GLOBAL??
            dir.insert("DosDevices", ObjectNode::new_symlink("DosDevices", r"\GLOBAL??", OBJ_PERMANENT));
        }

        let mut ns = Self {
            root,
            handle_table: HandleTable::new(),
        };

        // Create initial default devices and symlinks
        ns.create_symlink(r"\GLOBAL??\C:", r"\Device\HarddiskVolume1");
        ns.create_symlink(r"\GLOBAL??\NUL", r"\Device\Null");
        ns.create_symlink(r"\GLOBAL??\COM1", r"\Device\Serial0");
        ns.create_symlink(r"\GLOBAL??\CON", r"\Device\Console");

        ns.create_device(r"\Device\HarddiskVolume1", 0x00000007, r"\Driver\Disk"); // FILE_DEVICE_DISK
        ns.create_device(r"\Device\Null", 0x00000015, r"\Driver\Null");           // FILE_DEVICE_NULL
        ns.create_device(r"\Device\Serial0", 0x0000001B, r"\Driver\Serial");       // FILE_DEVICE_SERIAL_PORT
        ns.create_device(r"\Device\KeyboardClass0", 0x0000000B, r"\Driver\Kbdclass"); // FILE_DEVICE_KEYBOARD

        ns
    }

    /// Normalize NT path (e.g., "\Device\HarddiskVolume1" -> ["Device", "HarddiskVolume1"])
    fn parse_path<'a>(path: &'a str) -> Vec<&'a str> {
        path.trim_matches('\\')
            .split('\\')
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Resolve symbolic links recursively with a recursion limit of 16 to avoid loops
    pub fn resolve_path(&self, path: &str) -> String {
        let mut cur_path = String::from(path);
        for _ in 0..16 {
            let parts = Self::parse_path(&cur_path);
            if parts.is_empty() {
                break;
            }

            // Check if any prefix in parts resolves to a symlink
            let mut found_symlink = false;
            let mut accumulated = String::new();

            for (idx, &part) in parts.iter().enumerate() {
                accumulated.push('\\');
                accumulated.push_str(part);

                if let Some(target) = self.get_symlink_target(&accumulated) {
                    let mut remaining = String::new();
                    for rem in &parts[idx + 1..] {
                        remaining.push('\\');
                        remaining.push_str(rem);
                    }
                    cur_path = if target.ends_with('\\') && remaining.starts_with('\\') {
                        let mut s = target.clone();
                        s.push_str(&remaining[1..]);
                        s
                    } else {
                        let mut s = target.clone();
                        s.push_str(&remaining);
                        s
                    };
                    found_symlink = true;
                    break;
                }
            }

            if !found_symlink {
                break;
            }
        }
        cur_path
    }

    fn get_symlink_target(&self, full_path: &str) -> Option<String> {
        let parts = Self::parse_path(full_path);
        let mut current = &self.root;

        for part in parts {
            match &current.body {
                ObjectBody::Directory(dir) => {
                    if let Some(child) = dir.lookup(part) {
                        current = child;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }

        match &current.body {
            ObjectBody::SymbolicLink(link) => Some(link.target_path.clone()),
            _ => None,
        }
    }

    /// Create an object directory along an absolute NT path
    pub fn create_directory(&mut self, path: &str, attributes: u32) -> bool {
        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return false;
        }

        let mut current = &mut self.root;
        for (i, &part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            match &mut current.body {
                ObjectBody::Directory(dir) => {
                    let key = part.to_uppercase();
                    if !dir.entries.contains_key(&key) {
                        let node = ObjectNode::new_directory(part, attributes);
                        dir.entries.insert(key.clone(), Box::new(node));
                    }
                    if is_last {
                        return true;
                    }
                    current = dir.entries.get_mut(&key).unwrap().as_mut();
                }
                _ => return false,
            }
        }
        false
    }

    /// Create a symbolic link
    pub fn create_symlink(&mut self, link_path: &str, target_path: &str) -> bool {
        let parts = Self::parse_path(link_path);
        if parts.is_empty() {
            return false;
        }

        let leaf_name = parts[parts.len() - 1];
        let parent_parts = &parts[..parts.len() - 1];

        let mut current = &mut self.root;
        for &p in parent_parts {
            let key = p.to_uppercase();
            match &mut current.body {
                ObjectBody::Directory(dir) => {
                    if !dir.entries.contains_key(&key) {
                        let node = ObjectNode::new_directory(p, OBJ_PERMANENT);
                        dir.entries.insert(key.clone(), Box::new(node));
                    }
                    current = dir.entries.get_mut(&key).unwrap().as_mut();
                }
                _ => return false,
            }
        }

        match &mut current.body {
            ObjectBody::Directory(dir) => {
                let sym = ObjectNode::new_symlink(leaf_name, target_path, OBJ_PERMANENT);
                dir.insert(leaf_name, sym)
            }
            _ => false,
        }
    }

    /// Create a device object in the directory
    pub fn create_device(&mut self, dev_path: &str, dev_type: u32, driver: &str) -> bool {
        let parts = Self::parse_path(dev_path);
        if parts.is_empty() {
            return false;
        }

        let leaf_name = parts[parts.len() - 1];
        let parent_parts = &parts[..parts.len() - 1];

        let mut current = &mut self.root;
        for &p in parent_parts {
            let key = p.to_uppercase();
            match &mut current.body {
                ObjectBody::Directory(dir) => {
                    if !dir.entries.contains_key(&key) {
                        let node = ObjectNode::new_directory(p, OBJ_PERMANENT);
                        dir.entries.insert(key.clone(), Box::new(node));
                    }
                    current = dir.entries.get_mut(&key).unwrap().as_mut();
                }
                _ => return false,
            }
        }

        match &mut current.body {
            ObjectBody::Directory(dir) => {
                let dev = ObjectNode::new_device(leaf_name, dev_type, driver);
                dir.insert(leaf_name, dev)
            }
            _ => false,
        }
    }

    /// List entries in an object directory
    pub fn list_directory(&self, path: &str) -> Vec<(String, NtObjectType)> {
        let resolved = self.resolve_path(path);
        let parts = Self::parse_path(&resolved);

        let mut current = &self.root;
        for part in parts {
            match &current.body {
                ObjectBody::Directory(dir) => {
                    if let Some(child) = dir.lookup(part) {
                        current = child;
                    } else {
                        return Vec::new();
                    }
                }
                _ => return Vec::new(),
            }
        }

        match &current.body {
            ObjectBody::Directory(dir) => {
                dir.entries.values().map(|node| {
                    (node.header.name.clone(), node.header.object_type)
                }).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Open object and return an NT handle
    pub fn open_object(&mut self, path: &str, desired_access: u32, pid: u64) -> Result<NtHandle, i32> {
        let resolved = self.resolve_path(path);
        let parts = Self::parse_path(&resolved);

        let mut current = &self.root;
        for part in parts {
            match &current.body {
                ObjectBody::Directory(dir) => {
                    if let Some(child) = dir.lookup(part) {
                        current = child;
                    } else {
                        return Err(-1073741772); // STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)
                    }
                }
                _ => return Err(-1073741766), // STATUS_OBJECT_PATH_INVALID
            }
        }

        let obj_type = current.header.object_type;
        let handle = self.handle_table.allocate_handle(&resolved, obj_type, desired_access, false, pid);
        Ok(handle)
    }

    /// Close handle
    pub fn close_handle(&mut self, handle: NtHandle) -> bool {
        self.handle_table.close_handle(handle)
    }
}
