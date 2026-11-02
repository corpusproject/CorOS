//! Pure Native Windows NT Registry Hive Engine for CorOS.
//! 100% in-house implementation supporting:
//! - Standard Root Keys: HKLM, HKCU, HKCR, HKU, HKCC
//! - Windows Data Types: REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_EXPAND_SZ
//! - Hierarchical path walking (e.g. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control`)
//! - CRUD key/value operations, enumeration, and default Windows NT hives.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub const REG_NONE: u32                       = 0;
pub const REG_SZ: u32                         = 1;
pub const REG_EXPAND_SZ: u32                  = 2;
pub const REG_BINARY: u32                     = 3;
pub const REG_DWORD: u32                      = 4;
pub const REG_DWORD_BIG_ENDIAN: u32           = 5;
pub const REG_LINK: u32                       = 6;
pub const REG_MULTI_SZ: u32                   = 7;
pub const REG_RESOURCE_LIST: u32              = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32   = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32                      = 11;

#[derive(Clone, Debug)]
pub struct RegistryValue {
    pub name: String,
    pub val_type: u32,
    pub data: Vec<u8>,
}

impl RegistryValue {
    pub fn new_sz(name: &str, text: &str) -> Self {
        Self {
            name: String::from(name),
            val_type: REG_SZ,
            data: text.as_bytes().to_vec(),
        }
    }

    pub fn new_dword(name: &str, val: u32) -> Self {
        Self {
            name: String::from(name),
            val_type: REG_DWORD,
            data: val.to_le_bytes().to_vec(),
        }
    }

    pub fn new_qword(name: &str, val: u64) -> Self {
        Self {
            name: String::from(name),
            val_type: REG_QWORD,
            data: val.to_le_bytes().to_vec(),
        }
    }

    pub fn new_binary(name: &str, bin: &[u8]) -> Self {
        Self {
            name: String::from(name),
            val_type: REG_BINARY,
            data: bin.to_vec(),
        }
    }

    pub fn as_str(&self) -> Option<String> {
        if self.val_type == REG_SZ || self.val_type == REG_EXPAND_SZ {
            Some(String::from_utf8_lossy(&self.data).into_owned())
        } else {
            None
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.val_type == REG_DWORD && self.data.len() >= 4 {
            Some(u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.val_type == REG_QWORD && self.data.len() >= 8 {
            Some(u64::from_le_bytes([
                self.data[0], self.data[1], self.data[2], self.data[3],
                self.data[4], self.data[5], self.data[6], self.data[7],
            ]))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub struct RegistryKey {
    pub name: String,
    pub subkeys: BTreeMap<String, RegistryKey>,
    pub values: BTreeMap<String, RegistryValue>,
    pub timestamp_sec: u64,
}

impl RegistryKey {
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            subkeys: BTreeMap::new(),
            values: BTreeMap::new(),
            timestamp_sec: 0,
        }
    }

    pub fn get_or_create_child(&mut self, subkey_name: &str) -> &mut RegistryKey {
        self.subkeys.entry(String::from(subkey_name)).or_insert_with(|| RegistryKey::new(subkey_name))
    }
}

/// The System Registry Database storing root hives
pub struct RegistryDatabase {
    pub hklm: RegistryKey,
    pub hkcu: RegistryKey,
    pub hkcr: RegistryKey,
    pub hku:  RegistryKey,
    pub hkcc: RegistryKey,
}

impl RegistryDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            hklm: RegistryKey::new("HKEY_LOCAL_MACHINE"),
            hkcu: RegistryKey::new("HKEY_CURRENT_USER"),
            hkcr: RegistryKey::new("HKEY_CLASSES_ROOT"),
            hku:  RegistryKey::new("HKEY_USERS"),
            hkcc: RegistryKey::new("HKEY_CURRENT_CONFIG"),
        };

        db.populate_default_nt_hives();
        db
    }

    fn populate_default_nt_hives(&mut self) {
        // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
        let _ = self.set_value(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
            RegistryValue::new_sz("ProductName", "CorOS Enterprise Workstation 11"),
        );
        let _ = self.set_value(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentBuild",
            RegistryValue::new_sz("CurrentBuild", "26100"),
        );
        let _ = self.set_value(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentMajorVersionNumber",
            RegistryValue::new_dword("CurrentMajorVersionNumber", 10),
        );
        let _ = self.set_value(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "RegisteredOwner",
            RegistryValue::new_sz("RegisteredOwner", "CorOS User"),
        );

        // HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
        let _ = self.set_value(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecution",
            RegistryValue::new_sz("BootExecution", "autocheck autochk *"),
        );

        // HKEY_CURRENT_USER\Control Panel\Desktop
        let _ = self.set_value(
            r"HKEY_CURRENT_USER\Control Panel\Desktop",
            "Wallpaper",
            RegistryValue::new_sz("Wallpaper", "C:\\Windows\\Web\\Wallpaper\\CorOS\\default.png"),
        );
        let _ = self.set_value(
            r"HKEY_CURRENT_USER\Control Panel\Desktop",
            "FontSmoothing",
            RegistryValue::new_dword("FontSmoothing", 2),
        );

        // HKEY_CLASSES_ROOT\.txt
        let _ = self.set_value(
            r"HKEY_CLASSES_ROOT\.txt",
            "",
            RegistryValue::new_sz("", "txtfile"),
        );
        let _ = self.set_value(
            r"HKEY_CLASSES_ROOT\txtfile\shell\open\command",
            "",
            RegistryValue::new_sz("", "notepad.exe %1"),
        );
    }

    fn resolve_root<'a>(&mut self, path: &'a str) -> Option<(&mut RegistryKey, &'a str)> {
        let (root_name, rest) = if let Some(idx) = path.find('\\') {
            (&path[..idx], &path[idx + 1..])
        } else {
            (path, "")
        };

        match root_name {
            "HKEY_LOCAL_MACHINE" | "HKLM" => Some((&mut self.hklm, rest)),
            "HKEY_CURRENT_USER"  | "HKCU" => Some((&mut self.hkcu, rest)),
            "HKEY_CLASSES_ROOT"  | "HKCR" => Some((&mut self.hkcr, rest)),
            "HKEY_USERS"         | "HKU"  => Some((&mut self.hku, rest)),
            "HKEY_CURRENT_CONFIG"| "HKCC" => Some((&mut self.hkcc, rest)),
            _ => None,
        }
    }

    fn resolve_root_ref<'a>(&self, path: &'a str) -> Option<(&RegistryKey, &'a str)> {
        let (root_name, rest) = if let Some(idx) = path.find('\\') {
            (&path[..idx], &path[idx + 1..])
        } else {
            (path, "")
        };

        match root_name {
            "HKEY_LOCAL_MACHINE" | "HKLM" => Some((&self.hklm, rest)),
            "HKEY_CURRENT_USER"  | "HKCU" => Some((&self.hkcu, rest)),
            "HKEY_CLASSES_ROOT"  | "HKCR" => Some((&self.hkcr, rest)),
            "HKEY_USERS"         | "HKU"  => Some((&self.hku, rest)),
            "HKEY_CURRENT_CONFIG"| "HKCC" => Some((&self.hkcc, rest)),
            _ => None,
        }
    }

    /// Set or create a registry value.
    pub fn set_value(&mut self, key_path: &str, val_name: &str, value: RegistryValue) -> Result<(), &'static str> {
        let (root, rest) = self.resolve_root(key_path).ok_or("Invalid root registry hive")?;
        let mut cur = root;

        if !rest.is_empty() {
            for part in rest.split('\\').filter(|p| !p.is_empty()) {
                cur = cur.get_or_create_child(part);
            }
        }

        cur.values.insert(String::from(val_name), value);
        Ok(())
    }

    /// Get a registry value by key path and value name.
    pub fn get_value(&self, key_path: &str, val_name: &str) -> Option<&RegistryValue> {
        let (root, rest) = self.resolve_root_ref(key_path)?;
        let mut cur = root;

        if !rest.is_empty() {
            for part in rest.split('\\').filter(|p| !p.is_empty()) {
                cur = cur.subkeys.get(part)?;
            }
        }

        cur.values.get(val_name)
    }

    /// Enumerate all subkey names in a key.
    pub fn enum_subkeys(&self, key_path: &str) -> Option<Vec<String>> {
        let (root, rest) = self.resolve_root_ref(key_path)?;
        let mut cur = root;

        if !rest.is_empty() {
            for part in rest.split('\\').filter(|p| !p.is_empty()) {
                cur = cur.subkeys.get(part)?;
            }
        }

        Some(cur.subkeys.keys().cloned().collect())
    }

    /// Enumerate all value names in a key.
    pub fn enum_values(&self, key_path: &str) -> Option<Vec<String>> {
        let (root, rest) = self.resolve_root_ref(key_path)?;
        let mut cur = root;

        if !rest.is_empty() {
            for part in rest.split('\\').filter(|p| !p.is_empty()) {
                cur = cur.subkeys.get(part)?;
            }
        }

        Some(cur.values.keys().cloned().collect())
    }

    /// Delete a registry key and all its children.
    pub fn delete_key(&mut self, key_path: &str) -> Result<(), &'static str> {
        let (root, rest) = self.resolve_root(key_path).ok_or("Invalid root registry hive")?;
        let parts: Vec<&str> = rest.split('\\').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err("Cannot delete root hive");
        }

        let mut cur = root;
        for &p in &parts[..parts.len() - 1] {
            cur = cur.subkeys.get_mut(p).ok_or("Key not found in path")?;
        }

        let target = parts[parts.len() - 1];
        if cur.subkeys.remove(target).is_some() {
            Ok(())
        } else {
            Err("Target subkey not found")
        }
    }
}
