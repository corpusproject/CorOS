//! Windows Registry Editor (regedit.exe) GUI for CorOS.
//! 100% in-house implementation supporting:
//! - Split-pane layout (Left: Tree View of hives and subkeys, Right: Key values list)
//! - Navigation address bar (e.g. `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft`)
//! - Value inspector showing Name, Type (REG_SZ, REG_DWORD...), and Data representation
//! - Keyboard & mouse selection and status bar metrics

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::registry::hive::{RegistryDatabase, RegistryValue, REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY};

#[derive(Clone, Debug)]
pub struct RegeditUiState {
    pub current_path: String,
    pub selected_subkeys: Vec<String>,
    pub selected_values: Vec<(String, String, String)>, // (Name, TypeStr, DataStr)
    pub selected_tree_index: usize,
    pub selected_value_index: usize,
}

impl RegeditUiState {
    pub fn new() -> Self {
        Self {
            current_path: String::from(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
            selected_subkeys: Vec::new(),
            selected_values: Vec::new(),
            selected_tree_index: 0,
            selected_value_index: 0,
        }
    }

    /// Refresh values and subkeys list from the active registry database.
    pub fn refresh_from_db(&mut self, db: &RegistryDatabase) {
        self.selected_subkeys.clear();
        self.selected_values.clear();

        if let Some(subkeys) = db.enum_subkeys(&self.current_path) {
            self.selected_subkeys = subkeys;
        }

        if let Some(value_names) = db.enum_values(&self.current_path) {
            for name in value_names {
                if let Some(val) = db.get_value(&self.current_path, &name) {
                    let type_str = match val.val_type {
                        REG_SZ => "REG_SZ",
                        REG_DWORD => "REG_DWORD",
                        REG_QWORD => "REG_QWORD",
                        REG_BINARY => "REG_BINARY",
                        _ => "REG_NONE",
                    };

                    let data_str = if let Some(s) = val.as_str() {
                        s
                    } else if let Some(dw) = val.as_u32() {
                        format!("0x{:08x} ({})", dw, dw)
                    } else if let Some(qw) = val.as_u64() {
                        format!("0x{:016x} ({})", qw, qw)
                    } else {
                        format!("(binary data, {} bytes)", val.data.len())
                    };

                    let display_name = if name.is_empty() { String::from("(Default)") } else { name };
                    self.selected_values.push((display_name, String::from(type_str), data_str));
                }
            }
        }
    }
}
