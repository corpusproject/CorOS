//! Binary Format Dispatcher (`binfmt_misc`)
//!
//! Provides extensible binary execution dispatching via magic byte sequences,
//! bitmasks, and file extension associations according to the Linux `binfmt_misc` ABI.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Magic,
    Extension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BinfmtFlags {
    pub preserve_argv0: bool, // 'P'
    pub open_binary: bool,    // 'O'
    pub credentials: bool,    // 'C'
    pub fix_binary: bool,     // 'F'
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinfmtEntry {
    pub name: String,
    pub kind: MatchKind,
    pub offset: usize,
    pub magic: Vec<u8>,
    pub mask: Vec<u8>,
    pub extension: String,
    pub interpreter: String,
    pub flags: BinfmtFlags,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinfmtError {
    InvalidFormatString(&'static str),
    DuplicateEntry(String),
    EntryNotFound(String),
    MaskLengthMismatch,
    InvalidHexEscape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinfmtExecutionPlan {
    pub handler_name: String,
    pub interpreter: String,
    pub flags: BinfmtFlags,
    pub argv: Vec<String>,
}

pub struct BinfmtRegistry {
    pub entries: Vec<BinfmtEntry>,
}

impl BinfmtRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn register(&mut self, entry: BinfmtEntry) -> Result<(), BinfmtError> {
        if self.entries.iter().any(|e| e.name == entry.name) {
            return Err(BinfmtError::DuplicateEntry(entry.name));
        }
        self.entries.push(entry);
        Ok(())
    }

    pub fn unregister(&mut self, name: &str) -> Result<(), BinfmtError> {
        let pos = self.entries.iter().position(|e| e.name == name)
            .ok_or_else(|| BinfmtError::EntryNotFound(String::from(name)))?;
        self.entries.remove(pos);
        Ok(())
    }

    pub fn parse_registration(line: &str) -> Result<BinfmtEntry, BinfmtError> {
        if line.is_empty() {
            return Err(BinfmtError::InvalidFormatString("Empty registration string"));
        }

        let delim = line.chars().next().unwrap();
        let parts: Vec<&str> = line.split(delim).collect();

        // :name:type:offset:magic:mask:interpreter:flags
        if parts.len() < 8 {
            return Err(BinfmtError::InvalidFormatString("Too few fields"));
        }

        let name = parts[1];
        let type_str = parts[2];
        let offset_str = parts[3];
        let magic_str = parts[4];
        let mask_str = parts[5];
        let interp_str = parts[6];
        let flags_str = parts[7];

        let kind = match type_str {
            "M" => MatchKind::Magic,
            "E" => MatchKind::Extension,
            _ => return Err(BinfmtError::InvalidFormatString("Unknown match type")),
        };

        let offset = if offset_str.is_empty() {
            0
        } else {
            Self::parse_usize(offset_str)?
        };

        let (magic, extension) = if kind == MatchKind::Magic {
            (Self::parse_escaped_bytes(magic_str)?, String::new())
        } else {
            (Vec::new(), String::from(magic_str))
        };

        let mask = if mask_str.is_empty() {
            alloc::vec![0xFFu8; magic.len()]
        } else {
            let m = Self::parse_escaped_bytes(mask_str)?;
            if m.len() != magic.len() {
                return Err(BinfmtError::MaskLengthMismatch);
            }
            m
        };

        let mut flags = BinfmtFlags::default();
        for ch in flags_str.chars() {
            match ch {
                'P' => flags.preserve_argv0 = true,
                'O' => flags.open_binary = true,
                'C' => flags.credentials = true,
                'F' => flags.fix_binary = true,
                _ => {}
            }
        }

        Ok(BinfmtEntry {
            name: String::from(name),
            kind,
            offset,
            magic,
            mask,
            extension,
            interpreter: String::from(interp_str),
            flags,
            enabled: true,
        })
    }

    pub fn match_binary(&self, header: &[u8], filename: &str) -> Option<BinfmtExecutionPlan> {
        for entry in &self.entries {
            if !entry.enabled {
                continue;
            }

            let is_match = match entry.kind {
                MatchKind::Magic => {
                    if header.len() >= entry.offset + entry.magic.len() {
                        let slice = &header[entry.offset..entry.offset + entry.magic.len()];
                        slice.iter().zip(&entry.magic).zip(&entry.mask).all(|((&b, &m), &mask)| {
                            (b & mask) == (m & mask)
                        })
                    } else {
                        false
                    }
                }
                MatchKind::Extension => {
                    if let Some(ext) = filename.rsplit('.').next() {
                        ext == entry.extension
                    } else {
                        false
                    }
                }
            };

            if is_match {
                let mut argv = Vec::new();
                argv.push(entry.interpreter.clone());
                if !entry.flags.preserve_argv0 {
                    argv.push(String::from(filename));
                }

                return Some(BinfmtExecutionPlan {
                    handler_name: entry.name.clone(),
                    interpreter: entry.interpreter.clone(),
                    flags: entry.flags,
                    argv,
                });
            }
        }

        None
    }

    fn parse_escaped_bytes(s: &str) -> Result<Vec<u8>, BinfmtError> {
        let mut bytes = Vec::new();
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '\\' && i + 3 < chars.len() && chars[i + 1] == 'x' {
                let hex_str: String = chars[i + 2..i + 4].iter().collect();
                let byte = u8::from_str_radix(&hex_str, 16)
                    .map_err(|_| BinfmtError::InvalidHexEscape)?;
                bytes.push(byte);
                i += 4;
            } else {
                bytes.push(chars[i] as u8);
                i += 1;
            }
        }

        Ok(bytes)
    }

    fn parse_usize(s: &str) -> Result<usize, BinfmtError> {
        let mut val = 0usize;
        for b in s.bytes() {
            if b < b'0' || b > b'9' {
                return Err(BinfmtError::InvalidFormatString("Invalid integer"));
            }
            val = val.checked_mul(10).and_then(|v| v.checked_add((b - b'0') as usize))
                .ok_or(BinfmtError::InvalidFormatString("Integer overflow"))?;
        }
        Ok(val)
    }
}

pub fn verify_binfmt_misc() -> u32 {
    let mut check_count = 0u32;

    let mut reg = BinfmtRegistry::new();

    // Test 1: Register WASM binary handler (:wasm:M:0:\x00asm::/usr/bin/wasm_run:P)
    let wasm_spec = ":wasm:M:0:\\x00asm::/usr/bin/wasm_run:P";
    if let Ok(entry) = BinfmtRegistry::parse_registration(wasm_spec) {
        if entry.name == "wasm"
            && entry.magic == [0x00, b'a', b's', b'm']
            && entry.interpreter == "/usr/bin/wasm_run"
            && entry.flags.preserve_argv0
        {
            check_count += 1;
            reg.register(entry).unwrap();
        }
    }

    // Test 2: Register Java Class handler (0xCA, 0xFE, 0xBA, 0xBE)
    let java_spec = ":java:M:0:\\xca\\xfe\\xba\\xbe::/usr/bin/java:";
    if let Ok(entry) = BinfmtRegistry::parse_registration(java_spec) {
        if entry.name == "java" && entry.magic == [0xca, 0xfe, 0xba, 0xbe] {
            check_count += 1;
            reg.register(entry).unwrap();
        }
    }

    // Test 3: Register Python script by extension
    let py_spec = ":python:E::py::/usr/bin/python3:";
    if let Ok(entry) = BinfmtRegistry::parse_registration(py_spec) {
        if entry.name == "python" && entry.extension == "py" {
            check_count += 1;
            reg.register(entry).unwrap();
        }
    }

    // Test 4: Match WASM buffer
    let wasm_file = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
    if let Some(plan) = reg.match_binary(&wasm_file, "program.wasm") {
        if plan.handler_name == "wasm" && plan.interpreter == "/usr/bin/wasm_run" {
            check_count += 1;
        }
    }

    // Test 5: Match Java class buffer
    let java_file = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34];
    if let Some(plan) = reg.match_binary(&java_file, "Main.class") {
        if plan.handler_name == "java" && plan.interpreter == "/usr/bin/java" {
            check_count += 1;
        }
    }

    // Test 6: Match Python extension
    let dummy_header = [0x23, 0x21]; // #!
    if let Some(plan) = reg.match_binary(&dummy_header, "script.py") {
        if plan.handler_name == "python" && plan.interpreter == "/usr/bin/python3" {
            check_count += 1;
        }
    }

    // Test 7: Unregister entry
    let unreg = reg.unregister("wasm");
    if unreg.is_ok() && reg.match_binary(&wasm_file, "program.wasm").is_none() {
        check_count += 1;
    }

    check_count
}
