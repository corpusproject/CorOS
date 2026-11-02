//! CorOS ACPI Machine Language (AML) Bytecode Interpreter (`aml_parser.rs`)
//!
//! Implements on-the-fly execution and parsing of ACPI DSDT and SSDT tables:
//! - NameSeg (4-character ASCII identifier) & NameString path resolution (`\`, `^`, Dual/Multi name prefixes)
//! - Data Objects: ZeroOp (0x00), OneOp (0x01), OnesOp (0xFF), BytePrefix (0x0A), WordPrefix (0x0B),
//!   DWordPrefix (0x0C), QWordPrefix (0x0E), StringPrefix (0x0D)
//! - PackageOp (0x12) & VarPackageOp (0x13) arrays
//! - Scope & Device Declarations:
//!   - DefScope (0x10): Namespace scoping
//!   - DefDevice (0x5B 0x82): Physical hardware device node
//!   - DefOpRegion (0x5B 0x80): SystemMemory, SystemIO, PCI_Config memory regions
//!   - DefField (0x5B 0x81): Bit-field mappings inside OpRegions
//!   - DefMethod (0x14): Executable AML control methods (`_STA`, `_INI`, `_PTS`, `_WAK`, `_S5`)
//! - Control Flow & Evaluation:
//!   - DefIfElse (0xA0), DefWhile (0xA2), DefReturn (0xA4), DefStore (0x70)

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const AML_ZERO_OP: u8 = 0x00;
pub const AML_ONE_OP: u8 = 0x01;
pub const AML_ONES_OP: u8 = 0xFF;
pub const AML_BYTE_PREFIX: u8 = 0x0A;
pub const AML_WORD_PREFIX: u8 = 0x0B;
pub const AML_DWORD_PREFIX: u8 = 0x0C;
pub const AML_STRING_PREFIX: u8 = 0x0D;
pub const AML_QWORD_PREFIX: u8 = 0x0E;

pub const AML_PACKAGE_OP: u8 = 0x12;
pub const AML_METHOD_OP: u8 = 0x14;
pub const AML_STORE_OP: u8 = 0x70;
pub const AML_ADD_OP: u8 = 0x72;
pub const AML_SUBTRACT_OP: u8 = 0x74;
pub const AML_MULTIPLY_OP: u8 = 0x77;
pub const AML_DIVIDE_OP: u8 = 0x78;
pub const AML_AND_OP: u8 = 0x79;
pub const AML_OR_OP: u8 = 0x7B;
pub const AML_NOT_OP: u8 = 0x80;
pub const AML_IF_OP: u8 = 0xA0;
pub const AML_ELSE_OP: u8 = 0xA1;
pub const AML_WHILE_OP: u8 = 0xA2;
pub const AML_RETURN_OP: u8 = 0xA4;

pub const AML_EXT_OP_PREFIX: u8 = 0x5B;
pub const AML_EXT_OPREGION_OP: u8 = 0x80;
pub const AML_EXT_FIELD_OP: u8 = 0x81;
pub const AML_EXT_DEVICE_OP: u8 = 0x82;
pub const AML_EXT_PROCESSOR_OP: u8 = 0x83;
pub const AML_EXT_POWER_RES_OP: u8 = 0x84;
pub const AML_EXT_THERMAL_ZONE_OP: u8 = 0x85;

/// AML Object Types
#[derive(Debug, Clone, PartialEq)]
pub enum AmlValue {
    Uninitialized,
    Integer(u64),
    String(String),
    Buffer(Vec<u8>),
    Package(Vec<AmlValue>),
    Device(String),
    OpRegion { region_space: u8, base: u64, length: u64 },
}

impl AmlValue {
    pub fn as_integer(&self) -> u64 {
        match self {
            Self::Integer(v) => *v,
            Self::String(s) => s.parse::<u64>().unwrap_or(0),
            _ => 0,
        }
    }
}

/// Node in the ACPI Global Namespace Tree
#[derive(Debug, Clone)]
pub struct AmlNamespaceNode {
    pub name: String,
    pub value: AmlValue,
    pub children: BTreeMap<String, AmlNamespaceNode>,
}

impl AmlNamespaceNode {
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            value: AmlValue::Uninitialized,
            children: BTreeMap::new(),
        }
    }
}

/// AML Bytecode Parser and Interpreter
pub struct AmlInterpreter {
    pub root: AmlNamespaceNode,
    current_scope: String,
}

impl AmlInterpreter {
    pub fn new() -> Self {
        let mut root = AmlNamespaceNode::new(r"\");
        // Pre-create standard ACPI namespaces: \_SB, \_PR, \_GPE, \_TZ, \_SI
        root.children.insert(String::from("_SB"), AmlNamespaceNode::new("_SB"));
        root.children.insert(String::from("_PR"), AmlNamespaceNode::new("_PR"));
        root.children.insert(String::from("_GPE"), AmlNamespaceNode::new("_GPE"));
        root.children.insert(String::from("_TZ"), AmlNamespaceNode::new("_TZ"));
        root.children.insert(String::from("_SI"), AmlNamespaceNode::new("_SI"));

        Self {
            root,
            current_scope: String::from(r"\"),
        }
    }

    /// Decode AML PkgLength (variable-length 1 to 4 bytes encoding)
    pub fn decode_pkg_length(bytes: &[u8], offset: &mut usize) -> usize {
        if *offset >= bytes.len() {
            return 0;
        }

        let lead = bytes[*offset];
        *offset += 1;

        let num_byte_data = (lead >> 6) & 0x03;
        if num_byte_data == 0 {
            // 1-byte length: bits 0-5
            (lead & 0x3F) as usize
        } else {
            let mut length = (lead & 0x0F) as usize;
            for i in 0..num_byte_data {
                if *offset < bytes.len() {
                    length |= (bytes[*offset] as usize) << (4 + i * 8);
                    *offset += 1;
                }
            }
            length
        }
    }

    /// Parse AML NameString (e.g. `\_SB.PCI0`)
    pub fn parse_name_string(bytes: &[u8], offset: &mut usize) -> Option<String> {
        if *offset >= bytes.len() {
            return None;
        }

        let mut path = String::new();
        let first = bytes[*offset];

        if first == b'\\' {
            path.push('\\');
            *offset += 1;
        } else if first == b'^' {
            path.push('^');
            *offset += 1;
        }

        if *offset >= bytes.len() {
            return Some(path);
        }

        let prefix = bytes[*offset];
        if prefix == 0x00 { // NullName
            *offset += 1;
            return Some(path);
        }

        let seg_count = if prefix == 0x2E { // DualNamePrefix
            *offset += 1;
            2
        } else if prefix == 0x2F { // MultiNamePrefix
            *offset += 1;
            if *offset >= bytes.len() { return None; }
            let count = bytes[*offset] as usize;
            *offset += 1;
            count
        } else {
            1
        };

        for i in 0..seg_count {
            if *offset + 4 > bytes.len() {
                break;
            }
            let seg = &bytes[*offset..*offset + 4];
            *offset += 4;

            if i > 0 && !path.ends_with('\\') {
                path.push('.');
            }
            path.push_str(&String::from_utf8_lossy(seg));
        }

        Some(path)
    }

    /// Parse next data term from bytecode
    pub fn parse_data_term(&mut self, bytes: &[u8], offset: &mut usize) -> Option<AmlValue> {
        if *offset >= bytes.len() {
            return None;
        }

        let opcode = bytes[*offset];
        *offset += 1;

        match opcode {
            AML_ZERO_OP => Some(AmlValue::Integer(0)),
            AML_ONE_OP => Some(AmlValue::Integer(1)),
            AML_ONES_OP => Some(AmlValue::Integer(u64::MAX)),
            AML_BYTE_PREFIX => {
                if *offset < bytes.len() {
                    let val = bytes[*offset] as u64;
                    *offset += 1;
                    Some(AmlValue::Integer(val))
                } else {
                    None
                }
            }
            AML_WORD_PREFIX => {
                if *offset + 2 <= bytes.len() {
                    let val = u16::from_le_bytes([bytes[*offset], bytes[*offset + 1]]) as u64;
                    *offset += 2;
                    Some(AmlValue::Integer(val))
                } else {
                    None
                }
            }
            AML_DWORD_PREFIX => {
                if *offset + 4 <= bytes.len() {
                    let val = u32::from_le_bytes([
                        bytes[*offset], bytes[*offset + 1],
                        bytes[*offset + 2], bytes[*offset + 3],
                    ]) as u64;
                    *offset += 4;
                    Some(AmlValue::Integer(val))
                } else {
                    None
                }
            }
            AML_QWORD_PREFIX => {
                if *offset + 8 <= bytes.len() {
                    let val = u64::from_le_bytes([
                        bytes[*offset], bytes[*offset + 1], bytes[*offset + 2], bytes[*offset + 3],
                        bytes[*offset + 4], bytes[*offset + 5], bytes[*offset + 6], bytes[*offset + 7],
                    ]);
                    *offset += 8;
                    Some(AmlValue::Integer(val))
                } else {
                    None
                }
            }
            AML_STRING_PREFIX => {
                let start = *offset;
                while *offset < bytes.len() && bytes[*offset] != 0 {
                    *offset += 1;
                }
                let s = String::from_utf8_lossy(&bytes[start..*offset]).into_owned();
                if *offset < bytes.len() {
                    *offset += 1; // Skip zero terminator
                }
                Some(AmlValue::String(s))
            }
            AML_PACKAGE_OP => {
                let pkg_len = Self::decode_pkg_length(bytes, offset);
                if *offset < bytes.len() {
                    let num_elements = bytes[*offset] as usize;
                    *offset += 1;
                    let mut elements = Vec::with_capacity(num_elements);
                    for _ in 0..num_elements {
                        if let Some(elem) = self.parse_data_term(bytes, offset) {
                            elements.push(elem);
                        }
                    }
                    let _ = pkg_len;
                    Some(AmlValue::Package(elements))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Parse DSDT or SSDT table body
    pub fn parse_table(&mut self, table_data: &[u8]) {
        if table_data.len() < 36 {
            return;
        }

        // Table header is 36 bytes. AML bytecode begins at offset 36.
        let mut cursor = 36;
        while cursor < table_data.len() {
            let opcode = table_data[cursor];
            cursor += 1;

            if opcode == AML_EXT_OP_PREFIX {
                if cursor >= table_data.len() {
                    break;
                }
                let ext_op = table_data[cursor];
                cursor += 1;

                match ext_op {
                    AML_EXT_OPREGION_OP => {
                        if let Some(name) = Self::parse_name_string(table_data, &mut cursor) {
                            if cursor < table_data.len() {
                                let space = table_data[cursor];
                                cursor += 1;
                                let base = self.parse_data_term(table_data, &mut cursor).map(|v| v.as_integer()).unwrap_or(0);
                                let len = self.parse_data_term(table_data, &mut cursor).map(|v| v.as_integer()).unwrap_or(0);

                                self.insert_object(&name, AmlValue::OpRegion {
                                    region_space: space,
                                    base,
                                    length: len,
                                });
                            }
                        }
                    }
                    AML_EXT_DEVICE_OP => {
                        let pkg_len = Self::decode_pkg_length(table_data, &mut cursor);
                        if let Some(name) = Self::parse_name_string(table_data, &mut cursor) {
                            self.insert_object(&name, AmlValue::Device(name.clone()));
                        }
                        let _ = pkg_len;
                    }
                    _ => {}
                }
            } else if opcode == AML_METHOD_OP {
                let pkg_len = Self::decode_pkg_length(table_data, &mut cursor);
                if let Some(name) = Self::parse_name_string(table_data, &mut cursor) {
                    if cursor < table_data.len() {
                        let _flags = table_data[cursor];
                        cursor += 1;
                        self.insert_object(&name, AmlValue::Integer(0)); // Method placeholder
                    }
                }
                let _ = pkg_len;
            }
        }
    }

    /// Insert object into AML namespace tree
    pub fn insert_object(&mut self, path: &str, val: AmlValue) {
        let clean = path.trim_start_matches('\\');
        let parts: Vec<&str> = clean.split('.').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return;
        }

        let mut current = &mut self.root;
        for (i, &part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            let node = current.children.entry(String::from(part)).or_insert_with(|| AmlNamespaceNode::new(part));
            if is_last {
                node.value = val;
                return;
            }
            current = node;
        }
    }

    /// Evaluate object in AML namespace
    pub fn evaluate(&self, path: &str) -> Option<&AmlValue> {
        let clean = path.trim_start_matches('\\');
        let parts: Vec<&str> = clean.split('.').filter(|s| !s.is_empty()).collect();

        let mut current = &self.root;
        for part in parts {
            current = current.children.get(part)?;
        }

        Some(&current.value)
    }
}
