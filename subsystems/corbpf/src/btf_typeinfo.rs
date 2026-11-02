//! BPF Type Format (`BTF`) Binary Metadata Builder, Parser, and String Resolver.
//!
//! Implements the canonical `<linux/btf.h>` binary layout (`BTF_MAGIC = 0xEB9F`,
//! 24-byte `BtfHeader`, 12-byte `BtfType` descriptors, and null-terminated
//! string section lookup) enabling CO-RE (Compile Once - Run Everywhere) introspection.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Canonical BTF magic number (`0xEB9F`).
pub const BTF_MAGIC: u16 = 0xEB9F;
/// Current BTF specification version.
pub const BTF_VERSION: u8 = 1;
/// Size of the binary `btf_header` struct in bytes.
pub const BTF_HEADER_SIZE: usize = 24;

/// BTF integer encoding flags (`BTF_INT_SIGNED`, `BTF_INT_CHAR`, `BTF_INT_BOOL`).
pub const BTF_INT_SIGNED: u8 = 1 << 0;
pub const BTF_INT_CHAR: u8 = 1 << 1;
pub const BTF_INT_BOOL: u8 = 1 << 2;

/// BTF kind codes (`BTF_INFO_KIND(info)` bits `24..=28`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BtfKind {
    Unknown = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
}

impl BtfKind {
    pub const fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::Int,
            2 => Self::Ptr,
            3 => Self::Array,
            4 => Self::Struct,
            5 => Self::Union,
            6 => Self::Enum,
            7 => Self::Fwd,
            8 => Self::Typedef,
            9 => Self::Volatile,
            10 => Self::Const,
            11 => Self::Restrict,
            12 => Self::Func,
            13 => Self::FuncProto,
            14 => Self::Var,
            15 => Self::DataSec,
            _ => Self::Unknown,
        }
    }
}

/// 24-byte BTF binary header (`struct btf_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub type_off: u32,
    pub type_len: u32,
    pub str_off: u32,
    pub str_len: u32,
}

/// Member descriptor inside a `BtfKind::Struct` or `BtfKind::Union`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfMember {
    pub name: String,
    pub type_id: u32,
    pub bit_offset: u32,
}

/// Parsed high-level BTF type descriptor (`type_id` starts at `1`; `0` is `void`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfTypeDescriptor {
    pub type_id: u32,
    pub name: String,
    pub kind: BtfKind,
    pub size_or_type: u32,
    pub members: Vec<BtfMember>,
}

/// Error returned during BTF binary parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtfError {
    BufferTooSmall,
    BadMagic(u16),
    UnsupportedVersion(u8),
    SectionOutOfBounds,
    MalformedTypeRecord,
    InvalidStringOffset(u32),
}

/// Builder that emits a valid `<linux/btf.h>` binary blob and parses it back.
pub struct BtfBlobBuilder {
    type_bytes: Vec<u8>,
    str_bytes: Vec<u8>,
    next_type_id: u32,
}

impl BtfBlobBuilder {
    pub fn new() -> Self {
        // String table always starts with a leading NUL byte at offset 0 (representing anonymous name).
        Self {
            type_bytes: Vec::new(),
            str_bytes: vec![0u8],
            next_type_id: 1,
        }
    }

    /// Intern a string into the BTF string table and return its byte offset.
    pub fn add_string(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        let offset = self.str_bytes.len() as u32;
        self.str_bytes.extend_from_slice(s.as_bytes());
        self.str_bytes.push(0);
        offset
    }

    const fn make_info(kind: BtfKind, vlen: u16, kflag: bool) -> u32 {
        ((if kflag { 1u32 } else { 0u32 }) << 31)
            | ((kind as u32) << 24)
            | (vlen as u32)
    }

    fn push_type_header(&mut self, name_off: u32, info: u32, size_or_type: u32) -> u32 {
        let id = self.next_type_id;
        self.next_type_id += 1;
        self.type_bytes.extend_from_slice(&name_off.to_le_bytes());
        self.type_bytes.extend_from_slice(&info.to_le_bytes());
        self.type_bytes.extend_from_slice(&size_or_type.to_le_bytes());
        id
    }

    /// Add a `BTF_KIND_INT` type (12-byte base header + 4-byte int encoding word).
    pub fn add_int_type(&mut self, name: &str, byte_size: u32, encoding: u8) -> u32 {
        let name_off = self.add_string(name);
        let info = Self::make_info(BtfKind::Int, 0, false);
        let id = self.push_type_header(name_off, info, byte_size);
        let bits = (byte_size * 8) & 0xff;
        let int_data: u32 = ((encoding as u32) << 24) | bits;
        self.type_bytes.extend_from_slice(&int_data.to_le_bytes());
        id
    }

    /// Add a `BTF_KIND_PTR` referencing `target_type_id`.
    pub fn add_ptr_type(&mut self, target_type_id: u32) -> u32 {
        let info = Self::make_info(BtfKind::Ptr, 0, false);
        self.push_type_header(0, info, target_type_id)
    }

    /// Add a `BTF_KIND_TYPEDEF` aliasing `target_type_id`.
    pub fn add_typedef(&mut self, name: &str, target_type_id: u32) -> u32 {
        let name_off = self.add_string(name);
        let info = Self::make_info(BtfKind::Typedef, 0, false);
        self.push_type_header(name_off, info, target_type_id)
    }

    /// Add a `BTF_KIND_STRUCT` with `members: &[(field_name, field_type_id, bit_offset)]`.
    pub fn add_struct_type(
        &mut self,
        name: &str,
        byte_size: u32,
        members: &[(&str, u32, u32)],
    ) -> u32 {
        let name_off = self.add_string(name);
        let info = Self::make_info(BtfKind::Struct, members.len() as u16, false);
        let id = self.push_type_header(name_off, info, byte_size);
        for &(m_name, m_type, bit_off) in members {
            let m_name_off = self.add_string(m_name);
            self.type_bytes.extend_from_slice(&m_name_off.to_le_bytes());
            self.type_bytes.extend_from_slice(&m_type.to_le_bytes());
            self.type_bytes.extend_from_slice(&bit_off.to_le_bytes());
        }
        id
    }

    /// Finalize and serialize the complete BTF binary blob (`header + types + strings`).
    pub fn finish(&self) -> Vec<u8> {
        let hdr_len = BTF_HEADER_SIZE as u32;
        let type_off = 0u32;
        let type_len = self.type_bytes.len() as u32;
        let str_off = type_len;
        let str_len = self.str_bytes.len() as u32;

        let mut out = Vec::with_capacity(BTF_HEADER_SIZE + self.type_bytes.len() + self.str_bytes.len());
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0); // flags
        out.extend_from_slice(&hdr_len.to_le_bytes());
        out.extend_from_slice(&type_off.to_le_bytes());
        out.extend_from_slice(&type_len.to_le_bytes());
        out.extend_from_slice(&str_off.to_le_bytes());
        out.extend_from_slice(&str_len.to_le_bytes());
        out.extend_from_slice(&self.type_bytes);
        out.extend_from_slice(&self.str_bytes);
        out
    }
}

impl Default for BtfBlobBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Binary BTF parser and type resolver.
pub struct BtfParser;

impl BtfParser {
    /// Parse a binary BTF blob into its header and resolved `BtfTypeDescriptor` list.
    pub fn parse(blob: &[u8]) -> Result<(BtfHeader, Vec<BtfTypeDescriptor>), BtfError> {
        if blob.len() < BTF_HEADER_SIZE {
            return Err(BtfError::BufferTooSmall);
        }
        let magic = u16::from_le_bytes([blob[0], blob[1]]);
        if magic != BTF_MAGIC {
            return Err(BtfError::BadMagic(magic));
        }
        let version = blob[2];
        if version != BTF_VERSION {
            return Err(BtfError::UnsupportedVersion(version));
        }
        let flags = blob[3];
        let hdr_len = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        let type_off = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]);
        let type_len = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]);
        let str_off = u32::from_le_bytes([blob[16], blob[17], blob[18], blob[19]]);
        let str_len = u32::from_le_bytes([blob[20], blob[21], blob[22], blob[23]]);

        let type_start = (hdr_len as usize).saturating_add(type_off as usize);
        let type_end = type_start.saturating_add(type_len as usize);
        let str_start = (hdr_len as usize).saturating_add(str_off as usize);
        let str_end = str_start.saturating_add(str_len as usize);

        if type_end > blob.len() || str_end > blob.len() {
            return Err(BtfError::SectionOutOfBounds);
        }

        let type_sec = &blob[type_start..type_end];
        let str_sec = &blob[str_start..str_end];

        let mut cursor = 0usize;
        let mut type_id = 1u32;
        let mut types = Vec::new();

        while cursor < type_sec.len() {
            if cursor + 12 > type_sec.len() {
                return Err(BtfError::MalformedTypeRecord);
            }
            let name_off = u32::from_le_bytes([
                type_sec[cursor],
                type_sec[cursor + 1],
                type_sec[cursor + 2],
                type_sec[cursor + 3],
            ]);
            let info = u32::from_le_bytes([
                type_sec[cursor + 4],
                type_sec[cursor + 5],
                type_sec[cursor + 6],
                type_sec[cursor + 7],
            ]);
            let size_or_type = u32::from_le_bytes([
                type_sec[cursor + 8],
                type_sec[cursor + 9],
                type_sec[cursor + 10],
                type_sec[cursor + 11],
            ]);
            cursor += 12;

            let kind = BtfKind::from_u8(((info >> 24) & 0x1f) as u8);
            let vlen = (info & 0xffff) as usize;
            let name = Self::resolve_string(str_sec, name_off)?;
            let mut members = Vec::new();

            match kind {
                BtfKind::Int => {
                    if cursor + 4 > type_sec.len() {
                        return Err(BtfError::MalformedTypeRecord);
                    }
                    cursor += 4;
                }
                BtfKind::Struct | BtfKind::Union => {
                    if cursor + vlen * 12 > type_sec.len() {
                        return Err(BtfError::MalformedTypeRecord);
                    }
                    for _ in 0..vlen {
                        let m_name_off = u32::from_le_bytes([
                            type_sec[cursor],
                            type_sec[cursor + 1],
                            type_sec[cursor + 2],
                            type_sec[cursor + 3],
                        ]);
                        let m_type = u32::from_le_bytes([
                            type_sec[cursor + 4],
                            type_sec[cursor + 5],
                            type_sec[cursor + 6],
                            type_sec[cursor + 7],
                        ]);
                        let m_off = u32::from_le_bytes([
                            type_sec[cursor + 8],
                            type_sec[cursor + 9],
                            type_sec[cursor + 10],
                            type_sec[cursor + 11],
                        ]);
                        cursor += 12;
                        members.push(BtfMember {
                            name: Self::resolve_string(str_sec, m_name_off)?,
                            type_id: m_type,
                            bit_offset: m_off,
                        });
                    }
                }
                BtfKind::Ptr | BtfKind::Typedef | BtfKind::Volatile | BtfKind::Const | BtfKind::Fwd => {}
                _ => {
                    return Err(BtfError::MalformedTypeRecord);
                }
            }

            types.push(BtfTypeDescriptor {
                type_id,
                name,
                kind,
                size_or_type,
                members,
            });
            type_id += 1;
        }

        let header = BtfHeader {
            magic,
            version,
            flags,
            hdr_len,
            type_off,
            type_len,
            str_off,
            str_len,
        };
        Ok((header, types))
    }

    pub fn resolve_string(str_sec: &[u8], offset: u32) -> Result<String, BtfError> {
        let start = offset as usize;
        if start >= str_sec.len() {
            return Err(BtfError::InvalidStringOffset(offset));
        }
        let mut end = start;
        while end < str_sec.len() && str_sec[end] != 0 {
            end += 1;
        }
        let s = core::str::from_utf8(&str_sec[start..end])
            .map_err(|_| BtfError::InvalidStringOffset(offset))?;
        Ok(String::from(s))
    }
}
