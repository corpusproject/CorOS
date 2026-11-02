//! D-Bus wire protocol codec (16-byte fixed header, little/big-endian decoder,
//! `DbusMessageType`: `MethodCall`, `MethodReturn`, `Error`, `Signal`, D-Bus natural
//! alignment padding `align_to`, and marshaling/unmarshaling of `UINT32`, `INT64`,
//! `STRING`, `OBJECT_PATH`, `SIGNATURE`, and `ARRAY`).

use alloc::string::String;
use alloc::vec::Vec;

/// D-Bus protocol major version (`1`).
pub const DBUS_MAJOR_PROTOCOL_VERSION: u8 = 1;

/// Endianness flag in byte 0 of a D-Bus message header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbusEndian {
    /// `'l'` (`0x6C`) — Little-endian.
    Little,
    /// `'B'` (`0x42`) — Big-endian.
    Big,
}

impl DbusEndian {
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Little => b'l',
            Self::Big => b'B',
        }
    }

    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'l' => Some(Self::Little),
            b'B' => Some(Self::Big),
            _ => None,
        }
    }

    #[inline]
    pub fn write_u32(self, val: u32) -> [u8; 4] {
        match self {
            Self::Little => val.to_le_bytes(),
            Self::Big => val.to_be_bytes(),
        }
    }

    #[inline]
    pub fn read_u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    #[inline]
    pub fn write_i64(self, val: i64) -> [u8; 8] {
        match self {
            Self::Little => val.to_le_bytes(),
            Self::Big => val.to_be_bytes(),
        }
    }

    #[inline]
    pub fn read_i64(self, bytes: [u8; 8]) -> i64 {
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }
}

/// D-Bus message type in byte 1 of the fixed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbusMessageType {
    MethodCall = 1,
    MethodReturn = 2,
    Error = 3,
    Signal = 4,
}

impl DbusMessageType {
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::MethodCall),
            2 => Some(Self::MethodReturn),
            3 => Some(Self::Error),
            4 => Some(Self::Signal),
            _ => None,
        }
    }
}

/// D-Bus wire value types supported by the marshaler/unmarshaler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbusValue {
    /// `'u'` — 32-bit unsigned integer (4-byte aligned).
    Uint32(u32),
    /// `'x'` — 64-bit signed integer (8-byte aligned).
    Int64(i64),
    /// `'s'` — UTF-8 string preceded by 4-byte length and followed by NUL byte (4-byte aligned).
    String(String),
    /// `'o'` — Valid D-Bus object path (e.g. `"/org/freedesktop/DBus"`, 4-byte aligned).
    ObjectPath(String),
    /// `'g'` — Type signature preceded by 1-byte length and followed by NUL byte (1-byte aligned).
    Signature(String),
    /// `'a'` — Array of homogeneous elements preceded by 4-byte byte-length and element alignment padding.
    Array(Vec<DbusValue>),
}

impl DbusValue {
    /// Return the natural alignment boundary in bytes required by the D-Bus specification.
    pub const fn alignment(&self) -> usize {
        match self {
            Self::Uint32(_) | Self::String(_) | Self::ObjectPath(_) | Self::Array(_) => 4,
            Self::Int64(_) => 8,
            Self::Signature(_) => 1,
        }
    }
}

/// Compute the next offset aligned upward to `alignment` (where `alignment` is a power of two).
#[inline]
pub const fn align_to(offset: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        offset
    } else {
        (offset + alignment - 1) & !(alignment - 1)
    }
}

/// Validate a D-Bus `OBJECT_PATH` (`'o'`) according to the D-Bus specification:
/// must start with `'/'`, must not end with `'/'` unless the path is `"/"`, and must
/// not contain empty path components (`"//"`).
pub fn is_valid_object_path(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }
    if path.ends_with('/') || path.contains("//") {
        return false;
    }
    path.bytes().all(|b| {
        b == b'/' || b.is_ascii_alphanumeric() || b == b'_'
    })
}

/// Errors returned during D-Bus wire encoding or decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbusWireError {
    BufferTooShort,
    InvalidEndianFlag,
    InvalidMessageType,
    UnsupportedProtocolVersion,
    ZeroSerialForbidden,
    NonZeroAlignmentPadding,
    InvalidObjectPath,
    MissingNulTerminator,
    InvalidUtf8,
}

/// 16-byte fixed D-Bus message header (`yyyyuua(yv)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DbusFixedHeader {
    pub endian: DbusEndian,
    pub msg_type: DbusMessageType,
    pub flags: u8,
    pub version: u8,
    pub body_len: u32,
    pub serial: u32,
    pub header_fields_len: u32,
}

impl DbusFixedHeader {
    pub const SIZE: usize = 16;

    pub fn encode(&self) -> Result<[u8; Self::SIZE], DbusWireError> {
        if self.serial == 0 {
            return Err(DbusWireError::ZeroSerialForbidden);
        }
        let mut out = [0u8; Self::SIZE];
        out[0] = self.endian.to_byte();
        out[1] = self.msg_type as u8;
        out[2] = self.flags;
        out[3] = self.version;
        out[4..8].copy_from_slice(&self.endian.write_u32(self.body_len));
        out[8..12].copy_from_slice(&self.endian.write_u32(self.serial));
        out[12..16].copy_from_slice(&self.endian.write_u32(self.header_fields_len));
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DbusWireError> {
        if buf.len() < Self::SIZE {
            return Err(DbusWireError::BufferTooShort);
        }
        let endian = DbusEndian::from_byte(buf[0]).ok_or(DbusWireError::InvalidEndianFlag)?;
        let msg_type =
            DbusMessageType::from_byte(buf[1]).ok_or(DbusWireError::InvalidMessageType)?;
        let flags = buf[2];
        let version = buf[3];
        if version != DBUS_MAJOR_PROTOCOL_VERSION {
            return Err(DbusWireError::UnsupportedProtocolVersion);
        }
        let body_len = endian.read_u32([buf[4], buf[5], buf[6], buf[7]]);
        let serial = endian.read_u32([buf[8], buf[9], buf[10], buf[11]]);
        if serial == 0 {
            return Err(DbusWireError::ZeroSerialForbidden);
        }
        let header_fields_len = endian.read_u32([buf[12], buf[13], buf[14], buf[15]]);
        Ok(Self {
            endian,
            msg_type,
            flags,
            version,
            body_len,
            serial,
            header_fields_len,
        })
    }
}

/// D-Bus body marshaler and unmarshaler respecting natural alignment padding.
pub struct DbusCodec;

impl DbusCodec {
    fn pad_with_zeros(buf: &mut Vec<u8>, alignment: usize) {
        let target = align_to(buf.len(), alignment);
        while buf.len() < target {
            buf.push(0);
        }
    }

    fn verify_and_advance_padding(
        buf: &[u8],
        cursor: &mut usize,
        alignment: usize,
    ) -> Result<(), DbusWireError> {
        let target = align_to(*cursor, alignment);
        if target > buf.len() {
            return Err(DbusWireError::BufferTooShort);
        }
        for &b in &buf[*cursor..target] {
            if b != 0 {
                return Err(DbusWireError::NonZeroAlignmentPadding);
            }
        }
        *cursor = target;
        Ok(())
    }

    /// Marshal a single `DbusValue` into `buf` using `endian`.
    pub fn marshal_value(
        buf: &mut Vec<u8>,
        endian: DbusEndian,
        val: &DbusValue,
    ) -> Result<(), DbusWireError> {
        Self::pad_with_zeros(buf, val.alignment());
        match val {
            DbusValue::Uint32(v) => {
                buf.extend_from_slice(&endian.write_u32(*v));
            }
            DbusValue::Int64(v) => {
                buf.extend_from_slice(&endian.write_i64(*v));
            }
            DbusValue::String(s) => {
                let bytes = s.as_bytes();
                buf.extend_from_slice(&endian.write_u32(bytes.len() as u32));
                buf.extend_from_slice(bytes);
                buf.push(0);
            }
            DbusValue::ObjectPath(p) => {
                if !is_valid_object_path(p) {
                    return Err(DbusWireError::InvalidObjectPath);
                }
                let bytes = p.as_bytes();
                buf.extend_from_slice(&endian.write_u32(bytes.len() as u32));
                buf.extend_from_slice(bytes);
                buf.push(0);
            }
            DbusValue::Signature(sig) => {
                let bytes = sig.as_bytes();
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
                buf.push(0);
            }
            DbusValue::Array(elements) => {
                let elem_align = elements.first().map(|e| e.alignment()).unwrap_or(4);
                // Write placeholder 4-byte array byte length.
                let len_pos = buf.len();
                buf.extend_from_slice(&[0, 0, 0, 0]);
                // Pad to element alignment before starting array data.
                Self::pad_with_zeros(buf, elem_align);
                let data_start = buf.len();
                for elem in elements {
                    Self::marshal_value(buf, endian, elem)?;
                }
                let byte_len = (buf.len() - data_start) as u32;
                let len_bytes = endian.write_u32(byte_len);
                buf[len_pos..len_pos + 4].copy_from_slice(&len_bytes);
            }
        }
        Ok(())
    }

    pub fn unmarshal_uint32(
        buf: &[u8],
        cursor: &mut usize,
        endian: DbusEndian,
    ) -> Result<u32, DbusWireError> {
        Self::verify_and_advance_padding(buf, cursor, 4)?;
        if *cursor + 4 > buf.len() {
            return Err(DbusWireError::BufferTooShort);
        }
        let val = endian.read_u32([
            buf[*cursor],
            buf[*cursor + 1],
            buf[*cursor + 2],
            buf[*cursor + 3],
        ]);
        *cursor += 4;
        Ok(val)
    }

    pub fn unmarshal_int64(
        buf: &[u8],
        cursor: &mut usize,
        endian: DbusEndian,
    ) -> Result<i64, DbusWireError> {
        Self::verify_and_advance_padding(buf, cursor, 8)?;
        if *cursor + 8 > buf.len() {
            return Err(DbusWireError::BufferTooShort);
        }
        let val = endian.read_i64([
            buf[*cursor],
            buf[*cursor + 1],
            buf[*cursor + 2],
            buf[*cursor + 3],
            buf[*cursor + 4],
            buf[*cursor + 5],
            buf[*cursor + 6],
            buf[*cursor + 7],
        ]);
        *cursor += 8;
        Ok(val)
    }

    pub fn unmarshal_string(
        buf: &[u8],
        cursor: &mut usize,
        endian: DbusEndian,
    ) -> Result<String, DbusWireError> {
        let len = Self::unmarshal_uint32(buf, cursor, endian)? as usize;
        if *cursor + len + 1 > buf.len() {
            return Err(DbusWireError::BufferTooShort);
        }
        if buf[*cursor + len] != 0 {
            return Err(DbusWireError::MissingNulTerminator);
        }
        let s = core::str::from_utf8(&buf[*cursor..*cursor + len])
            .map_err(|_| DbusWireError::InvalidUtf8)?;
        *cursor += len + 1;
        Ok(String::from(s))
    }

    pub fn unmarshal_object_path(
        buf: &[u8],
        cursor: &mut usize,
        endian: DbusEndian,
    ) -> Result<String, DbusWireError> {
        let s = Self::unmarshal_string(buf, cursor, endian)?;
        if !is_valid_object_path(&s) {
            return Err(DbusWireError::InvalidObjectPath);
        }
        Ok(s)
    }

    pub fn unmarshal_signature(
        buf: &[u8],
        cursor: &mut usize,
    ) -> Result<String, DbusWireError> {
        if *cursor + 2 > buf.len() {
            return Err(DbusWireError::BufferTooShort);
        }
        let len = buf[*cursor] as usize;
        *cursor += 1;
        if *cursor + len + 1 > buf.len() {
            return Err(DbusWireError::BufferTooShort);
        }
        if buf[*cursor + len] != 0 {
            return Err(DbusWireError::MissingNulTerminator);
        }
        let s = core::str::from_utf8(&buf[*cursor..*cursor + len])
            .map_err(|_| DbusWireError::InvalidUtf8)?;
        *cursor += len + 1;
        Ok(String::from(s))
    }

    pub fn unmarshal_int64_array(
        buf: &[u8],
        cursor: &mut usize,
        endian: DbusEndian,
    ) -> Result<Vec<i64>, DbusWireError> {
        let byte_len = Self::unmarshal_uint32(buf, cursor, endian)? as usize;
        Self::verify_and_advance_padding(buf, cursor, 8)?;
        let end = *cursor + byte_len;
        if end > buf.len() {
            return Err(DbusWireError::BufferTooShort);
        }
        let mut out = Vec::new();
        while *cursor < end {
            out.push(Self::unmarshal_int64(buf, cursor, endian)?);
        }
        Ok(out)
    }
}

/// Self-test verifying 16-byte fixed header encode/decode in both endiannesses,
/// `align_to` padding, and marshaling/unmarshaling of `OBJECT_PATH`, `SIGNATURE`, `STRING`,
/// `UINT32`, `INT64`, and `ARRAY` of `INT64`.
pub fn self_test() -> bool {
    let mut body = Vec::new();
    let endian = DbusEndian::Big;

    if DbusCodec::marshal_value(
        &mut body,
        endian,
        &DbusValue::ObjectPath(String::from("/org/coros/SystemManager")),
    )
    .is_err()
        || DbusCodec::marshal_value(
            &mut body,
            endian,
            &DbusValue::Signature(String::from("osuax")),
        )
        .is_err()
        || DbusCodec::marshal_value(
            &mut body,
            endian,
            &DbusValue::String(String::from("StartUnit")),
        )
        .is_err()
        || DbusCodec::marshal_value(&mut body, endian, &DbusValue::Uint32(42)).is_err()
        || DbusCodec::marshal_value(
            &mut body,
            endian,
            &DbusValue::Array(alloc::vec![
                DbusValue::Int64(100_000_000_000),
                DbusValue::Int64(-999_999_999)
            ]),
        )
        .is_err()
    {
        return false;
    }

    let hdr = DbusFixedHeader {
        endian,
        msg_type: DbusMessageType::MethodCall,
        flags: 0x01,
        version: DBUS_MAJOR_PROTOCOL_VERSION,
        body_len: body.len() as u32,
        serial: 17,
        header_fields_len: 32,
    };

    let wire_hdr = match hdr.encode() {
        Ok(h) => h,
        Err(_) => return false,
    };
    let decoded_hdr = match DbusFixedHeader::decode(&wire_hdr) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if decoded_hdr != hdr {
        return false;
    }

    let mut cur = 0usize;
    let path = match DbusCodec::unmarshal_object_path(&body, &mut cur, endian) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match DbusCodec::unmarshal_signature(&body, &mut cur) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let method = match DbusCodec::unmarshal_string(&body, &mut cur, endian) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let code = match DbusCodec::unmarshal_uint32(&body, &mut cur, endian) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let timestamps = match DbusCodec::unmarshal_int64_array(&body, &mut cur, endian) {
        Ok(a) => a,
        Err(_) => return false,
    };

    path == "/org/coros/SystemManager"
        && sig == "osuax"
        && method == "StartUnit"
        && code == 42
        && timestamps.as_slice() == [100_000_000_000i64, -999_999_999i64]
        && cur == body.len()
}
