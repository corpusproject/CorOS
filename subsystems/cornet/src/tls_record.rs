//! TLS 1.3 (RFC 8446) Record Layer Framing, `ClientHello` / `ServerHello` Handshake Extension Codec & SHA-256 Transcript Hash State.

use alloc::vec::Vec;

/// Legacy TLS 1.2 Record Version (`0x0303`) carried in TLS 1.3 record headers and `legacy_version`.
pub const TLS_LEGACY_VERSION_1_2: u16 = 0x0303;
/// Negotiated TLS 1.3 Protocol Version (`0x0304`) carried inside `supported_versions` (Extension 43).
pub const TLS_VERSION_1_3: u16 = 0x0304;

/// TLS 1.3 Cipher Suite: `TLS_AES_128_GCM_SHA256` (`0x1301`).
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 Cipher Suite: `TLS_AES_256_GCM_SHA384` (`0x1302`).
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// TLS 1.3 Cipher Suite: `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`).
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Named Group: `x25519` (`0x001D`).
pub const NAMED_GROUP_X25519: u16 = 0x001D;

/// TLS Extension Type: `supported_versions` (`0x002B = 43`).
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
/// TLS Extension Type: `key_share` (`0x0033 = 51`).
pub const EXT_KEY_SHARE: u16 = 0x0033;

/// RFC 8446 Section 5.1 TLS Record ContentType.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    /// Legacy ChangeCipherSpec (`20`).
    ChangeCipherSpec = 20,
    /// Alert message (`21`).
    Alert = 21,
    /// Handshake message (`22`).
    Handshake = 22,
    /// Encrypted Application Data (`23`).
    ApplicationData = 23,
}

impl ContentType {
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// Errors encountered while parsing or building TLS 1.3 records and handshake messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsError {
    /// Buffer is shorter than the 5-byte TLS record header or declared payload length.
    TruncatedRecord,
    /// Unrecognized `ContentType` byte.
    InvalidContentType(u8),
    /// Record payload exceeds RFC 8446 limit (`16384 + 256` bytes).
    RecordOverflow(u16),
    /// Handshake message header or body is malformed or truncated.
    MalformedHandshake,
    /// Malformed `supported_versions` or `key_share` TLS extension.
    MalformedExtension,
}

/// 5-byte TLS Record Header (`content_type: u8`, `legacy_record_version: u16`, `length: u16`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsRecordHeader {
    pub content_type: ContentType,
    pub legacy_record_version: u16,
    pub length: u16,
}

impl TlsRecordHeader {
    /// Fixed length of a TLS record header in bytes.
    pub const LEN: usize = 5;
    /// Maximum TLS 1.3 ciphertext record payload length (`2^14 + 256 = 16640`).
    pub const MAX_PAYLOAD_LEN: u16 = 16_640;

    /// Parses a 5-byte `TlsRecordHeader` and returns `(header, fragment_slice)`.
    pub fn parse_record(buf: &[u8]) -> Result<(Self, &[u8]), TlsError> {
        if buf.len() < Self::LEN {
            return Err(TlsError::TruncatedRecord);
        }
        let content_type =
            ContentType::from_u8(buf[0]).ok_or(TlsError::InvalidContentType(buf[0]))?;
        let legacy_record_version = u16::from_be_bytes([buf[1], buf[2]]);
        let length = u16::from_be_bytes([buf[3], buf[4]]);
        if length > Self::MAX_PAYLOAD_LEN {
            return Err(TlsError::RecordOverflow(length));
        }
        let end = Self::LEN + (length as usize);
        if buf.len() < end {
            return Err(TlsError::TruncatedRecord);
        }
        Ok((
            Self {
                content_type,
                legacy_record_version,
                length,
            },
            &buf[Self::LEN..end],
        ))
    }

    /// Wraps `fragment` inside a 5-byte TLS record header.
    pub fn wrap_record(content_type: ContentType, fragment: &[u8]) -> Result<Vec<u8>, TlsError> {
        if fragment.len() > Self::MAX_PAYLOAD_LEN as usize {
            return Err(TlsError::RecordOverflow(fragment.len() as u16));
        }
        let mut out = Vec::with_capacity(Self::LEN + fragment.len());
        out.push(content_type as u8);
        out.extend_from_slice(&TLS_LEGACY_VERSION_1_2.to_be_bytes());
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        Ok(out)
    }
}

/// TLS 1.3 KeyShare Entry (`group: u16`, `key_exchange: Vec<u8>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

/// TLS 1.3 `ClientHello` Handshake Message (Type `1`) with `supported_versions` and `key_share`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsClientHello {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub key_shares: Vec<KeyShareEntry>,
}

impl TlsClientHello {
    /// Encodes this `ClientHello` as a TLS Handshake message (`msg_type = 1`, 24-bit length, body).
    pub fn encode_handshake(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_LEGACY_VERSION_1_2.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);

        let cs_bytes_len = (self.cipher_suites.len() * 2) as u16;
        body.extend_from_slice(&cs_bytes_len.to_be_bytes());
        for &cs in &self.cipher_suites {
            body.extend_from_slice(&cs.to_be_bytes());
        }

        // Legacy compression_methods = [0x01, 0x00] (null compression).
        body.extend_from_slice(&[1, 0]);

        // Build extensions block: supported_versions (0x002B) and key_share (0x0033).
        let mut exts = Vec::new();

        if !self.supported_versions.is_empty() {
            exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
            let list_bytes = (self.supported_versions.len() * 2) as u8;
            exts.extend_from_slice(&((list_bytes as u16) + 1).to_be_bytes());
            exts.push(list_bytes);
            for &v in &self.supported_versions {
                exts.extend_from_slice(&v.to_be_bytes());
            }
        }

        if !self.key_shares.is_empty() {
            let mut ks_list = Vec::new();
            for ks in &self.key_shares {
                ks_list.extend_from_slice(&ks.group.to_be_bytes());
                ks_list.extend_from_slice(&(ks.key_exchange.len() as u16).to_be_bytes());
                ks_list.extend_from_slice(&ks.key_exchange);
            }
            exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
            exts.extend_from_slice(&((ks_list.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(ks_list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&ks_list);
        }

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::with_capacity(4 + body.len());
        hs.push(1); // HandshakeType::client_hello (1)
        let len24 = body.len() as u32;
        hs.push(((len24 >> 16) & 0xFF) as u8);
        hs.push(((len24 >> 8) & 0xFF) as u8);
        hs.push((len24 & 0xFF) as u8);
        hs.extend_from_slice(&body);
        hs
    }

    /// Parses a `TlsClientHello` from a Handshake message buffer (`msg_type == 1`).
    pub fn parse_handshake(hs: &[u8]) -> Result<Self, TlsError> {
        if hs.len() < 4 || hs[0] != 1 {
            return Err(TlsError::MalformedHandshake);
        }
        let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
        if hs.len() < 4 + body_len {
            return Err(TlsError::MalformedHandshake);
        }
        let b = &hs[4..4 + body_len];
        if b.len() < 35 {
            return Err(TlsError::MalformedHandshake);
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&b[2..34]);
        let sid_len = b[34] as usize;
        let mut pos = 35;
        if pos + sid_len + 2 > b.len() {
            return Err(TlsError::MalformedHandshake);
        }
        let session_id = b[pos..pos + sid_len].to_vec();
        pos += sid_len;

        let cs_len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
        pos += 2;
        if cs_len == 0 || cs_len % 2 != 0 || pos + cs_len + 1 > b.len() {
            return Err(TlsError::MalformedHandshake);
        }
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        for chunk in b[pos..pos + cs_len].chunks_exact(2) {
            cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        pos += cs_len;

        let comp_len = b[pos] as usize;
        pos += 1 + comp_len;
        if pos + 2 > b.len() {
            return Err(TlsError::MalformedHandshake);
        }
        let exts_len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
        pos += 2;
        if pos + exts_len > b.len() {
            return Err(TlsError::MalformedExtension);
        }

        let mut supported_versions = Vec::new();
        let mut key_shares = Vec::new();
        let exts_end = pos + exts_len;

        while pos + 4 <= exts_end {
            let ext_type = u16::from_be_bytes([b[pos], b[pos + 1]]);
            let ext_len = u16::from_be_bytes([b[pos + 2], b[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > exts_end {
                return Err(TlsError::MalformedExtension);
            }
            let edata = &b[pos..pos + ext_len];
            pos += ext_len;

            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    if edata.is_empty() || (edata[0] as usize) + 1 != edata.len() || edata[0] % 2 != 0
                    {
                        return Err(TlsError::MalformedExtension);
                    }
                    for vc in edata[1..].chunks_exact(2) {
                        supported_versions.push(u16::from_be_bytes([vc[0], vc[1]]));
                    }
                }
                EXT_KEY_SHARE => {
                    if edata.len() < 2 {
                        return Err(TlsError::MalformedExtension);
                    }
                    let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
                    if 2 + list_len != edata.len() {
                        return Err(TlsError::MalformedExtension);
                    }
                    let mut kp = 2;
                    while kp + 4 <= edata.len() {
                        let group = u16::from_be_bytes([edata[kp], edata[kp + 1]]);
                        let klen = u16::from_be_bytes([edata[kp + 2], edata[kp + 3]]) as usize;
                        kp += 4;
                        if kp + klen > edata.len() {
                            return Err(TlsError::MalformedExtension);
                        }
                        key_shares.push(KeyShareEntry {
                            group,
                            key_exchange: edata[kp..kp + klen].to_vec(),
                        });
                        kp += klen;
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            random,
            session_id,
            cipher_suites,
            supported_versions,
            key_shares,
        })
    }
}

/// TLS 1.3 `ServerHello` Handshake Message (Type `2`) with selected version and server `key_share`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsServerHello {
    pub random: [u8; 32],
    pub session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub selected_version: u16,
    pub server_key_share: KeyShareEntry,
}

impl TlsServerHello {
    /// Encodes this `ServerHello` as a TLS Handshake message (`msg_type = 2`).
    pub fn encode_handshake(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_LEGACY_VERSION_1_2.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(self.session_id_echo.len() as u8);
        body.extend_from_slice(&self.session_id_echo);
        body.extend_from_slice(&self.cipher_suite.to_be_bytes());
        body.push(0); // legacy_compression_method = 0

        let mut exts = Vec::new();
        // supported_versions (ServerHello form: 2-byte selected_version)
        exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&self.selected_version.to_be_bytes());

        // key_share (ServerHello form: single KeyShareEntry)
        let klen = self.server_key_share.key_exchange.len() as u16;
        exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&(4 + klen).to_be_bytes());
        exts.extend_from_slice(&self.server_key_share.group.to_be_bytes());
        exts.extend_from_slice(&klen.to_be_bytes());
        exts.extend_from_slice(&self.server_key_share.key_exchange);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::with_capacity(4 + body.len());
        hs.push(2); // HandshakeType::server_hello (2)
        let len24 = body.len() as u32;
        hs.push(((len24 >> 16) & 0xFF) as u8);
        hs.push(((len24 >> 8) & 0xFF) as u8);
        hs.push((len24 & 0xFF) as u8);
        hs.extend_from_slice(&body);
        hs
    }

    /// Parses a `TlsServerHello` from a Handshake message buffer (`msg_type == 2`).
    pub fn parse_handshake(hs: &[u8]) -> Result<Self, TlsError> {
        if hs.len() < 4 || hs[0] != 2 {
            return Err(TlsError::MalformedHandshake);
        }
        let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
        if hs.len() < 4 + body_len {
            return Err(TlsError::MalformedHandshake);
        }
        let b = &hs[4..4 + body_len];
        if b.len() < 38 {
            return Err(TlsError::MalformedHandshake);
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&b[2..34]);
        let sid_len = b[34] as usize;
        let mut pos = 35;
        if pos + sid_len + 5 > b.len() {
            return Err(TlsError::MalformedHandshake);
        }
        let session_id_echo = b[pos..pos + sid_len].to_vec();
        pos += sid_len;

        let cipher_suite = u16::from_be_bytes([b[pos], b[pos + 1]]);
        pos += 3; // skip cipher_suite (2) + legacy_compression_method (1)

        let exts_len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
        pos += 2;
        if pos + exts_len > b.len() {
            return Err(TlsError::MalformedExtension);
        }

        let mut selected_version = 0u16;
        let mut server_key_share = None;
        let exts_end = pos + exts_len;

        while pos + 4 <= exts_end {
            let ext_type = u16::from_be_bytes([b[pos], b[pos + 1]]);
            let ext_len = u16::from_be_bytes([b[pos + 2], b[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > exts_end {
                return Err(TlsError::MalformedExtension);
            }
            let edata = &b[pos..pos + ext_len];
            pos += ext_len;

            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    if edata.len() != 2 {
                        return Err(TlsError::MalformedExtension);
                    }
                    selected_version = u16::from_be_bytes([edata[0], edata[1]]);
                }
                EXT_KEY_SHARE => {
                    if edata.len() < 4 {
                        return Err(TlsError::MalformedExtension);
                    }
                    let group = u16::from_be_bytes([edata[0], edata[1]]);
                    let klen = u16::from_be_bytes([edata[2], edata[3]]) as usize;
                    if 4 + klen != edata.len() {
                        return Err(TlsError::MalformedExtension);
                    }
                    server_key_share = Some(KeyShareEntry {
                        group,
                        key_exchange: edata[4..].to_vec(),
                    });
                }
                _ => {}
            }
        }

        Ok(Self {
            random,
            session_id_echo,
            cipher_suite,
            selected_version,
            server_key_share: server_key_share.ok_or(TlsError::MalformedExtension)?,
        })
    }
}

/// FIPS 180-4 SHA-256 Round Constants $K_{0..63}$.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// TLS 1.3 Handshake Transcript Hash State (RFC 8446 Section 4.4.1, FIPS 180-4 SHA-256).
#[derive(Clone, Debug)]
pub struct TlsTranscriptHash {
    buffer: Vec<u8>,
}

impl TlsTranscriptHash {
    /// Creates an empty TLS 1.3 handshake transcript accumulator.
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Appends a raw Handshake message (`ClientHello`, `ServerHello`, etc.) to the transcript.
    pub fn update(&mut self, handshake_msg: &[u8]) {
        self.buffer.extend_from_slice(handshake_msg);
    }

    /// Computes the current 32-byte SHA-256 `Transcript-Hash(M1 || M2 || ...)` without consuming state.
    pub fn current_hash(&self) -> [u8; 32] {
        sha256_digest(&self.buffer)
    }
}

impl Default for TlsTranscriptHash {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes a standard FIPS 180-4 SHA-256 32-byte digest.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Runs self-tests for the `tls_record` module.
pub fn verify_net_tls_record() -> u32 {
    let mut passed = 0u32;

    // 1. Verify FIPS 180-4 SHA-256 test vector for ASCII "abc".
    let abc_hash = sha256_digest(b"abc");
    if abc_hash[0..4] == [0xBA, 0x78, 0x16, 0xBF] && abc_hash[28..32] == [0xF2, 0x00, 0x15, 0xAD] {
        passed += 1;
    }

    // 2. Build and parse a TLS 1.3 ClientHello wrapped in a TLS Record header.
    let ch = TlsClientHello {
        random: [0x11; 32],
        session_id: alloc::vec![0xAA; 32],
        cipher_suites: alloc::vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256],
        supported_versions: alloc::vec![TLS_VERSION_1_3],
        key_shares: alloc::vec![KeyShareEntry {
            group: NAMED_GROUP_X25519,
            key_exchange: alloc::vec![0x42; 32],
        }],
    };
    let ch_hs = ch.encode_handshake();
    let mut transcript = TlsTranscriptHash::new();
    transcript.update(&ch_hs);

    if let Ok(rec) = TlsRecordHeader::wrap_record(ContentType::Handshake, &ch_hs) {
        if let Ok((hdr, frag)) = TlsRecordHeader::parse_record(&rec) {
            if hdr.content_type == ContentType::Handshake
                && TlsClientHello::parse_handshake(frag) == Ok(ch)
            {
                passed += 1;
            }
        }
    }

    // 3. Build and parse a TLS 1.3 ServerHello with selected_version 0x0304 and x25519 key_share.
    let sh = TlsServerHello {
        random: [0x22; 32],
        session_id_echo: alloc::vec![0xAA; 32],
        cipher_suite: TLS_AES_128_GCM_SHA256,
        selected_version: TLS_VERSION_1_3,
        server_key_share: KeyShareEntry {
            group: NAMED_GROUP_X25519,
            key_exchange: alloc::vec![0x99; 32],
        },
    };
    let sh_hs = sh.encode_handshake();
    if TlsServerHello::parse_handshake(&sh_hs) == Ok(sh) {
        passed += 1;
    }

    // 4. Verify transcript hash state changes deterministically upon appending ServerHello.
    let h1 = transcript.current_hash();
    transcript.update(&sh_hs);
    let h2 = transcript.current_hash();
    if h1 != h2 && h2 == sha256_digest(&[ch_hs.as_slice(), sh_hs.as_slice()].concat()) {
        passed += 1;
    }

    passed
}
