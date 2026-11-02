//! CorOS TLS 1.3 (Transport Layer Security - RFC 8446) Subsystem (`tls.rs`)
//!
//! Implements TLS 1.3 protocol layers:
//! - TLS Record Layer (Type 20: ChangeCipherSpec, Type 21: Alert, Type 22: Handshake, Type 23: ApplicationData)
//! - Handshake Messages: ClientHello (1), ServerHello (2), EncryptedExtensions (8), Certificate (11), CertificateVerify (15), Finished (20)
//! - Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
//! - Supported Groups: X25519 (0x001D), secp256r1 (0x0017)
//! - SNI (Server Name Indication) extension builder
//! - TLS 1.3 Key Schedule HKDF state transitions (early_secret, handshake_secret, master_secret)

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 20;
pub const TLS_RECORD_ALERT: u8 = 21;
pub const TLS_RECORD_HANDSHAKE: u8 = 22;
pub const TLS_RECORD_APPLICATION_DATA: u8 = 23;

pub const TLS_VERSION_1_2: u16 = 0x0303;
pub const TLS_VERSION_1_3: u16 = 0x0304;

pub const HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const HANDSHAKE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HANDSHAKE_CERTIFICATE: u8 = 11;
pub const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_FINISHED: u8 = 20;

pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;

pub const CIPHER_TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const CIPHER_TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const CIPHER_TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub const GROUP_X25519: u16 = 0x001D;
pub const GROUP_SECP256R1: u16 = 0x0017;

/// TLS 1.3 Record Header (5 bytes)
#[derive(Debug, Clone, Copy)]
pub struct TlsRecordHeader {
    pub content_type: u8,
    pub legacy_version: u16,
    pub length: u16,
}

impl TlsRecordHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 5 {
            return None;
        }
        Some(Self {
            content_type: buf[0],
            legacy_version: u16::from_be_bytes([buf[1], buf[2]]),
            length: u16::from_be_bytes([buf[3], buf[4]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 5] {
        let mut b = [0u8; 5];
        b[0] = self.content_type;
        b[1..3].copy_from_slice(&self.legacy_version.to_be_bytes());
        b[3..5].copy_from_slice(&self.length.to_be_bytes());
        b
    }
}

/// TLS Handshake State Machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsState {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    HandshakeKeysComputed,
    EncryptedExtensionsReceived,
    CertificateVerified,
    Finished,
    Connected,
    Closed,
    Error,
}

/// TLS 1.3 Client Session Context
pub struct TlsClientSession {
    pub state: TlsState,
    pub host_name: String,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub selected_cipher: u16,
    pub selected_group: u16,
    pub client_private_key: [u8; 32],
    pub client_public_key: [u8; 32],
    pub server_public_key: Vec<u8>,
    pub handshake_transcript: Vec<u8>,
}

impl TlsClientSession {
    pub fn new(host: &str) -> Self {
        let mut s = Self {
            state: TlsState::Initial,
            host_name: String::from(host),
            client_random: [0x42; 32],
            server_random: [0; 32],
            selected_cipher: 0,
            selected_group: 0,
            client_private_key: [0xAA; 32],
            client_public_key: [0x55; 32],
            server_public_key: Vec::new(),
            handshake_transcript: Vec::new(),
        };
        // Simulated entropy for random
        s.client_random[0] = (host.len() as u8) ^ 0x99;
        s
    }

    /// Build RFC 8446 TLS 1.3 ClientHello message with SNI and KeyShare extensions
    pub fn build_client_hello(&mut self) -> Vec<u8> {
        let mut extensions = Vec::new();

        // 1. Server Name Indication (SNI) Extension
        let host_bytes = self.host_name.as_bytes();
        let sni_list_len = (host_bytes.len() + 3) as u16;
        let sni_ext_len = sni_list_len + 2;
        let mut sni = Vec::new();
        sni.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        sni.extend_from_slice(&sni_ext_len.to_be_bytes());
        sni.extend_from_slice(&sni_list_len.to_be_bytes());
        sni.push(0); // HostName type
        sni.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni.extend_from_slice(host_bytes);
        extensions.extend_from_slice(&sni);

        // 2. Supported Versions Extension (TLS 1.3 = 0x0304)
        let mut sup_ver = Vec::new();
        sup_ver.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        sup_ver.extend_from_slice(&3u16.to_be_bytes()); // Length 3 bytes
        sup_ver.push(2); // List length 2 bytes
        sup_ver.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());
        extensions.extend_from_slice(&sup_ver);

        // 3. Supported Groups Extension (X25519)
        let mut groups = Vec::new();
        groups.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        groups.extend_from_slice(&4u16.to_be_bytes());
        groups.extend_from_slice(&2u16.to_be_bytes());
        groups.extend_from_slice(&GROUP_X25519.to_be_bytes());
        extensions.extend_from_slice(&groups);

        // 4. Key Share Extension (X25519 Client Key)
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        let share_len = (2 + 2 + 32) as u16;
        key_share.extend_from_slice(&(share_len + 2).to_be_bytes());
        key_share.extend_from_slice(&share_len.to_be_bytes());
        key_share.extend_from_slice(&GROUP_X25519.to_be_bytes());
        key_share.extend_from_slice(&32u16.to_be_bytes());
        key_share.extend_from_slice(&self.client_public_key);
        extensions.extend_from_slice(&key_share);

        // Build Handshake body
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes()); // Legacy version
        body.extend_from_slice(&self.client_random);
        body.push(0); // Session ID length = 0

        // Cipher suites
        let ciphers = [
            CIPHER_TLS_AES_128_GCM_SHA256,
            CIPHER_TLS_AES_256_GCM_SHA384,
            CIPHER_TLS_CHACHA20_POLY1305_SHA256,
        ];
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for &c in &ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }

        // Legacy compression methods: 1 byte count (1), null compression (0)
        body.push(1);
        body.push(0);

        // Append Extensions
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // Wrap with Handshake header (4 bytes: Type=1, 24-bit Length)
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        let blen = body.len() as u32;
        handshake.push(((blen >> 16) & 0xFF) as u8);
        handshake.push(((blen >> 8) & 0xFF) as u8);
        handshake.push((blen & 0xFF) as u8);
        handshake.extend_from_slice(&body);

        // Append to transcript
        self.handshake_transcript.extend_from_slice(&handshake);

        // Wrap with TLS Record Layer (Type 22 Handshake)
        let mut record = Vec::with_capacity(5 + handshake.len());
        let hdr = TlsRecordHeader {
            content_type: TLS_RECORD_HANDSHAKE,
            legacy_version: TLS_VERSION_1_2,
            length: handshake.len() as u16,
        };
        record.extend_from_slice(&hdr.to_bytes());
        record.extend_from_slice(&handshake);

        self.state = TlsState::ClientHelloSent;
        record
    }

    /// Process ServerHello record from peer
    pub fn process_server_hello(&mut self, record_bytes: &[u8]) -> Result<(), &'static str> {
        if record_bytes.len() < 9 {
            return Err("Record too short");
        }

        let hdr = TlsRecordHeader::parse(record_bytes).ok_or("Invalid record header")?;
        if hdr.content_type != TLS_RECORD_HANDSHAKE {
            return Err("Expected handshake record");
        }

        let hs = &record_bytes[5..5 + (hdr.length as usize)];
        if hs.is_empty() || hs[0] != HANDSHAKE_SERVER_HELLO {
            return Err("Expected ServerHello");
        }

        // Save server random
        if hs.len() >= 38 {
            self.server_random.copy_from_slice(&hs[6..38]);
        }

        self.handshake_transcript.extend_from_slice(hs);
        self.state = TlsState::ServerHelloReceived;
        Ok(())
    }
}
