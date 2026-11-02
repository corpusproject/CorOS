//! IPsec (Internet Protocol Security) Engine for CorOS.
//!
//! Implements RFC 4301 (Security Architecture for IP), RFC 4302 (Authentication Header - AH),
//! RFC 4303 (Encapsulating Security Payload - ESP), Security Policy Database (SPD),
//! Security Association Database (SAD), anti-replay sliding window, and AES-GCM-128/256 AEAD.

#![allow(dead_code)]

use alloc::vec::Vec;
use crate::crypto::aes_gcm::AesGcm;
use crate::crypto::sha256::HmacSha256;

/// IP Protocol numbers for IPsec
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;

/// IPsec Operating Mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecMode {
    /// Protects inner L4 payload while keeping original IP header
    Transport,
    /// Encapsulates full original IP packet inside a new outer IP header
    Tunnel {
        tunnel_src: [u8; 4],
        tunnel_dst: [u8; 4],
    },
}

/// Supported Cryptographic Suites
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpsecCipherSuite {
    /// AES-128-GCM with 16-byte ICV tag and 12-byte IV (RFC 4106)
    Aes128Gcm { key: [u8; 16], salt: [u8; 4] },
    /// AES-256-GCM with 16-byte ICV tag and 12-byte IV (RFC 4106)
    Aes256Gcm { key: [u8; 32], salt: [u8; 4] },
    /// HMAC-SHA256-128 Authentication only (RFC 4868)
    HmacSha256 { key: Vec<u8> },
}

/// Anti-Replay Sliding Window (64-packet window, RFC 4303 Appendix C)
#[derive(Debug, Clone, Copy)]
pub struct AntiReplayWindow {
    pub window_size: u32,
    pub bitmap: u64,
    pub last_seq: u32,
}

impl AntiReplayWindow {
    pub const fn new() -> Self {
        Self {
            window_size: 64,
            bitmap: 0,
            last_seq: 0,
        }
    }

    /// Check if a received sequence number is valid and not replayed
    pub fn check(&self, seq: u32) -> bool {
        if seq == 0 {
            return false; // Sequence number 0 is prohibited in RFC 4303
        }

        if seq > self.last_seq {
            true // Ahead of window, valid
        } else {
            let diff = self.last_seq - seq;
            if diff >= self.window_size {
                false // Too old, dropped
            } else {
                (self.bitmap & (1u64 << diff)) == 0 // Check if already seen
            }
        }
    }

    /// Update window state after packet successfully passes authentication
    pub fn update(&mut self, seq: u32) {
        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff < self.window_size {
                self.bitmap <<= diff;
            } else {
                self.bitmap = 0;
            }
            self.bitmap |= 1;
            self.last_seq = seq;
        } else {
            let diff = self.last_seq - seq;
            if diff < self.window_size {
                self.bitmap |= 1u64 << diff;
            }
        }
    }
}

/// ESP Packet Header (RFC 4303)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspHeader {
    pub spi: u32,
    pub seq_no: u32,
}

impl EspHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let spi = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let seq_no = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(Self { spi, seq_no })
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.spi.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq_no.to_be_bytes());
    }
}

/// AH (Authentication Header, RFC 4302)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhHeader {
    pub next_header: u8,
    pub payload_len: u8, // In 4-byte units, minus 2
    pub reserved: u16,
    pub spi: u32,
    pub seq_no: u32,
}

impl AhHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        Some(Self {
            next_header: buf[0],
            payload_len: buf[1],
            reserved: u16::from_be_bytes([buf[2], buf[3]]),
            spi: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            seq_no: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}

/// Security Association (SA) representing a unidirectional cryptographic pipeline
pub struct SecurityAssociation {
    pub spi: u32,
    pub mode: IpsecMode,
    pub cipher_suite: IpsecCipherSuite,
    pub seq_counter: u32,
    pub anti_replay: AntiReplayWindow,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub lifetime_bytes: u64,
    pub is_outbound: bool,
}

impl SecurityAssociation {
    pub fn new(spi: u32, mode: IpsecMode, cipher_suite: IpsecCipherSuite, is_outbound: bool) -> Self {
        Self {
            spi,
            mode,
            cipher_suite,
            seq_counter: 0,
            anti_replay: AntiReplayWindow::new(),
            packets_processed: 0,
            bytes_processed: 0,
            lifetime_bytes: 1_000_000_000, // 1 GB default lifetime
            is_outbound,
        }
    }

    /// Encapsulate and encrypt an outgoing packet with ESP
    pub fn encapsulate_esp(&mut self, payload: &[u8], next_header: u8) -> Result<Vec<u8>, &'static str> {
        self.seq_counter = self.seq_counter.checked_add(1).ok_or("Sequence number overflow")?;
        let current_seq = self.seq_counter;

        // ESP Trailer requires padding to align to 4 bytes (or AES block size 16)
        // Payload + Pad + PadLen(1) + NextHeader(1) must be a multiple of 4 (or 16 for AES-CBC)
        let unpadded_len = payload.len() + 2; // + pad_len byte + next_header byte
        let pad_len = (16 - (unpadded_len % 16)) % 16;

        let mut plaintext = Vec::with_capacity(payload.len() + pad_len + 2);
        plaintext.extend_from_slice(payload);
        for i in 1..=pad_len {
            plaintext.push(i as u8); // RFC standard padding sequence (1, 2, 3...)
        }
        plaintext.push(pad_len as u8);
        plaintext.push(next_header);

        // Prepare ESP Header (SPI + Seq)
        let mut esp_header = [0u8; 8];
        esp_header[0..4].copy_from_slice(&self.spi.to_be_bytes());
        esp_header[4..8].copy_from_slice(&current_seq.to_be_bytes());

        match &self.cipher_suite {
            IpsecCipherSuite::Aes128Gcm { key, salt } => {
                // In RFC 4106 AES-GCM: 12-byte IV consists of 4-byte Salt + 8-byte Explicit IV
                let mut explicit_iv = [0u8; 8];
                explicit_iv[0..4].copy_from_slice(&current_seq.to_be_bytes());
                explicit_iv[4..8].copy_from_slice(&(!current_seq).to_be_bytes());

                let mut nonce = [0u8; 12];
                nonce[0..4].copy_from_slice(salt);
                nonce[4..12].copy_from_slice(&explicit_iv);

                // AAD (Additional Authenticated Data) is the 8-byte ESP header
                let gcm = AesGcm::new_aes128(key);
                let (ciphertext, tag) = gcm.encrypt(&nonce, &esp_header, &plaintext);

                let mut packet = Vec::with_capacity(8 + 8 + ciphertext.len() + 16);
                packet.extend_from_slice(&esp_header);
                packet.extend_from_slice(&explicit_iv);
                packet.extend_from_slice(&ciphertext);
                packet.extend_from_slice(&tag);

                self.packets_processed += 1;
                self.bytes_processed += packet.len() as u64;
                Ok(packet)
            }
            IpsecCipherSuite::Aes256Gcm { key, salt } => {
                let mut explicit_iv = [0u8; 8];
                explicit_iv[0..4].copy_from_slice(&current_seq.to_be_bytes());
                explicit_iv[4..8].copy_from_slice(&(!current_seq).to_be_bytes());

                let mut nonce = [0u8; 12];
                nonce[0..4].copy_from_slice(salt);
                nonce[4..12].copy_from_slice(&explicit_iv);

                let gcm = AesGcm::new_aes256(key);
                let (ciphertext, tag) = gcm.encrypt(&nonce, &esp_header, &plaintext);

                let mut packet = Vec::with_capacity(8 + 8 + ciphertext.len() + 16);
                packet.extend_from_slice(&esp_header);
                packet.extend_from_slice(&explicit_iv);
                packet.extend_from_slice(&ciphertext);
                packet.extend_from_slice(&tag);

                self.packets_processed += 1;
                self.bytes_processed += packet.len() as u64;
                Ok(packet)
            }
            IpsecCipherSuite::HmacSha256 { key } => {
                // Plaintext ESP (Null encryption) with HMAC-SHA256 authentication
                let mut hmac = HmacSha256::new(key);
                hmac.update(&esp_header);
                hmac.update(&plaintext);
                let auth_tag = hmac.finalize();

                let mut packet = Vec::with_capacity(8 + plaintext.len() + 16);
                packet.extend_from_slice(&esp_header);
                packet.extend_from_slice(&plaintext);
                packet.extend_from_slice(&auth_tag[..16]); // Truncated to 128-bit ICV

                self.packets_processed += 1;
                self.bytes_processed += packet.len() as u64;
                Ok(packet)
            }
        }
    }

    /// Decrypt and verify an incoming ESP packet
    pub fn decapsulate_esp(&mut self, esp_packet: &[u8]) -> Result<(Vec<u8>, u8), &'static str> {
        if esp_packet.len() < 8 + 16 {
            return Err("ESP packet too short");
        }

        let hdr = EspHeader::parse(esp_packet).ok_or("Failed to parse ESP header")?;
        if hdr.spi != self.spi {
            return Err("SPI mismatch");
        }

        // Anti-replay check
        if !self.anti_replay.check(hdr.seq_no) {
            return Err("Replay attack detected: sequence number rejected");
        }

        let (decrypted, next_header) = match &self.cipher_suite {
            IpsecCipherSuite::Aes128Gcm { key, salt } => {
                if esp_packet.len() < 8 + 8 + 16 {
                    return Err("Packet too short for AES-GCM IV and ICV");
                }
                let explicit_iv = &esp_packet[8..16];
                let ciphertext_and_tag = &esp_packet[16..];
                let ct_len = ciphertext_and_tag.len() - 16;
                let ciphertext = &ciphertext_and_tag[..ct_len];
                let tag = &ciphertext_and_tag[ct_len..];

                let mut nonce = [0u8; 12];
                nonce[0..4].copy_from_slice(salt);
                nonce[4..12].copy_from_slice(explicit_iv);

                let mut tag16 = [0u8; 16];
                tag16.copy_from_slice(tag);

                let gcm = AesGcm::new_aes128(key);
                let plaintext = gcm.decrypt(&nonce, &esp_packet[..8], ciphertext, &tag16)?;

                if plaintext.len() < 2 {
                    return Err("Decrypted ESP payload too small for trailer");
                }
                let pad_len = plaintext[plaintext.len() - 2] as usize;
                let next_hdr = plaintext[plaintext.len() - 1];

                if plaintext.len() < 2 + pad_len {
                    return Err("Invalid ESP pad length");
                }
                let payload_len = plaintext.len() - 2 - pad_len;
                (plaintext[..payload_len].to_vec(), next_hdr)
            }
            IpsecCipherSuite::Aes256Gcm { key, salt } => {
                if esp_packet.len() < 8 + 8 + 16 {
                    return Err("Packet too short for AES-256-GCM IV and ICV");
                }
                let explicit_iv = &esp_packet[8..16];
                let ciphertext_and_tag = &esp_packet[16..];
                let ct_len = ciphertext_and_tag.len() - 16;
                let ciphertext = &ciphertext_and_tag[..ct_len];
                let tag = &ciphertext_and_tag[ct_len..];

                let mut nonce = [0u8; 12];
                nonce[0..4].copy_from_slice(salt);
                nonce[4..12].copy_from_slice(explicit_iv);

                let mut tag16 = [0u8; 16];
                tag16.copy_from_slice(tag);

                let gcm = AesGcm::new_aes256(key);
                let plaintext = gcm.decrypt(&nonce, &esp_packet[..8], ciphertext, &tag16)?;

                if plaintext.len() < 2 {
                    return Err("Decrypted ESP payload too small for trailer");
                }
                let pad_len = plaintext[plaintext.len() - 2] as usize;
                let next_hdr = plaintext[plaintext.len() - 1];

                if plaintext.len() < 2 + pad_len {
                    return Err("Invalid ESP pad length");
                }
                let payload_len = plaintext.len() - 2 - pad_len;
                (plaintext[..payload_len].to_vec(), next_hdr)
            }
            IpsecCipherSuite::HmacSha256 { key } => {
                let icv_offset = esp_packet.len() - 16;
                let data_to_auth = &esp_packet[..icv_offset];
                let received_icv = &esp_packet[icv_offset..];

                let mut hmac = HmacSha256::new(key);
                hmac.update(data_to_auth);
                let computed_tag = hmac.finalize();

                if &computed_tag[..16] != received_icv {
                    return Err("HMAC-SHA256 authentication verification failed");
                }

                let payload_with_trailer = &esp_packet[8..icv_offset];
                if payload_with_trailer.len() < 2 {
                    return Err("Payload too small for trailer");
                }
                let pad_len = payload_with_trailer[payload_with_trailer.len() - 2] as usize;
                let next_hdr = payload_with_trailer[payload_with_trailer.len() - 1];

                if payload_with_trailer.len() < 2 + pad_len {
                    return Err("Invalid ESP pad length");
                }
                let payload_len = payload_with_trailer.len() - 2 - pad_len;
                (payload_with_trailer[..payload_len].to_vec(), next_hdr)
            }
        };

        // Authentication succeeded -> Update anti-replay window
        self.anti_replay.update(hdr.seq_no);
        self.packets_processed += 1;
        self.bytes_processed += esp_packet.len() as u64;

        Ok((decrypted, next_header))
    }
}

/// Security Policy Action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Deliver without security processing
    Bypass,
    /// Silently drop the packet
    Discard,
    /// Apply IPsec protection using the matching SA
    Protect { spi: u32 },
}

/// Security Policy Entry (SPD)
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub priority: u32,
    pub src_subnet: [u8; 4],
    pub src_mask: u8,
    pub dst_subnet: [u8; 4],
    pub dst_mask: u8,
    pub proto: Option<u8>,
    pub action: PolicyAction,
}

impl SecurityPolicy {
    fn matches_ip(ip: [u8; 4], subnet: [u8; 4], mask_bits: u8) -> bool {
        if mask_bits == 0 {
            return true;
        }
        let mask = !((1u32 << (32 - mask_bits)) - 1);
        let ip_val = u32::from_be_bytes(ip);
        let sub_val = u32::from_be_bytes(subnet);
        (ip_val & mask) == (sub_val & mask)
    }

    pub fn matches(&self, src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8) -> bool {
        if !Self::matches_ip(src_ip, self.src_subnet, self.src_mask) {
            return false;
        }
        if !Self::matches_ip(dst_ip, self.dst_subnet, self.dst_mask) {
            return false;
        }
        if let Some(p) = self.proto {
            if p != proto {
                return false;
            }
        }
        true
    }
}

/// IPsec Security Subsystem Engine
pub struct IpsecEngine {
    pub spd: Vec<SecurityPolicy>,
    pub sad: Vec<SecurityAssociation>,
}

impl IpsecEngine {
    pub fn new() -> Self {
        Self {
            spd: Vec::new(),
            sad: Vec::new(),
        }
    }

    /// Add a policy to the Security Policy Database (SPD)
    pub fn add_policy(&mut self, policy: SecurityPolicy) {
        let idx = self.spd.iter().position(|p| p.priority < policy.priority).unwrap_or(self.spd.len());
        self.spd.insert(idx, policy);
    }

    /// Add an SA to the Security Association Database (SAD)
    pub fn add_sa(&mut self, sa: SecurityAssociation) {
        self.sad.push(sa);
    }

    /// Lookup outgoing policy for a packet
    pub fn lookup_policy(&self, src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8) -> PolicyAction {
        for policy in &self.spd {
            if policy.matches(src_ip, dst_ip, proto) {
                return policy.action;
            }
        }
        PolicyAction::Bypass
    }

    /// Find an SA by SPI
    pub fn get_sa_mut(&mut self, spi: u32) -> Option<&mut SecurityAssociation> {
        self.sad.iter_mut().find(|sa| sa.spi == spi)
    }
}
