//! Stateless TCP SYN flood defense (`SynCookieEngine`).
//!
//! Uses keyed SipHash-2-4 to encode and validate client/server IPv4+port tuples,
//! a 60-second time counter (`count`), and an 8-entry Maximum Segment Size (`MSS`) table index
//! inside the 32-bit TCP Initial Sequence Number (`ISN`), per Linux `net/ipv4/syncookies.c`.

/// 8-entry standard TCP Maximum Segment Size (`MSS`) table (in bytes) encoded in the 3-bit SYN cookie MSS index.
pub const SYN_COOKIE_MSS_TABLE: [u16; 8] = [536, 1200, 1360, 1400, 1440, 1460, 4312, 8960];

/// Maximum age (in 60-second counter ticks) accepted when validating an incoming ACK cookie (240 seconds).
pub const MAX_SYN_COOKIE_AGE_TICKS: u32 = 4;

/// Genuine keyed SipHash-2-4 pseudorandom function (Aumasson & Bernstein).
pub struct SipHasher24 {
    v_a: u64,
    v_b: u64,
    v_c: u64,
    v_d: u64,
}

impl SipHasher24 {
    #[inline]
    pub const fn new(key_lo: u64, key_hi: u64) -> Self {
        Self {
            v_a: key_lo ^ 0x736f6d6570736575,
            v_b: key_hi ^ 0x646f72616e646f6d,
            v_c: key_lo ^ 0x6c7967656e657261,
            v_d: key_hi ^ 0x7465646279746573,
        }
    }

    #[inline]
    fn sip_round(&mut self) {
        self.v_a = self.v_a.wrapping_add(self.v_b);
        self.v_b = self.v_b.rotate_left(13);
        self.v_b ^= self.v_a;
        self.v_a = self.v_a.rotate_left(32);

        self.v_c = self.v_c.wrapping_add(self.v_d);
        self.v_d = self.v_d.rotate_left(16);
        self.v_d ^= self.v_c;

        self.v_a = self.v_a.wrapping_add(self.v_d);
        self.v_d = self.v_d.rotate_left(21);
        self.v_d ^= self.v_a;

        self.v_c = self.v_c.wrapping_add(self.v_b);
        self.v_b = self.v_b.rotate_left(17);
        self.v_b ^= self.v_c;
        self.v_c = self.v_c.rotate_left(32);
    }

    #[inline]
    pub fn absorb_u64(&mut self, word: u64) {
        self.v_d ^= word;
        self.sip_round();
        self.sip_round();
        self.v_a ^= word;
    }

    #[inline]
    pub fn finish(mut self, byte_len: u8) -> u64 {
        let b = (byte_len as u64) << 56;
        self.v_d ^= b;
        self.sip_round();
        self.sip_round();
        self.v_a ^= b;

        self.v_c ^= 0xff;
        self.sip_round();
        self.sip_round();
        self.sip_round();
        self.sip_round();

        self.v_a ^ self.v_b ^ self.v_c ^ self.v_d
    }
}

/// Connection 4-tuple identifying a TCP endpoint pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpEndpointTuple {
    pub client_ipv4: u32,
    pub server_ipv4: u32,
    pub client_port: u16,
    pub server_port: u16,
}

/// Stateless TCP SYN cookie generator and validator.
pub struct SynCookieEngine {
    key_first_lo: u64,
    key_first_hi: u64,
    key_second_lo: u64,
    key_second_hi: u64,
    pub cookies_issued: u64,
    pub cookies_validated: u64,
    pub cookies_rejected: u64,
}

impl SynCookieEngine {
    pub const fn new(
        key_first_lo: u64,
        key_first_hi: u64,
        key_second_lo: u64,
        key_second_hi: u64,
    ) -> Self {
        Self {
            key_first_lo,
            key_first_hi,
            key_second_lo,
            key_second_hi,
            cookies_issued: 0,
            cookies_validated: 0,
            cookies_rejected: 0,
        }
    }

    /// Selects the largest `SYN_COOKIE_MSS_TABLE` index whose MSS does not exceed `advertised_mss`.
    pub fn select_mss_index(advertised_mss: u16) -> u8 {
        let mut best_idx = 0u8;
        for (i, &table_mss) in SYN_COOKIE_MSS_TABLE.iter().enumerate() {
            if advertised_mss >= table_mss {
                best_idx = i as u8;
            } else {
                break;
            }
        }
        best_idx
    }

    fn cookie_hash(
        key_lo: u64,
        key_hi: u64,
        tuple: &TcpEndpointTuple,
        count: u32,
        extra: u32,
    ) -> u32 {
        let mut hasher = SipHasher24::new(key_lo, key_hi);
        let addr_word = ((tuple.client_ipv4 as u64) << 32) | (tuple.server_ipv4 as u64);
        let port_count_word = ((tuple.client_port as u64) << 48)
            | ((tuple.server_port as u64) << 32)
            | (count as u64);
        hasher.absorb_u64(addr_word);
        hasher.absorb_u64(port_count_word);
        hasher.absorb_u64(extra as u64);
        (hasher.finish(24) & 0xFFFF_FFFF) as u32
    }

    /// Encodes a stateless 32-bit TCP Initial Sequence Number (`ISN`) cookie for an incoming SYN segment.
    ///
    /// Cookie layout (following Linux `cookie_hash` construction):
    /// `ISN = H1(tuple, 0, 0) + client_isn + (count << 24) + ((H2(tuple, count, 1) + mss_ind) & 0x00FF_FFFF)`
    pub fn generate_syn_cookie(
        &mut self,
        tuple: &TcpEndpointTuple,
        client_isn: u32,
        advertised_mss: u16,
        now_epoch_secs: u64,
    ) -> u32 {
        let count = (now_epoch_secs / 60) as u32;
        let mss_ind = Self::select_mss_index(advertised_mss) as u32;

        let h1 = Self::cookie_hash(self.key_first_lo, self.key_first_hi, tuple, 0, 0);
        let h2 = Self::cookie_hash(self.key_second_lo, self.key_second_hi, tuple, count, 1);

        self.cookies_issued += 1;

        let low24 = (h2.wrapping_add(mss_ind)) & 0x00FF_FFFF;
        h1.wrapping_add(client_isn)
            .wrapping_add(count << 24)
            .wrapping_add(low24)
    }

    /// Validates an incoming ACK's `ack_seq - 1` (`cookie_isn`) and `seq - 1` (`client_isn`),
    /// returning the negotiated MSS from `SYN_COOKIE_MSS_TABLE` if authentic and within the 4-tick window.
    pub fn validate_ack_cookie(
        &mut self,
        tuple: &TcpEndpointTuple,
        client_isn: u32,
        cookie_isn: u32,
        now_epoch_secs: u64,
    ) -> Option<u16> {
        let current_count = (now_epoch_secs / 60) as u32;
        let h1 = Self::cookie_hash(self.key_first_lo, self.key_first_hi, tuple, 0, 0);
        let stripped = cookie_isn.wrapping_sub(h1).wrapping_sub(client_isn);

        let cookie_count = stripped >> 24;
        let current_count_byte = current_count & 0xFF;
        let age_ticks = current_count_byte.wrapping_sub(cookie_count) & 0xFF;

        if age_ticks >= MAX_SYN_COOKIE_AGE_TICKS {
            self.cookies_rejected += 1;
            return None;
        }

        let reconstructed_count = current_count.wrapping_sub(age_ticks);
        let h2 = Self::cookie_hash(
            self.key_second_lo,
            self.key_second_hi,
            tuple,
            reconstructed_count,
            1,
        );
        let mss_ind = (stripped.wrapping_sub(h2)) & 0x00FF_FFFF;

        if mss_ind < (SYN_COOKIE_MSS_TABLE.len() as u32) {
            self.cookies_validated += 1;
            Some(SYN_COOKIE_MSS_TABLE[mss_ind as usize])
        } else {
            self.cookies_rejected += 1;
            None
        }
    }
}
