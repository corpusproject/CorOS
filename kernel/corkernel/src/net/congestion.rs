//! Advanced TCP Congestion Control Algorithms (Google BBR, CUBIC, Reno)
//!
//! Bare-metal no_std pure Rust implementation of modern TCP congestion engines:
//! - RFC 5681 TCP Reno (Slow Start, Congestion Avoidance, Fast Recovery)
//! - RFC 8312 CUBIC (Concave/Convex Cubic window growth, W_max scaling)
//! - Google BBR (Bottleneck Bandwidth and RTT: STARTUP, DRAIN, PROBE_BW, PROBE_RTT)
//! - Pacing rate calculation, RTT moving average, and delivery rate estimation

#![allow(dead_code)]

/// TCP Congestion Algorithm Selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    Reno,
    Cubic,
    Bbr,
}

/// TCP Congestion State Machine (RFC 5681 / Linux TCP State)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    Open,       // Normal packet flow, in-order ACKs
    Disorder,   // Duplicate ACKs or SACK holes detected
    Cwr,        // Congestion Window Reduced (ECN / single loss)
    Recovery,   // Fast Recovery in progress
    Loss,       // RTO timeout, cwnd reset to 1 MSS
}

/// Google BBR State Machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// Window / Rate Parameters for a TCP Connection
pub struct TcpCongestionControl {
    pub algorithm: CongestionAlgorithm,
    pub state: CongestionState,

    // Base RFC 5681 Parameters
    pub mss: u32,
    pub cwnd: u32,           // Congestion window in bytes
    pub ssthresh: u32,       // Slow start threshold in bytes
    pub rtt_us: u32,         // Latest smoothed RTT in microseconds
    pub min_rtt_us: u32,     // Minimum RTT seen (RTprop)
    pub max_bandwidth_bps: u64, // Estimated bottleneck bandwidth (BtlBw)

    // CUBIC Specific (RFC 8312)
    pub cubic_w_max: u32,    // Window size just before last reduction
    pub cubic_epoch_start_us: u64,
    pub cubic_k_us: u64,     // Time period that the cubic function takes to reach W_max

    // Google BBR Specific
    pub bbr_state: BbrState,
    pub bbr_pacing_gain: u32, // Fixed-point 8 bits (256 = 1.0x, 739 = 2.89x)
    pub bbr_cwnd_gain: u32,
    pub bbr_cycle_index: usize,
    pub bbr_cycle_stamp_us: u64,

    // Statistics
    pub packets_in_flight: u32,
    pub bytes_delivered: u64,
    pub duplicate_ack_count: u32,
}

impl TcpCongestionControl {
    pub fn new(mss: u32, algorithm: CongestionAlgorithm) -> Self {
        let initial_cwnd = mss * 10; // RFC 6928 initial window (IW10)
        Self {
            algorithm,
            state: CongestionState::Open,
            mss,
            cwnd: initial_cwnd,
            ssthresh: 65535,
            rtt_us: 100_000, // 100ms default
            min_rtt_us: u32::MAX,
            max_bandwidth_bps: 1_000_000, // 1 Mbps default
            cubic_w_max: 0,
            cubic_epoch_start_us: 0,
            cubic_k_us: 0,
            bbr_state: BbrState::Startup,
            bbr_pacing_gain: 739, // 2.89x in Startup
            bbr_cwnd_gain: 739,
            bbr_cycle_index: 0,
            bbr_cycle_stamp_us: 0,
            packets_in_flight: 0,
            bytes_delivered: 0,
            duplicate_ack_count: 0,
        }
    }

    /// Process incoming ACK and update congestion window
    pub fn on_ack_received(&mut self, bytes_acked: u32, rtt_sample_us: u32, now_us: u64) {
        self.duplicate_ack_count = 0;
        self.bytes_delivered += bytes_acked as u64;

        // Update RTT
        if rtt_sample_us < self.min_rtt_us {
            self.min_rtt_us = rtt_sample_us;
        }
        self.rtt_us = ((self.rtt_us as u64 * 7 + rtt_sample_us as u64) / 8) as u32;

        // Estimate bandwidth: bytes / RTT
        if rtt_sample_us > 0 {
            let bw_sample = (bytes_acked as u64 * 8 * 1_000_000) / (rtt_sample_us as u64);
            if bw_sample > self.max_bandwidth_bps {
                self.max_bandwidth_bps = bw_sample;
            }
        }

        match self.algorithm {
            CongestionAlgorithm::Reno => self.reno_on_ack(bytes_acked),
            CongestionAlgorithm::Cubic => self.cubic_on_ack(bytes_acked, now_us),
            CongestionAlgorithm::Bbr => self.bbr_on_ack(now_us),
        }
    }

    /// Handle duplicate ACK (Fast Retransmit / Fast Recovery)
    pub fn on_duplicate_ack(&mut self) -> bool {
        self.duplicate_ack_count += 1;
        if self.duplicate_ack_count == 3 {
            // Trigger Fast Retransmit
            self.state = CongestionState::Recovery;
            self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
            self.cwnd = self.ssthresh + 3 * self.mss;
            true // Retransmit missing segment
        } else if self.duplicate_ack_count > 3 {
            // Inflate window for each subsequent duplicate ACK
            self.cwnd += self.mss;
            false
        } else {
            false
        }
    }

    /// Handle Retransmission Timeout (RTO)
    pub fn on_timeout(&mut self) {
        self.state = CongestionState::Loss;
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
        self.cwnd = self.mss; // Reset to 1 MSS
        self.duplicate_ack_count = 0;

        if self.algorithm == CongestionAlgorithm::Cubic {
            self.cubic_w_max = self.cwnd;
        } else if self.algorithm == CongestionAlgorithm::Bbr {
            self.bbr_state = BbrState::Startup;
            self.bbr_pacing_gain = 739;
        }
    }

    // --- Reno Congestion Control (RFC 5681) ---
    fn reno_on_ack(&mut self, bytes_acked: u32) {
        if self.cwnd < self.ssthresh {
            // Slow Start: Exponential growth
            self.cwnd += bytes_acked.min(self.mss);
        } else {
            // Congestion Avoidance: Linear growth (~1 MSS per RTT)
            let increment = ((self.mss as u64 * self.mss as u64) / self.cwnd as u64) as u32;
            self.cwnd += increment.max(1);
        }
    }

    // --- CUBIC Congestion Control (RFC 8312) ---
    fn cubic_on_ack(&mut self, bytes_acked: u32, now_us: u64) {
        if self.cwnd < self.ssthresh {
            self.cwnd += bytes_acked.min(self.mss);
            return;
        }

        if self.cubic_epoch_start_us == 0 {
            self.cubic_epoch_start_us = now_us;
            if self.cwnd < self.cubic_w_max {
                // K = ((W_max - W_initial) / C)^(1/3)
                self.cubic_k_us = 1_000_000; // 1 second approximation
            } else {
                self.cubic_k_us = 0;
            }
        }

        let elapsed_us = now_us.saturating_sub(self.cubic_epoch_start_us);
        let t_diff = (elapsed_us as i64 - self.cubic_k_us as i64) / 1000; // in ms
        let cubic_offset = (t_diff * t_diff * t_diff) / 10_000;

        let target_cwnd = if cubic_offset >= 0 {
            (self.cubic_w_max as i64 + cubic_offset).max(self.mss as i64) as u32
        } else {
            (self.cubic_w_max as i64 + cubic_offset).max(self.mss as i64) as u32
        };

        if target_cwnd > self.cwnd {
            self.cwnd += ((target_cwnd - self.cwnd) / 10).max(1);
        } else {
            self.cwnd += self.mss / (self.cwnd / self.mss).max(1);
        }
    }

    // --- Google BBR Congestion Control ---
    fn bbr_on_ack(&mut self, now_us: u64) {
        // BDP = BtlBw * RTprop
        let bdp = ((self.max_bandwidth_bps as u64 * self.min_rtt_us as u64) / 8_000_000) as u32;
        let target_cwnd = ((bdp as u64 * self.bbr_cwnd_gain as u64) / 256) as u32;

        match self.bbr_state {
            BbrState::Startup => {
                self.cwnd = target_cwnd.max(4 * self.mss);
                // When pipe is full, drain excess queue
                if self.bytes_delivered > 3 * bdp as u64 {
                    self.bbr_state = BbrState::Drain;
                    self.bbr_pacing_gain = 177; // 0.7x (drain queue)
                    self.bbr_cwnd_gain = 256;
                }
            }
            BbrState::Drain => {
                self.cwnd = target_cwnd.max(4 * self.mss);
                if self.packets_in_flight <= bdp {
                    self.bbr_state = BbrState::ProbeBw;
                    self.bbr_pacing_gain = 256; // 1.0x
                    self.bbr_cycle_stamp_us = now_us;
                }
            }
            BbrState::ProbeBw => {
                // Cycle pacing gain between 1.25x, 0.75x, 1x, 1x, 1x, 1x...
                let cycle_gains = [320, 192, 256, 256, 256, 256, 256, 256];
                if now_us.saturating_sub(self.bbr_cycle_stamp_us) > self.min_rtt_us as u64 {
                    self.bbr_cycle_index = (self.bbr_cycle_index + 1) % cycle_gains.len();
                    self.bbr_pacing_gain = cycle_gains[self.bbr_cycle_index];
                    self.bbr_cycle_stamp_us = now_us;
                }
                self.cwnd = target_cwnd.max(4 * self.mss);
            }
            BbrState::ProbeRtt => {
                self.cwnd = 4 * self.mss;
                self.bbr_pacing_gain = 256;
            }
        }
    }

    /// Calculate pacing rate in bytes per second
    pub fn get_pacing_rate_bps(&self) -> u64 {
        match self.algorithm {
            CongestionAlgorithm::Bbr => {
                ((self.max_bandwidth_bps as u64 * self.bbr_pacing_gain as u64) / 256) / 8
            }
            _ => {
                // Non-BBR: cwnd / RTT
                if self.rtt_us > 0 {
                    (self.cwnd as u64 * 1_000_000) / (self.rtt_us as u64)
                } else {
                    1_000_000
                }
            }
        }
    }
}
