//! QoS Token-Bucket Policer, DiffServ DSCP Classifier (`CS0`..`CS7`, `EF`, `AF`) & Strict-Priority / WFQ Packet Scheduler.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Differentiated Services Code Point (DSCP, 6-bit value in IPv4 ToS / IPv6 Traffic Class, RFC 2474 / RFC 3246).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DscpClass {
    /// Default Best-Effort (`CS0 = 0b000000 = 0`).
    BestEffortCs0,
    /// Scavenger / Low-Priority (`CS1 = 0b001000 = 8`).
    ClassSelector1,
    /// OAM / Administration (`CS2 = 0b010000 = 16`).
    ClassSelector2,
    /// Broadcast Video / Signaling (`CS3 = 0b011000 = 24`).
    ClassSelector3,
    /// Real-Time Interactive (`CS4 = 0b100000 = 32`).
    ClassSelector4,
    /// Broadcast / Mission-Critical (`CS5 = 0b101000 = 40`).
    ClassSelector5,
    /// Internetwork Control (`CS6 = 0b110000 = 48`, e.g., BGP/OSPF).
    NetworkControlCs6,
    /// Reserved Link-Layer Control (`CS7 = 0b111000 = 56`).
    LinkControlCs7,
    /// Assured Forwarding (`AFxy`, e.g. `AF11 = 10`, `AF21 = 18`, `AF31 = 26`, `AF41 = 34`).
    AssuredForwarding { class: u8, drop_precedence: u8 },
    /// Expedited Forwarding (`EF = 0b101110 = 46`, low-latency VoIP / real-time audio).
    ExpeditedForwarding,
    /// Other 6-bit DSCP codepoint.
    Other(u8),
}

/// 4-Tier QoS Hardware Queue Priority Level (`0` = Bulk/Background .. `3` = Strict Real-Time Control).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrafficPriority {
    Bulk = 0,
    BestEffort = 1,
    Assured = 2,
    StrictRealtime = 3,
}

impl DscpClass {
    /// Decodes a raw 6-bit DSCP value (`0..=63`) into a `DscpClass`.
    pub const fn from_dscp(code: u8) -> Self {
        let dscp = code & 0x3F;
        match dscp {
            0 => Self::BestEffortCs0,
            8 => Self::ClassSelector1,
            16 => Self::ClassSelector2,
            24 => Self::ClassSelector3,
            32 => Self::ClassSelector4,
            40 => Self::ClassSelector5,
            48 => Self::NetworkControlCs6,
            56 => Self::LinkControlCs7,
            46 => Self::ExpeditedForwarding,
            // AF11..AF43: 0bXYZ_DD0 where class = XYZ (1..=4), drop_prec = DD (1..=3)
            10 | 12 | 14 | 18 | 20 | 22 | 26 | 28 | 30 | 34 | 36 | 38 => {
                let class = dscp >> 3;
                let drop_precedence = (dscp >> 1) & 0x03;
                Self::AssuredForwarding {
                    class,
                    drop_precedence,
                }
            }
            other => Self::Other(other),
        }
    }

    /// Maps this `DscpClass` to one of the four hardware `TrafficPriority` queues.
    pub const fn to_priority(self) -> TrafficPriority {
        match self {
            Self::ClassSelector1 => TrafficPriority::Bulk,
            Self::BestEffortCs0 | Self::ClassSelector2 | Self::Other(_) => {
                TrafficPriority::BestEffort
            }
            Self::ClassSelector3
            | Self::ClassSelector4
            | Self::ClassSelector5
            | Self::AssuredForwarding { .. } => TrafficPriority::Assured,
            Self::ExpeditedForwarding | Self::NetworkControlCs6 | Self::LinkControlCs7 => {
                TrafficPriority::StrictRealtime
            }
        }
    }
}

/// Token-Bucket Traffic Policer & Rate Limiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    /// Maximum burst size in bytes (bucket capacity).
    pub capacity_bytes: u64,
    /// Sustained refill rate in bytes per tick.
    pub refill_bytes_per_tick: u64,
    /// Currently available tokens in bytes.
    pub available_tokens: u64,
    /// Last tick timestamp when tokens were replenished.
    pub last_refill_tick: u64,
    /// Total packets conformed (accepted).
    pub conformed_packets: u64,
    /// Total packets exceeded (dropped/policed).
    pub exceeded_packets: u64,
}

impl TokenBucket {
    /// Creates a new `TokenBucket` initialized at full burst capacity.
    pub const fn new(capacity_bytes: u64, refill_bytes_per_tick: u64) -> Self {
        Self {
            capacity_bytes,
            refill_bytes_per_tick,
            available_tokens: capacity_bytes,
            last_refill_tick: 0,
            conformed_packets: 0,
            exceeded_packets: 0,
        }
    }

    /// Replenishes tokens up to `capacity_bytes` based on elapsed ticks since `last_refill_tick`.
    pub fn refill(&mut self, now_tick: u64) {
        if now_tick > self.last_refill_tick {
            let elapsed = now_tick - self.last_refill_tick;
            let added = elapsed.saturating_mul(self.refill_bytes_per_tick);
            self.available_tokens = self
                .available_tokens
                .saturating_add(added)
                .min(self.capacity_bytes);
            self.last_refill_tick = now_tick;
        }
    }

    /// Attempts to consume `packet_bytes` tokens at `now_tick`. Returns `true` if conforming.
    pub fn consume(&mut self, packet_bytes: usize, now_tick: u64) -> bool {
        self.refill(now_tick);
        let cost = packet_bytes as u64;
        if self.available_tokens >= cost {
            self.available_tokens -= cost;
            self.conformed_packets += 1;
            true
        } else {
            self.exceeded_packets += 1;
            false
        }
    }
}

/// Hybrid Strict-Priority (for `StrictRealtime`) + Deficit Weighted Fair Queueing (WFQ) Scheduler
/// across the lower three classes (`Bulk`, `BestEffort`, `Assured`).
#[derive(Clone, Debug)]
pub struct QosPacketScheduler {
    queues: [VecDeque<Vec<u8>>; 4],
    /// Quantum weights in bytes per WFQ round for `[Bulk, BestEffort, Assured]`.
    pub quanta: [u32; 3],
    deficits: [u32; 3],
    rr_cursor: usize,
}

impl QosPacketScheduler {
    /// Creates a new 4-class QoS scheduler with default WFQ byte quanta `[500, 1500, 4500]`.
    pub const fn new() -> Self {
        Self {
            queues: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
            quanta: [500, 1500, 4500],
            deficits: [0, 0, 0],
            rr_cursor: 2, // Start at Assured (queue 2)
        }
    }

    /// Classifies a packet by its 6-bit DSCP field and enqueues it into the appropriate priority queue.
    pub fn enqueue_by_dscp(&mut self, dscp_code: u8, packet: Vec<u8>) -> TrafficPriority {
        let prio = DscpClass::from_dscp(dscp_code).to_priority();
        self.queues[prio as usize].push_back(packet);
        prio
    }

    /// Dequeues the next packet to transmit:
    /// 1. Always drains `StrictRealtime` (`queue[3]`) first (Strict Priority).
    /// 2. Otherwise services `Assured` (`2`), `BestEffort` (`1`), and `Bulk` (`0`) via Deficit WFQ.
    pub fn dequeue_next(&mut self) -> Option<(TrafficPriority, Vec<u8>)> {
        if let Some(pkt) = self.queues[TrafficPriority::StrictRealtime as usize].pop_front() {
            return Some((TrafficPriority::StrictRealtime, pkt));
        }

        if self.queues[0].is_empty() && self.queues[1].is_empty() && self.queues[2].is_empty() {
            return None;
        }

        // Run Deficit Round-Robin across queues 2, 1, 0 until a head-of-line packet fits its deficit.
        for _ in 0..32 {
            let q_idx = self.rr_cursor;
            if let Some(front) = self.queues[q_idx].front() {
                let pkt_len = front.len() as u32;
                if self.deficits[q_idx] < pkt_len {
                    self.deficits[q_idx] = self.deficits[q_idx].saturating_add(self.quanta[q_idx]);
                }
                if self.deficits[q_idx] >= pkt_len {
                    self.deficits[q_idx] -= pkt_len;
                    let pkt = self.queues[q_idx].pop_front().unwrap();
                    let prio = match q_idx {
                        0 => TrafficPriority::Bulk,
                        1 => TrafficPriority::BestEffort,
                        _ => TrafficPriority::Assured,
                    };
                    if self.queues[q_idx].is_empty() {
                        self.deficits[q_idx] = 0;
                    }
                    self.rr_cursor = if q_idx == 0 { 2 } else { q_idx - 1 };
                    return Some((prio, pkt));
                }
            } else {
                self.deficits[q_idx] = 0;
            }
            self.rr_cursor = if q_idx == 0 { 2 } else { q_idx - 1 };
        }
        None
    }
}

impl Default for QosPacketScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs self-tests for the `qos_traffic` module.
pub fn verify_net_qos_traffic() -> u32 {
    let mut passed = 0u32;

    // 1. Verify DSCP classification for EF (46), AF31 (26), CS6 (48), and CS1 (8).
    let expected_af31 = DscpClass::AssuredForwarding {
        class: 3,
        drop_precedence: 1,
    };
    if DscpClass::from_dscp(46) == DscpClass::ExpeditedForwarding
        && DscpClass::from_dscp(26) == expected_af31
        && DscpClass::from_dscp(48).to_priority() == TrafficPriority::StrictRealtime
        && DscpClass::from_dscp(8).to_priority() == TrafficPriority::Bulk
    {
        passed += 1;
    }

    // 2. Verify Token-Bucket policing and timed token replenishment.
    let mut bucket = TokenBucket::new(1000, 100);
    if bucket.consume(600, 0)
        && !bucket.consume(600, 0)
        && bucket.consume(600, 2) // +200 tokens at tick 2 -> 400 + 200 = 600
        && bucket.conformed_packets == 2
        && bucket.exceeded_packets == 1
    {
        passed += 1;
    }

    // 3. Verify Strict-Priority preemption of EF (46) ahead of BestEffort (0) and Bulk (8).
    let mut sched = QosPacketScheduler::new();
    let _ = sched.enqueue_by_dscp(8, alloc::vec![0xB0; 200]); // Bulk
    let _ = sched.enqueue_by_dscp(0, alloc::vec![0xBE; 200]); // BestEffort
    let _ = sched.enqueue_by_dscp(46, alloc::vec![0xEF; 64]); // Expedited Forwarding (StrictRealtime)

    if let Some((first_prio, first_pkt)) = sched.dequeue_next() {
        if first_prio == TrafficPriority::StrictRealtime && first_pkt[0] == 0xEF {
            passed += 1;
        }
    }

    // 4. Verify WFQ drains remaining BestEffort and Bulk queues without starvation.
    let second = sched.dequeue_next().map(|(p, _)| p);
    let third = sched.dequeue_next().map(|(p, _)| p);
    if second == Some(TrafficPriority::BestEffort)
        && third == Some(TrafficPriority::Bulk)
        && sched.dequeue_next().is_none()
    {
        passed += 1;
    }

    passed
}
