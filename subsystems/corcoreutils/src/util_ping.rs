//! CorOS Userland Coreutil: `ping`
//! ICMP Echo Request/Reply sequence tracker, integer square-root RTT standard deviation (`mdev`)
//! & `min`/`avg`/`max` calculator, packet loss percentage analyzer, and `iputils-ping` report formatter.

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug)]
pub struct PingOptions {
    pub count: u32,
    pub ttl: u8,
    pub payload_size: u16,
    pub quiet: bool,
}

impl PingOptions {
    pub const fn default_options() -> Self {
        Self {
            count: 4,
            ttl: 64,
            payload_size: 56,
            quiet: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> (Self, Option<String>) {
        let mut opts = Self::default_options();
        let mut target: Option<String> = None;
        let mut idx = 0;

        while idx < args.len() {
            match args[idx] {
                "-c" if idx + 1 < args.len() => {
                    if let Ok(c) = args[idx + 1].parse::<u32>() {
                        opts.count = c.max(1);
                    }
                    idx += 2;
                }
                "-t" if idx + 1 < args.len() => {
                    if let Ok(t) = args[idx + 1].parse::<u8>() {
                        opts.ttl = t;
                    }
                    idx += 2;
                }
                "-s" if idx + 1 < args.len() => {
                    if let Ok(s) = args[idx + 1].parse::<u16>() {
                        opts.payload_size = s;
                    }
                    idx += 2;
                }
                "-q" => {
                    opts.quiet = true;
                    idx += 1;
                }
                other if !other.starts_with('-') => {
                    target = Some(String::from(other));
                    idx += 1;
                }
                _ => {
                    idx += 1;
                }
            }
        }
        (opts, target)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpEchoSample {
    pub icmp_seq: u16,
    pub received_ttl: u8,
    /// `Some(rtt_us)` if reply received, `None` if request timed out.
    pub rtt_microseconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PingRttStats {
    pub transmitted: u32,
    pub received: u32,
    pub loss_percent: u32,
    pub min_us: u64,
    pub avg_us: u64,
    pub max_us: u64,
    pub mdev_us: u64,
}

const fn isqrt_u128(n: u128) -> u64 {
    if n < 2 {
        return n as u64;
    }
    let mut x = n;
    let mut y = (x + 1) >> 1;
    while y < x {
        x = y;
        y = (x + n / x) >> 1;
    }
    x as u64
}

/// Computes `min`, `avg`, `max`, and population standard deviation `mdev` (in microseconds) plus packet loss percentage.
pub fn compute_ping_statistics(samples: &[IcmpEchoSample]) -> PingRttStats {
    let transmitted = samples.len() as u32;
    if transmitted == 0 {
        return PingRttStats {
            transmitted: 0,
            received: 0,
            loss_percent: 0,
            min_us: 0,
            avg_us: 0,
            max_us: 0,
            mdev_us: 0,
        };
    }

    let mut received = 0u32;
    let mut min_us = u64::MAX;
    let mut max_us = 0u64;
    let mut sum_us = 0u128;
    let mut sum_sq_us = 0u128;

    for s in samples {
        if let Some(rtt) = s.rtt_microseconds {
            received += 1;
            if rtt < min_us {
                min_us = rtt;
            }
            if rtt > max_us {
                max_us = rtt;
            }
            let r = rtt as u128;
            sum_us += r;
            sum_sq_us += r * r;
        }
    }

    let lost = transmitted - received;
    let loss_percent = (lost * 100) / transmitted;

    if received == 0 {
        return PingRttStats {
            transmitted,
            received: 0,
            loss_percent: 100,
            min_us: 0,
            avg_us: 0,
            max_us: 0,
            mdev_us: 0,
        };
    }

    let n = received as u128;
    let avg = sum_us / n;
    let mean_sq = sum_sq_us / n;
    let variance = mean_sq.saturating_sub(avg * avg);
    let mdev_us = isqrt_u128(variance);

    PingRttStats {
        transmitted,
        received,
        loss_percent,
        min_us,
        avg_us: avg as u64,
        max_us,
        mdev_us,
    }
}

fn format_us_as_ms(us: u64) -> String {
    format!("{}.{:03}", us / 1000, us % 1000)
}

/// Formats a complete `ping` session transcript and summary footer.
pub fn format_ping_session(
    hostname: &str,
    resolved_ip: &str,
    opts: PingOptions,
    samples: &[IcmpEchoSample],
) -> String {
    let mut out = String::new();
    let wire_bytes = opts.payload_size + 28; // +8 ICMP header +20 IPv4 header
    let icmp_bytes = opts.payload_size + 8;

    out.push_str(&format!(
        "PING {} ({}) {}({}) bytes of data.\n",
        hostname, resolved_ip, opts.payload_size, wire_bytes
    ));

    if !opts.quiet {
        for s in samples {
            if let Some(rtt) = s.rtt_microseconds {
                out.push_str(&format!(
                    "{} bytes from {}: icmp_seq={} ttl={} time={} ms\n",
                    icmp_bytes,
                    resolved_ip,
                    s.icmp_seq,
                    s.received_ttl,
                    format_us_as_ms(rtt)
                ));
            }
        }
    }

    let stats = compute_ping_statistics(samples);
    out.push_str(&format!("\n--- {} ping statistics ---\n", hostname));
    out.push_str(&format!(
        "{} packets transmitted, {} received, {}% packet loss\n",
        stats.transmitted, stats.received, stats.loss_percent
    ));

    if stats.received > 0 {
        out.push_str(&format!(
            "rtt min/avg/max/mdev = {}/{}/{}/{} ms\n",
            format_us_as_ms(stats.min_us),
            format_us_as_ms(stats.avg_us),
            format_us_as_ms(stats.max_us),
            format_us_as_ms(stats.mdev_us),
        ));
    }

    out
}

pub fn verify_util_ping() -> u32 {
    let mut passed = 0u32;

    let (opts, host) = PingOptions::parse_args(&["-c", "4", "-s", "64", "10.0.2.2"]);
    if opts.count == 4 && opts.payload_size == 64 && host.as_deref() == Some("10.0.2.2") {
        passed += 1;
    }

    let samples = [
        IcmpEchoSample { icmp_seq: 1, received_ttl: 64, rtt_microseconds: Some(400) },
        IcmpEchoSample { icmp_seq: 2, received_ttl: 64, rtt_microseconds: Some(600) },
        IcmpEchoSample { icmp_seq: 3, received_ttl: 64, rtt_microseconds: Some(800) },
        IcmpEchoSample { icmp_seq: 4, received_ttl: 64, rtt_microseconds: None },
    ];

    let stats = compute_ping_statistics(&samples);
    if stats.transmitted == 4
        && stats.received == 3
        && stats.loss_percent == 25
        && stats.min_us == 400
        && stats.avg_us == 600
        && stats.max_us == 800
        && stats.mdev_us == 163
    {
        passed += 1;
    }

    let report = format_ping_session("gateway.coros", "10.0.2.2", opts, &samples);
    if report.contains("25% packet loss") && report.contains("rtt min/avg/max/mdev = 0.400/0.600/0.800/0.163 ms") {
        passed += 1;
    }

    passed
}
