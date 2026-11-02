#![no_std]
//! `cornet` — CorOS Complete Network Protocol Stack, Sockets & Stateful Packet Firewall.

extern crate alloc;

pub mod arp_ndp;
pub mod bsd_sockets;
pub mod dhcp_client;
pub mod dns_resolver;
pub mod ethernet_mac;
pub mod firewall_filter;
pub mod iana_services;
pub mod icmp_echo;
pub mod ipv4_routing;
pub mod ipv6_core;
pub mod loopback_if;
pub mod netlink_diag;
pub mod qos_traffic;
pub mod tcp_fsm;
pub mod tls_record;
pub mod udp_datagram;

/// Runs network stack and firewall self-tests across all 16 protocol modules,
/// returning the total number of passed protocol verification checks.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    passed += ethernet_mac::verify_net_ethernet_mac();
    passed += arp_ndp::verify_net_arp_ndp();
    passed += ipv4_routing::verify_net_ipv4_routing();
    passed += ipv6_core::verify_net_ipv6_core();
    passed += icmp_echo::verify_net_icmp_echo();
    passed += udp_datagram::verify_net_udp_datagram();
    passed += tcp_fsm::verify_net_tcp_fsm();
    passed += bsd_sockets::verify_net_bsd_sockets();
    passed += dhcp_client::verify_net_dhcp_client();
    passed += dns_resolver::verify_net_dns_resolver();
    passed += firewall_filter::verify_net_firewall_filter();
    passed += loopback_if::verify_net_loopback_if();
    passed += netlink_diag::verify_net_netlink_diag();
    passed += qos_traffic::verify_net_qos_traffic();
    passed += iana_services::verify_net_iana_services();
    passed += tls_record::verify_net_tls_record();
    passed
}
