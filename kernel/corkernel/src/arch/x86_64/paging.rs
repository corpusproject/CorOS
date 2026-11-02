//! Architecture paging activation remains blocked: the kernel retains UEFI
//! CR3. Four-level construction and mapping primitives live in
//! `crate::memory::virtual_memory`; no boot-time ownership-preserving CR3 switch
//! is exposed until current mappings and physical-table access are proven.

/// Fail-closed source gate. It stays closed until paging mode, safe table
/// access, complete required-mapping coverage, memory attributes/reservations,
/// and a real transition/recovery exercise have all been established.
/// The CPU module exposes no CR3 write operation in this milestone.
pub const fn cr3_transition_gate_open() -> bool { false }

#[cfg(test)]
mod tests {
    #[test]
    fn cr3_transition_gate_is_closed_in_source() {
        assert!(!super::cr3_transition_gate_open());
    }
}
