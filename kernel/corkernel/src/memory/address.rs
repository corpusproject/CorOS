use super::PAGE_SIZE;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalAddress(pub u64);
impl PhysicalAddress {
    pub const fn new(value: u64) -> Self { Self(value) }
    pub const fn is_aligned(self, alignment: u64) -> bool { alignment != 0 && self.0 % alignment == 0 }
    pub fn checked_add(self, bytes: u64) -> Option<Self> { self.0.checked_add(bytes).map(Self) }
    pub const fn offset(self, alignment: u64) -> u64 { if alignment == 0 { 0 } else { self.0 % alignment } }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualAddress(pub u64);
impl VirtualAddress {
    pub const fn new(value: u64) -> Option<Self> { if is_canonical(value) { Some(Self(value)) } else { None } }
    pub const fn is_canonical(self) -> bool { is_canonical(self.0) }
    pub const fn is_aligned(self, alignment: u64) -> bool { alignment != 0 && self.0 % alignment == 0 }
    pub const fn offset(self, alignment: u64) -> u64 { if alignment == 0 { 0 } else { self.0 % alignment } }
}

/// Four-level paging canonicality (48-bit virtual addresses). LA57 is not enabled by CorOS yet.
pub const fn is_canonical(value: u64) -> bool {
    let upper = value >> 48;
    if value & (1 << 47) == 0 { upper == 0 } else { upper == 0xffff }
}

pub const fn align_down(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() { None } else { Some(value & !(alignment - 1)) }
}
pub const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() { return None; }
    match value.checked_add(alignment - 1) { Some(v) => Some(v & !(alignment - 1)), None => None }
}

pub const fn page_containing(address: PhysicalAddress) -> PhysicalAddress {
    PhysicalAddress(address.0 & !(PAGE_SIZE - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn virtual_address_canonical_boundaries() {
        assert!(VirtualAddress::new(0x0000_7fff_ffff_ffff).is_some());
        assert!(VirtualAddress::new(0xffff_8000_0000_0000).is_some());
        assert!(VirtualAddress::new(0x0000_8000_0000_0000).is_none());
        assert!(VirtualAddress::new(0xffff_7fff_ffff_ffff).is_none());
    }
    #[test] fn address_alignment_and_rounding_are_checked() {
        assert!(PhysicalAddress(0x2000).is_aligned(PAGE_SIZE));
        assert!(!PhysicalAddress(0x2001).is_aligned(PAGE_SIZE));
        assert_eq!(align_down(0x2345, PAGE_SIZE), Some(0x2000));
        assert_eq!(align_up(0x2001, PAGE_SIZE), Some(0x3000));
        assert_eq!(align_up(u64::MAX, PAGE_SIZE), None);
    }
}
