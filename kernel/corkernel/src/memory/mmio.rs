//! Typed MMIO address/range validation. Mapping is performed by the page mapper
//! with cache attributes selected by the architecture layer (not normal RAM).
use super::{address::PhysicalAddress, PAGE_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MmioAddress(PhysicalAddress);
impl MmioAddress {
    pub fn new(address: PhysicalAddress) -> Option<Self> {
        if address.0 == 0 || !address.is_aligned(PAGE_SIZE) { None } else { Some(Self(address)) }
    }
    pub const fn physical(self) -> PhysicalAddress { self.0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioRegion { pub base: MmioAddress, pub length: u64 }
impl MmioRegion {
    pub fn new(base: PhysicalAddress, length: u64) -> Option<Self> {
        if length == 0 || base.0.checked_add(length).is_none() { return None; }
        let page_base = PhysicalAddress(base.0 & !(PAGE_SIZE - 1));
        let offset = base.0 - page_base.0;
        let span = offset.checked_add(length)?;
        let rounded = span.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
        Some(Self { base: MmioAddress::new(page_base)?, length: rounded })
    }
    pub fn end(self) -> Option<PhysicalAddress> { self.base.physical().checked_add(self.length) }
    pub fn contains(self, address: PhysicalAddress, bytes: u64) -> bool {
        let Some(end) = address.checked_add(bytes) else { return false; };
        address.0 >= self.base.physical().0 && self.end().map(|r| end.0 <= r.0).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn validates_and_rounds_mmio_ranges_without_overflow() {
        let region = MmioRegion::new(PhysicalAddress(0xfee0_0123), 0x2000).unwrap();
        assert_eq!(region.base.physical(), PhysicalAddress(0xfee0_0000));
        assert!(region.contains(PhysicalAddress(0xfee0_1000), 16));
        assert!(!region.contains(PhysicalAddress(0xfee0_3000), 1));
        assert!(MmioRegion::new(PhysicalAddress(u64::MAX - 4), 16).is_none());
        assert!(MmioRegion::new(PhysicalAddress(0), 1).is_none());
    }
}
