use super::{address::{PhysicalAddress, VirtualAddress}, PAGE_SIZE};

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Frame4KiB(pub u64);
impl Frame4KiB {
    pub const fn containing(address: PhysicalAddress) -> Self { Self(address.0 / PAGE_SIZE) }
    pub const fn start_address(self) -> Option<PhysicalAddress> {
        match self.0.checked_mul(PAGE_SIZE) {
            Some(addr) => Some(PhysicalAddress(addr)),
            None => None,
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Page4KiB(pub u64);
impl Page4KiB {
    pub const fn containing(address: VirtualAddress) -> Self { Self(address.0 / PAGE_SIZE) }
    pub const fn start_address(self) -> Option<VirtualAddress> {
        match self.0.checked_mul(PAGE_SIZE) {
            Some(addr) => Some(VirtualAddress(addr)),
            None => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn frame_and_page_containing_addresses_round_down() {
        assert_eq!(Frame4KiB::containing(PhysicalAddress(0x4fff)), Frame4KiB(4));
        assert_eq!(Frame4KiB(4).start_address(), Some(PhysicalAddress(0x4000)));
        assert_eq!(Page4KiB::containing(VirtualAddress(0x8abc)), Page4KiB(8));
        assert_eq!(Page4KiB(8).start_address(), Some(VirtualAddress(0x8000)));
        assert_eq!(Frame4KiB(u64::MAX).start_address(), None);
        assert_eq!(Page4KiB(u64::MAX).start_address(), None);
    }
}
