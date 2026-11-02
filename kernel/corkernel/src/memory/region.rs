use corboot_info::{MemoryDescriptor, EFI_MEMORY_ACPI_NVS, EFI_MEMORY_ACPI_RECLAIM, EFI_MEMORY_BAD, EFI_MEMORY_BOOT_SERVICES_CODE, EFI_MEMORY_BOOT_SERVICES_DATA, EFI_MEMORY_CONVENTIONAL, EFI_MEMORY_LOADER_CODE, EFI_MEMORY_LOADER_DATA, EFI_MEMORY_MAPPED_IO, EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_MEMORY_RUNTIME};
use super::{address::PhysicalAddress, PAGE_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionType { Usable, LoaderReclaimable, AcpiReclaimable, AcpiNvs, Bad, Mmio, MmioPortSpace, Reserved }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion { pub start: PhysicalAddress, pub frame_count: u64, pub kind: RegionType }
impl MemoryRegion {
    pub fn from_uefi(d: MemoryDescriptor) -> Option<Self> {
        if d.physical_start % PAGE_SIZE != 0 || d.number_of_pages == 0
            || d.number_of_pages.checked_mul(PAGE_SIZE)?.checked_add(d.physical_start).is_none() { return None; }
        if d.attribute & EFI_MEMORY_RUNTIME != 0 {
            return Some(Self { start: PhysicalAddress(d.physical_start), frame_count: d.number_of_pages, kind: RegionType::Reserved });
        }
        let kind = match d.memory_type {
            EFI_MEMORY_CONVENTIONAL => RegionType::Usable,
            EFI_MEMORY_LOADER_CODE | EFI_MEMORY_LOADER_DATA | EFI_MEMORY_BOOT_SERVICES_CODE | EFI_MEMORY_BOOT_SERVICES_DATA => RegionType::LoaderReclaimable,
            EFI_MEMORY_ACPI_RECLAIM => RegionType::AcpiReclaimable,
            EFI_MEMORY_ACPI_NVS => RegionType::AcpiNvs,
            EFI_MEMORY_BAD => RegionType::Bad,
            EFI_MEMORY_MAPPED_IO => RegionType::Mmio,
            EFI_MEMORY_MAPPED_IO_PORT_SPACE => RegionType::MmioPortSpace,
            _ => RegionType::Reserved,
        };
        Some(Self { start: PhysicalAddress(d.physical_start), frame_count: d.number_of_pages, kind })
    }
    pub fn end_address(self) -> Option<PhysicalAddress> { self.frame_count.checked_mul(PAGE_SIZE)?.checked_add(self.start.0).map(PhysicalAddress) }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn classifies_uefi_memory_without_promoting_reclaimable_regions() {
        let mk = |memory_type| MemoryDescriptor { memory_type, physical_start: 0x1000, number_of_pages: 1, ..MemoryDescriptor::default() };
        assert_eq!(MemoryRegion::from_uefi(mk(EFI_MEMORY_CONVENTIONAL)).unwrap().kind, RegionType::Usable);
        assert_eq!(MemoryRegion::from_uefi(mk(EFI_MEMORY_LOADER_DATA)).unwrap().kind, RegionType::LoaderReclaimable);
        assert_eq!(MemoryRegion::from_uefi(mk(10)).unwrap().kind, RegionType::AcpiNvs);
        assert_eq!(MemoryRegion::from_uefi(mk(8)).unwrap().kind, RegionType::Bad);
        assert_eq!(MemoryRegion::from_uefi(mk(11)).unwrap().kind, RegionType::Mmio);
        let runtime = MemoryDescriptor { attribute: corboot_info::EFI_MEMORY_RUNTIME, ..mk(EFI_MEMORY_CONVENTIONAL) };
        assert_eq!(MemoryRegion::from_uefi(runtime).unwrap().kind, RegionType::Reserved);
    }

    #[test]
    fn rejects_unaligned_empty_and_overflowing_descriptors() {
        assert!(MemoryRegion::from_uefi(MemoryDescriptor { physical_start: 1, number_of_pages: 1, ..MemoryDescriptor::default() }).is_none());
        assert!(MemoryRegion::from_uefi(MemoryDescriptor { physical_start: 0x1000, number_of_pages: 0, ..MemoryDescriptor::default() }).is_none());
        assert!(MemoryRegion::from_uefi(MemoryDescriptor { physical_start: u64::MAX - 0xfff, number_of_pages: 2, ..MemoryDescriptor::default() }).is_none());
    }
}
