#![no_std]

#[cfg(test)]
extern crate std;

use core::{mem::{align_of, size_of}, slice};

pub const BOOT_INFO_MAGIC: u64 = u64::from_le_bytes(*b"CORSBOOT");
pub const BOOT_INFO_VERSION: u32 = 1;
pub const CORBOOT_VERSION: u32 = 1;
pub const ARCH_X86_64: u32 = 1;
pub const ARCH_AARCH64: u32 = 2;
pub const ARCH_RISCV64: u32 = 3;

pub const FLAG_ACPI: u32 = 1 << 0;
pub const FLAG_FRAMEBUFFER: u32 = 1 << 1;
pub const FLAG_SAFE_MODE: u32 = 1 << 2;
pub const FLAG_VERBOSE_BOOT: u32 = 1 << 3;
pub const FLAG_FAST_RESUME: u32 = 1 << 4;
pub const FLAG_WATCHDOG_RECOVERED: u32 = 1 << 5;
pub const FLAG_INITRD_PRESENT: u32 = 1 << 6;
pub const SUPPORTED_FLAGS: u32 = FLAG_ACPI
    | FLAG_FRAMEBUFFER
    | FLAG_SAFE_MODE
    | FLAG_VERBOSE_BOOT
    | FLAG_FAST_RESUME
    | FLAG_WATCHDOG_RECOVERED
    | FLAG_INITRD_PRESENT;

pub const EFI_MEMORY_LOADER_CODE: u32 = 1;
pub const EFI_MEMORY_LOADER_DATA: u32 = 2;
pub const EFI_MEMORY_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_MEMORY_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_MEMORY_CONVENTIONAL: u32 = 7;
pub const EFI_MEMORY_ACPI_RECLAIM: u32 = 9;
pub const EFI_MEMORY_BAD: u32 = 8;
pub const EFI_MEMORY_ACPI_NVS: u32 = 10;
pub const EFI_MEMORY_RESERVED: u32 = 0;
pub const EFI_MEMORY_MAPPED_IO: u32 = 11;
pub const EFI_MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
pub const EFI_MEMORY_RUNTIME: u64 = 1 << 63;
/// Layout version for the EFI_MEMORY_DESCRIPTOR prefix represented below.
pub const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;

pub const PIXEL_RED_GREEN_BLUE_RESERVED_8: u32 = 0;
pub const PIXEL_BLUE_GREEN_RED_RESERVED_8: u32 = 1;
pub const PIXEL_BIT_MASK: u32 = 2;

/// Fixed versioned handoff structure shared by CorBoot and CorKernel.
/// Pointer-like addresses use `u64` so the ABI does not contain Rust pointers.
/// LoadedImage `ImageBase` and protocol table values are opaque firmware
/// address values; they must not be reinterpreted as physical addresses.
/// `framebuffer_address` is the exception: GOP defines its base as physical.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub architecture: u32,
    pub flags: u32,
    pub bootloader_version: u32,
    pub _reserved0: u32,
    /// EFI LoadedImage `ImageBase` pointer value; physical interpretation unknown.
    pub bootloader_image_address: u64,
    pub bootloader_image_size: u64,
    /// Pointer value returned by AllocatePool; not a physical address field.
    pub memory_map_address: u64,
    pub memory_map_size: u64,
    pub memory_descriptor_size: u64,
    pub memory_descriptor_version: u32,
    pub firmware_revision: u32,
    /// EFI configuration-table pointer value; opaque to the frame allocator.
    pub acpi_rsdp_address: u64,
    /// GOP `FrameBufferBase`, defined by UEFI as a physical address.
    pub framebuffer_address: u64,
    pub framebuffer_size: u64,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_stride: u32,
    pub framebuffer_format: u32,
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
    /// EFI LoadedImage `ImageBase` pointer value; physical interpretation unknown.
    pub kernel_image_address: u64,
    pub kernel_image_size: u64,
    pub cmdline: [u8; 64],
    pub initrd_address: u64,
    pub initrd_size: u64,
    pub boot_slot: u32,
    pub last_boot_status: u32,
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            size: size_of::<Self>() as u32,
            architecture: ARCH_X86_64,
            flags: 0,
            bootloader_version: CORBOOT_VERSION,
            _reserved0: 0,
            bootloader_image_address: 0,
            bootloader_image_size: 0,
            memory_map_address: 0,
            memory_map_size: 0,
            memory_descriptor_size: 0,
            memory_descriptor_version: 0,
            firmware_revision: 0,
            acpi_rsdp_address: 0,
            framebuffer_address: 0,
            framebuffer_size: 0,
            framebuffer_width: 0,
            framebuffer_height: 0,
            framebuffer_stride: 0,
            framebuffer_format: 0,
            red_mask: 0,
            green_mask: 0,
            blue_mask: 0,
            reserved_mask: 0,
            kernel_image_address: 0,
            kernel_image_size: 0,
            cmdline: [0u8; 64],
            initrd_address: 0,
            initrd_size: 0,
            boot_slot: 0,
            last_boot_status: 0,
        }
    }

    pub fn validate(&self) -> Result<(), BootInfoError> {
        if self.magic != BOOT_INFO_MAGIC {
            return Err(BootInfoError::BadMagic);
        }
        if self.version != BOOT_INFO_VERSION || self.size < size_of::<Self>() as u32 {
            return Err(BootInfoError::UnsupportedVersion);
        }
        if self.architecture != ARCH_X86_64
            && self.architecture != ARCH_AARCH64
            && self.architecture != ARCH_RISCV64
        {
            return Err(BootInfoError::UnsupportedArchitecture);
        }
        if self.flags & !SUPPORTED_FLAGS != 0 {
            return Err(BootInfoError::UnsupportedFlags);
        }
        if self._reserved0 != 0 {
            return Err(BootInfoError::NonZeroReservedField);
        }
        if self.bootloader_image_address == 0
            || self.bootloader_image_size == 0
            || self.bootloader_image_address.checked_add(self.bootloader_image_size).is_none()
        {
            return Err(BootInfoError::InvalidBootloaderImage);
        }
        if self.memory_map_address == 0
            || self.memory_map_size == 0
            || self.memory_map_size > isize::MAX as u64
            || self.memory_map_address.checked_add(self.memory_map_size).is_none()
            || self.memory_descriptor_size < size_of::<MemoryDescriptor>() as u64
            || self.memory_descriptor_size > 4096
            || self.memory_descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION
            || self.memory_map_size % self.memory_descriptor_size != 0
        {
            return Err(BootInfoError::InvalidMemoryMap);
        }
        if self.kernel_image_address == 0
            || self.kernel_image_size == 0
            || self.kernel_image_address.checked_add(self.kernel_image_size).is_none()
        {
            return Err(BootInfoError::InvalidKernelImage);
        }
        if self.flags & FLAG_FRAMEBUFFER != 0 {
            if self.framebuffer_address == 0
                || self.framebuffer_width == 0
                || self.framebuffer_height == 0
                || self.framebuffer_stride < self.framebuffer_width
                || !matches!(
                    self.framebuffer_format,
                    PIXEL_RED_GREEN_BLUE_RESERVED_8 | PIXEL_BLUE_GREEN_RED_RESERVED_8 | PIXEL_BIT_MASK
                )
            {
                return Err(BootInfoError::InvalidFramebuffer);
            }
            let required = (self.framebuffer_stride as u64)
                .checked_mul(self.framebuffer_height as u64)
                .and_then(|pixels| pixels.checked_mul(4))
                .ok_or(BootInfoError::InvalidFramebuffer)?;
            if self.framebuffer_size < required
                || self.framebuffer_address.checked_add(self.framebuffer_size).is_none()
            {
                return Err(BootInfoError::InvalidFramebuffer);
            }
            if self.framebuffer_format == PIXEL_BIT_MASK
                && !valid_pixel_masks([self.red_mask, self.green_mask, self.blue_mask, self.reserved_mask])
            {
                return Err(BootInfoError::InvalidFramebuffer);
            }
        }
        if self.flags & FLAG_FRAMEBUFFER == 0
            && (self.framebuffer_address != 0 || self.framebuffer_size != 0)
        {
            return Err(BootInfoError::InvalidFramebuffer);
        }
        if (self.flags & FLAG_ACPI != 0) != (self.acpi_rsdp_address != 0) {
            return Err(BootInfoError::InvalidAcpiPointer);
        }
        Ok(())
    }
}

pub fn valid_pixel_masks(masks: [u32; 4]) -> bool {
    if masks[0] == 0 || masks[1] == 0 || masks[2] == 0 { return false; }
    let mut occupied = 0u32;
    for mask in masks {
        if mask == 0 { continue; }
        let shifted = mask >> mask.trailing_zeros();
        if shifted & shifted.wrapping_add(1) != 0 || occupied & mask != 0 { return false; }
        occupied |= mask;
    }
    true
}

const _: [(); 240] = [(); size_of::<BootInfo>()];
const _: [(); 8] = [(); align_of::<BootInfo>()];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryDescriptor {
    pub memory_type: u32,
    pub _padding: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

const _: [(); 40] = [(); size_of::<MemoryDescriptor>()];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoError {
    BadMagic,
    UnsupportedVersion,
    UnsupportedArchitecture,
    UnsupportedFlags,
    InvalidBootloaderImage,
    InvalidMemoryMap,
    InvalidKernelImage,
    InvalidFramebuffer,
    InvalidAcpiPointer,
    NonZeroReservedField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryMapError {
    DescriptorTooSmall,
    DescriptorTooLarge,
    MisalignedLength,
}

pub struct MemoryMap<'a> {
    bytes: &'a [u8],
    descriptor_size: usize,
}

impl<'a> MemoryMap<'a> {
    pub fn new(bytes: &'a [u8], descriptor_size: usize) -> Result<Self, MemoryMapError> {
        if descriptor_size < size_of::<MemoryDescriptor>() {
            return Err(MemoryMapError::DescriptorTooSmall);
        }
        if descriptor_size > 4096 {
            return Err(MemoryMapError::DescriptorTooLarge);
        }
        if bytes.len() % descriptor_size != 0 {
            return Err(MemoryMapError::MisalignedLength);
        }
        Ok(Self {
            bytes,
            descriptor_size,
        })
    }

    pub fn iter(&self) -> MemoryMapIter<'_> {
        MemoryMapIter {
            bytes: self.bytes,
            descriptor_size: self.descriptor_size,
            offset: 0,
        }
    }
}

pub struct MemoryMapIter<'a> {
    bytes: &'a [u8],
    descriptor_size: usize,
    offset: usize,
}

impl Iterator for MemoryMapIter<'_> {
    type Item = MemoryDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.offset.checked_add(self.descriptor_size)?;
        if end > self.bytes.len() {
            return None;
        }
        let descriptor = unsafe {
            core::ptr::read_unaligned(
                self.bytes.as_ptr().add(self.offset).cast::<MemoryDescriptor>(),
            )
        };
        self.offset = end;
        Some(descriptor)
    }
}

/// Creates a byte view of the firmware memory map after BootInfo has been
/// validated. The pointer and length originate from CorBoot's memory map call.
///
/// # Safety
/// `boot_info.memory_map_address..memory_map_address + memory_map_size` must
/// remain mapped and readable for the returned lifetime.
pub unsafe fn memory_map_from_boot_info<'a>(
    boot_info: &BootInfo,
) -> Result<MemoryMap<'a>, MemoryMapError> {
    let len = usize::try_from(boot_info.memory_map_size)
        .map_err(|_| MemoryMapError::MisalignedLength)?;
    let descriptor_size = usize::try_from(boot_info.memory_descriptor_size)
        .map_err(|_| MemoryMapError::DescriptorTooLarge)?;
    let address = usize::try_from(boot_info.memory_map_address)
        .map_err(|_| MemoryMapError::MisalignedLength)?;
    if len == 0 || address == 0 || len > isize::MAX as usize {
        return Err(MemoryMapError::MisalignedLength);
    }
    if descriptor_size < size_of::<MemoryDescriptor>() {
        return Err(MemoryMapError::DescriptorTooSmall);
    }
    if descriptor_size > 4096 {
        return Err(MemoryMapError::DescriptorTooLarge);
    }
    if len % descriptor_size != 0 || address.checked_add(len).is_none() {
        return Err(MemoryMapError::MisalignedLength);
    }
    let bytes = slice::from_raw_parts(boot_info.memory_map_address as *const u8, len);
    MemoryMap::new(bytes, descriptor_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_info_abi_is_stable() {
        assert_eq!(size_of::<BootInfo>(), 240);
        assert_eq!(size_of::<MemoryDescriptor>(), 40);
    }

    #[test]
    fn validates_multi_arch_architectures() {
        let mut info = BootInfo::empty();
        info.memory_map_address = 0x100000;
        info.memory_map_size = 40;
        info.memory_descriptor_size = 40;
        info.memory_descriptor_version = 1;
        info.kernel_image_address = 0x200000;
        info.kernel_image_size = 0x10000;
        info.bootloader_image_address = 0x80000;
        info.bootloader_image_size = 0x10000;

        info.architecture = ARCH_X86_64;
        assert_eq!(info.validate(), Ok(()));

        info.architecture = ARCH_AARCH64;
        assert_eq!(info.validate(), Ok(()));

        info.architecture = ARCH_RISCV64;
        assert_eq!(info.validate(), Ok(()));

        info.architecture = 0;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedArchitecture));

        info.architecture = 4;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedArchitecture));
    }

    #[test]
    fn rejects_invalid_memory_map_descriptor_sizes() {
        assert_eq!(MemoryMap::new(&[], 39).err(), Some(MemoryMapError::DescriptorTooSmall));
        assert_eq!(MemoryMap::new(&[], 4097).err(), Some(MemoryMapError::DescriptorTooLarge));
        assert_eq!(MemoryMap::new(&[0; 41], 40).err(), Some(MemoryMapError::MisalignedLength));
    }

    #[test]
    fn iterates_firmware_descriptors_with_extension_padding() {
        let mut bytes = [0u8; 96];
        let first = MemoryDescriptor {
            memory_type: EFI_MEMORY_CONVENTIONAL,
            physical_start: 0x1000,
            number_of_pages: 4,
            ..MemoryDescriptor::default()
        };
        let second = MemoryDescriptor {
            memory_type: EFI_MEMORY_LOADER_DATA,
            physical_start: 0x5000,
            number_of_pages: 2,
            ..MemoryDescriptor::default()
        };
        unsafe {
            core::ptr::write_unaligned(bytes.as_mut_ptr().cast::<MemoryDescriptor>(), first);
            core::ptr::write_unaligned(bytes.as_mut_ptr().add(48).cast::<MemoryDescriptor>(), second);
        }
        let map = MemoryMap::new(&bytes, 48).unwrap();
        let mut iter = map.iter();
        assert_eq!(iter.next().unwrap().physical_start, 0x1000);
        assert_eq!(iter.next().unwrap().physical_start, 0x5000);
        assert!(iter.next().is_none());
    }

    #[test]
    fn validates_minimal_handoff() {
        let mut info = BootInfo::empty();
        info.memory_map_address = 0x100000;
        info.memory_map_size = 40;
        info.memory_descriptor_size = 40;
        info.kernel_image_address = 0x200000;
        info.kernel_image_size = 0x10000;
        info.bootloader_image_address = 0x80000;
        info.bootloader_image_size = 0x10000;
        info.memory_descriptor_version = 1;
        assert_eq!(info.validate(), Ok(()));
        info.memory_map_size = 39;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidMemoryMap));
    }

    #[test]
    fn rejects_unsupported_boot_info_version_and_short_struct_size() {
        let mut info = BootInfo::empty();
        info.memory_map_address = 0x100000;
        info.memory_map_size = 40;
        info.memory_descriptor_size = 40;
        info.memory_descriptor_version = 1;
        info.kernel_image_address = 0x200000;
        info.kernel_image_size = 0x10000;
        info.bootloader_image_address = 0x80000;
        info.bootloader_image_size = 0x10000;
        info.version += 1;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedVersion));
        info.version = BOOT_INFO_VERSION;
        info.size = (size_of::<BootInfo>() as u32) - 1;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedVersion));
        info.size = size_of::<BootInfo>() as u32;
        info.memory_descriptor_version = EFI_MEMORY_DESCRIPTOR_VERSION + 1;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidMemoryMap));
    }

    #[test]
    fn validates_signature_flags_alignment_and_image_ranges() {
        assert_eq!(align_of::<BootInfo>(), 8);
        let mut info = BootInfo::empty();
        info.memory_map_address = 0x100000;
        info.memory_map_size = 40;
        info.memory_descriptor_size = 40;
        info.memory_descriptor_version = 1;
        info.kernel_image_address = 0x200000;
        info.kernel_image_size = 0x10000;
        info.bootloader_image_address = 0x80000;
        info.bootloader_image_size = 0x10000;
        assert_eq!(info.validate(), Ok(()));
        info.flags = 1 << 31;
        assert_eq!(info.validate(), Err(BootInfoError::UnsupportedFlags));
        info.flags = 0;
        info.bootloader_image_address = u64::MAX - 7;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidBootloaderImage));
    }

    #[test]
    fn rejects_inconsistent_optional_pointer_flags() {
        let mut info = BootInfo::empty();
        info.memory_map_address = 0x100000;
        info.memory_map_size = 40;
        info.memory_descriptor_size = 40;
        info.memory_descriptor_version = 1;
        info.kernel_image_address = 0x200000;
        info.kernel_image_size = 0x10000;
        info.bootloader_image_address = 0x80000;
        info.bootloader_image_size = 0x10000;
        info.flags = FLAG_ACPI;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidAcpiPointer));
    }

    #[test]
    fn validates_bitmask_pixel_layout() {
        let mut info = BootInfo::empty();
        info.memory_map_address = 0x100000;
        info.memory_map_size = 40;
        info.memory_descriptor_size = 40;
        info.memory_descriptor_version = 1;
        info.kernel_image_address = 0x200000;
        info.kernel_image_size = 0x10000;
        info.bootloader_image_address = 0x80000;
        info.bootloader_image_size = 0x10000;
        info.flags = FLAG_FRAMEBUFFER;
        info.framebuffer_address = 0x300000;
        info.framebuffer_size = 640 * 480 * 4;
        info.framebuffer_width = 640;
        info.framebuffer_height = 480;
        info.framebuffer_stride = 640;
        info.framebuffer_format = PIXEL_BIT_MASK;
        info.red_mask = 0x00ff_0000;
        info.green_mask = 0x0000_ff00;
        info.blue_mask = 0x0000_00ff;
        assert_eq!(info.validate(), Ok(()));
        info.green_mask = 0x0000_0a00;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidFramebuffer));
        info.green_mask = 0x0000_00ff;
        assert_eq!(info.validate(), Err(BootInfoError::InvalidFramebuffer));
    }
}
