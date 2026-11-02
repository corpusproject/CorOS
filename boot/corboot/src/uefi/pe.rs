use core::{mem::size_of, ptr};

const PE_SIGNATURE: u32 = 0x0000_4550;
const PE32_PLUS_MAGIC: u16 = 0x020b;
const PE_ENTRYPOINT_OFFSET: usize = 16;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_SUBSYSTEM_OFFSET: usize = 68;
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const SECTION_HEADER_SIZE: usize = 40;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Reads the entry RVA from an image already validated and loaded by UEFI.
///
/// # Safety
/// `image_base..image_base + image_size` must be readable firmware-loaded PE
/// image memory for the duration of this call.
pub unsafe fn image_entry_point(image_base: *mut u8, image_size: usize) -> Option<usize> {
    if image_base.is_null() || image_size < 0x40 {
        return None;
    }
    if ptr::read_unaligned(image_base.cast::<u16>()) != 0x5a4d {
        return None;
    }
    let pe_offset = ptr::read_unaligned(image_base.add(0x3c).cast::<u32>()) as usize;
    let coff_header_size = 24usize;
    if pe_offset.checked_add(coff_header_size)? > image_size {
        return None;
    }
    if ptr::read_unaligned(image_base.add(pe_offset).cast::<u32>()) != PE_SIGNATURE {
        return None;
    }
    let coff = image_base.add(pe_offset + size_of::<u32>());
    if ptr::read_unaligned(coff.cast::<u16>()) != IMAGE_FILE_MACHINE_AMD64 { return None; }
    let section_count = ptr::read_unaligned(coff.add(2).cast::<u16>()) as usize;
    let optional_size = ptr::read_unaligned(coff.add(16).cast::<u16>()) as usize;
    if section_count == 0 { return None; }
    let optional_offset = pe_offset.checked_add(coff_header_size)?;
    let section_offset = optional_offset.checked_add(optional_size)?;
    let section_bytes = section_count.checked_mul(SECTION_HEADER_SIZE)?;
    if optional_size < IMAGE_SUBSYSTEM_OFFSET + size_of::<u16>()
        || section_offset.checked_add(section_bytes)? > image_size
    { return None; }
    let optional_header = image_base.add(optional_offset);
    if ptr::read_unaligned(optional_header.cast::<u16>()) != PE32_PLUS_MAGIC {
        return None;
    }
    if ptr::read_unaligned(optional_header.add(IMAGE_SUBSYSTEM_OFFSET).cast::<u16>())
        != IMAGE_SUBSYSTEM_EFI_APPLICATION { return None; }
    let entry_rva = ptr::read_unaligned(
        optional_header
            .add(PE_ENTRYPOINT_OFFSET)
            .cast::<u32>(),
    ) as usize;
    if entry_rva == 0 || entry_rva >= image_size {
        return None;
    }
    // UEFI LoadImage has already validated, loaded, and relocated this image.
    // The Loaded Image protocol omits its entry address, so this bounded read
    // only identifies the executable entry section for the direct handoff.
    let mut executable_entry = false;
    for index in 0..section_count {
        let section = image_base.add(section_offset + index * SECTION_HEADER_SIZE);
        let virtual_size = ptr::read_unaligned(section.add(8).cast::<u32>()) as usize;
        let virtual_address = ptr::read_unaligned(section.add(12).cast::<u32>()) as usize;
        let raw_size = ptr::read_unaligned(section.add(16).cast::<u32>()) as usize;
        let characteristics = ptr::read_unaligned(section.add(36).cast::<u32>());
        let mapped_size = virtual_size.max(raw_size);
        if characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && entry_rva >= virtual_address
            && entry_rva < virtual_address.checked_add(mapped_size)?
        { executable_entry = true; break; }
    }
    if !executable_entry { return None; }
    (image_base as usize).checked_add(entry_rva)
}
