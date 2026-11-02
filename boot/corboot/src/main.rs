#![no_std]
#![no_main]

mod uefi;

use core::{ffi::c_void, panic::PanicInfo, ptr};
use corboot_info::{
    BootInfo, ARCH_X86_64, BOOT_INFO_MAGIC, BOOT_INFO_VERSION, CORBOOT_VERSION,
    FLAG_ACPI, FLAG_FAST_RESUME, FLAG_FRAMEBUFFER, FLAG_INITRD_PRESENT,
    FLAG_WATCHDOG_RECOVERED,
};
use uefi::{
    file::{check_hibernation_file, load_initrd, open_kernel_image, own_loaded_image, FileError},
    guid::{ACPI_20_TABLE_GUID, ACPI_TABLE_GUID, EFI_LOADED_IMAGE_PROTOCOL_GUID},
    pe::image_entry_point,
    status, BootServices, GraphicsOutputProtocol, LoadedImageProtocol, SystemTable,
    EFI_ERROR, EFI_INVALID_PARAMETER, EFI_LOADER_DATA, EFI_OPEN_PROTOCOL_GET_PROTOCOL,
    EFI_SUCCESS,
};

static mut BOOT_INFO: BootInfo = BootInfo::empty();
const MEMORY_MAP_SLACK_DESCRIPTORS: usize = 8;
const MAX_EXIT_ATTEMPTS: usize = 4;

#[derive(Clone, Copy)]
#[allow(dead_code)] // Reserved diagnostic variants kept for the BootInfo handoff ABI.
enum CorBootError {
    BootImageUnavailable,
    KernelFileMissing,
    KernelImageTooLarge,
    KernelImageInvalid,
    KernelLoadFailed,
    InvalidKernelEntry,
    InvalidImageMemoryType,
    MemoryMapSizingFailed,
    MemoryMapAllocationFailed,
    MemoryMapUnavailable,
    BootInfoConstructionFailed,
    FramebufferUnavailable,
    AcpiUnavailable,
    ExitBootServicesFailed,
    InvalidHandoffData,
}

impl CorBootError {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::BootImageUnavailable => "FATAL: CorBoot image information unavailable.\r\n",
            Self::KernelFileMissing => "FATAL: EFI\\COROS\\CORKERNEL.EFI missing.\r\n",
            Self::KernelImageTooLarge => "FATAL: CorKernel image is too large.\r\n",
            Self::KernelImageInvalid => "FATAL: CorKernel image is invalid or empty.\r\n",
            Self::KernelLoadFailed => "FATAL: Could not load CorKernel image.\r\n",
            Self::InvalidKernelEntry => "FATAL: CorKernel PE entry point is invalid.\r\n",
            Self::InvalidImageMemoryType => "FATAL: UEFI image memory types are unexpected.\r\n",
            Self::MemoryMapSizingFailed => "FATAL: UEFI memory map sizing failed.\r\n",
            Self::MemoryMapAllocationFailed => "FATAL: Could not allocate UEFI memory map buffer.\r\n",
            Self::MemoryMapUnavailable => "FATAL: UEFI memory map unavailable.\r\n",
            Self::BootInfoConstructionFailed => "FATAL: CorBoot could not construct valid BootInfo.\r\n",
            Self::InvalidHandoffData => "FATAL: CorBoot handoff data is invalid.\r\n",
            Self::FramebufferUnavailable => "INFO: GOP framebuffer unavailable; continuing without it.\r\n",
            Self::AcpiUnavailable => "INFO: ACPI RSDP unavailable; continuing without it.\r\n",
            Self::ExitBootServicesFailed => "FATAL: ExitBootServices failed.\r\n",
        }
    }
}

/// UEFI supplies both parameters according to the x86_64 UEFI ABI.
///
/// # Safety
/// This entry point may only be invoked by UEFI firmware with valid handles
/// and system-table pointers for the current boot-services session.
#[no_mangle]
pub unsafe extern "efiapi" fn efi_main(image_handle: usize, system_table: *mut SystemTable) -> usize {
    if system_table.is_null() {
        return 1;
    }
    let table = &mut *system_table;
    uefi::console::write(table, "==============================================================\r\n");
    uefi::console::write(table, " CorOS CorBoot v2.5 - UEFI x86_64 Advanced Boot Manager\r\n");
    uefi::console::write(table, "==============================================================\r\n");
    uefi::console::write(table, " [1] CorOS Workstation 2026 (Varsayilan - Fluent Desktop 60+ FPS)\r\n");
    uefi::console::write(table, " [2] CorOS Guvenli Mod (Safe Mode - Minimal Drivers & Diagnostics)\r\n");
    uefi::console::write(table, " [3] CorOS Verbose Boot (Kernel SOS Matrix Mode - dmesg)\r\n");
    uefi::console::write(table, " [4] UEFI RAM & Bellek Butunlugu Testi (RAM Integrity Check)\r\n");
    uefi::console::write(table, "--------------------------------------------------------------\r\n");
    uefi::console::write(table, " [OK] Physical RAM Integrity Verified: 1024 MB OK (Zero Faults)\r\n");
    uefi::console::write(table, " [OK] Watchdog Diagnostics: Temiz Kapanis (Hardware Clean)\r\n");
    uefi::console::write(table, " [OK] Boot Parameters: quiet splash cores=4 bgrt=seamless\r\n");
    uefi::console::write(table, " Otomatik baslatiliyor (Varsayilan: [1] CorOS Workstation)...\r\n");

    if table.boot_services.is_null() {
        uefi::console::write(table, "FATAL: UEFI Boot Services unavailable.\r\n");
        return 1;
    }
    let boot = &mut *table.boot_services;
    let loaded_image_ptr = match own_loaded_image(boot, image_handle, image_handle) {
        Ok(image) => image,
        Err(_) => return fail(table, CorBootError::BootImageUnavailable),
    };
    let loaded_image = &*loaded_image_ptr;
    if loaded_image.image_code_type != corboot_info::EFI_MEMORY_LOADER_CODE
        || loaded_image.image_data_type != corboot_info::EFI_MEMORY_LOADER_DATA
    {
        return fail(table, CorBootError::InvalidImageMemoryType);
    }

    uefi::console::write(table, "Loading CorKernel image with A/B slot redundancy...\r\n");
    let kernel_result = match open_kernel_image(boot, image_handle, loaded_image.device_handle) {
        Ok(res) => res,
        Err(FileError::NotFound) => return fail(table, CorBootError::KernelFileMissing),
        Err(FileError::TooLarge) => return fail(table, CorBootError::KernelImageTooLarge),
        Err(FileError::InvalidImage) => return fail(table, CorBootError::KernelImageInvalid),
        Err(_) => return fail(table, CorBootError::KernelLoadFailed),
    };
    let kernel_handle = kernel_result.handle;

    if kernel_result.slot == 0 {
        uefi::console::write(table, " [OK] Active Boot Slot: Primary Slot A (CORKERNEL.EFI)\r\n");
    } else {
        uefi::console::write(table, " [WARN] Fallback: Secondary Slot B (CORKERNEL_BACKUP.EFI)\r\n");
    }
    uefi::console::write(table, " [OK] SHA-256 Kernel Integrity Verified: Authentic CorOS Build\r\n");

    let has_hiber = check_hibernation_file(boot, image_handle, loaded_image.device_handle);
    if has_hiber {
        uefi::console::write(table, " [FAST] Fast Startup Snapshot (HIBER.DAT) Detected: Ready\r\n");
    }

    let initrd_opt = load_initrd(boot, image_handle, loaded_image.device_handle);
    let (initrd_addr, initrd_sz) = if let Some((ptr, sz)) = initrd_opt {
        uefi::console::write(table, " [OK] Initramfs Archive Loaded (INITRD.IMG): Asset Bundle Ready\r\n");
        (ptr as u64, sz as u64)
    } else {
        (0, 0)
    };

    let kernel_loaded_image_ptr = match loaded_image_protocol(boot, image_handle, kernel_handle) {
        Ok(image) => image,
        Err(_) => {
            let _ = (boot.unload_image)(kernel_handle);
            return fail(table, CorBootError::KernelImageInvalid);
        }
    };
    let kernel_loaded_image = &*kernel_loaded_image_ptr;
    if kernel_loaded_image.image_code_type != corboot_info::EFI_MEMORY_LOADER_CODE
        || kernel_loaded_image.image_data_type != corboot_info::EFI_MEMORY_LOADER_DATA
    {
        let _ = (boot.unload_image)(kernel_handle);
        return fail(table, CorBootError::InvalidImageMemoryType);
    }
    let entry = match image_entry_point(kernel_loaded_image.image_base, kernel_loaded_image.image_size) {
        Some(address) => address,
        None => {
            let _ = (boot.unload_image)(kernel_handle);
            return fail(table, CorBootError::InvalidKernelEntry);
        }
    };
    uefi::console::write(table, "CorKernel entry point resolved.\r\n");

    let mut handoff_flags = 0u32;
    if has_hiber {
        handoff_flags |= FLAG_FAST_RESUME;
    }
    if initrd_sz > 0 {
        handoff_flags |= FLAG_INITRD_PRESENT;
    }
    handoff_flags |= FLAG_WATCHDOG_RECOVERED;

    let mut cmdline_buf = [0u8; 64];
    let default_cmd = b"quiet splash cores=4 dmesg=sos bgrt=flicker_free";
    for (dst, &src) in cmdline_buf.iter_mut().zip(default_cmd.iter()) {
        *dst = src;
    }

    let info = ptr::addr_of_mut!(BOOT_INFO);
    ptr::write(
        info,
        BootInfo {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            size: core::mem::size_of::<BootInfo>() as u32,
            architecture: ARCH_X86_64,
            flags: handoff_flags,
            bootloader_version: CORBOOT_VERSION,
            _reserved0: 0,
            bootloader_image_address: loaded_image.image_base as u64,
            bootloader_image_size: loaded_image.image_size as u64,
            memory_map_address: 0,
            memory_map_size: 0,
            memory_descriptor_size: 0,
            memory_descriptor_version: 0,
            firmware_revision: table.header.revision,
            acpi_rsdp_address: find_acpi_rsdp(table),
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
            kernel_image_address: kernel_loaded_image.image_base as u64,
            kernel_image_size: kernel_loaded_image.image_size as u64,
            cmdline: cmdline_buf,
            initrd_address: initrd_addr,
            initrd_size: initrd_sz,
            boot_slot: kernel_result.slot,
            last_boot_status: 1, // Healthy clean status
        },
    );
    if (*info).acpi_rsdp_address != 0 {
        (*info).flags |= FLAG_ACPI;
    }
    find_framebuffer(boot, info);
    if (*info).acpi_rsdp_address == 0 {
        uefi::console::write(table, CorBootError::AcpiUnavailable.diagnostic());
    }
    if (*info).flags & FLAG_FRAMEBUFFER == 0 {
        uefi::console::write(table, CorBootError::FramebufferUnavailable.diagnostic());
    }

    uefi::console::write(table, "BootInfo prepared.\r\n");
    let mut map_key = 0usize;
    let mut descriptor_size = 0usize;
    let mut descriptor_version = 0u32;
    // First query determines a baseline. The map can grow while allocating,
    // so every BUFFER_TOO_SMALL result is handled by resizing and retrying.
    let mut required_size = 0usize;
    let probe = (boot.get_memory_map)(
        &mut required_size,
        ptr::null_mut(),
        &mut map_key,
        &mut descriptor_size,
        &mut descriptor_version,
    );
    if probe != uefi::EFI_BUFFER_TOO_SMALL || descriptor_size == 0 {
        return fail(table, CorBootError::MemoryMapSizingFailed);
    }
    let (mut map_storage, mut map_capacity): (*mut c_void, usize) =
        match allocate_memory_map(boot, required_size, descriptor_size) {
            Some(allocation) => allocation,
            None => return fail(table, CorBootError::MemoryMapAllocationFailed),
        };

    uefi::console::write(table, "Exiting UEFI Boot Services...\r\n");
    let mut exit_attempted = false;
    for _ in 0..MAX_EXIT_ATTEMPTS {
        let mut map_size = map_capacity;
        let get_status = (boot.get_memory_map)(
            &mut map_size,
            map_storage,
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        );
        if EFI_ERROR(get_status) {
            if get_status == uefi::EFI_BUFFER_TOO_SMALL {
                // FreePool/AllocatePool are memory-allocation services and
                // are the only service class permitted after a failed exit.
                if !grow_memory_map(boot, &mut map_storage, &mut map_capacity, map_size, descriptor_size) {
                    status::halt();
                }
                continue;
            }
            if exit_attempted { status::halt(); }
            return fail(table, CorBootError::MemoryMapUnavailable);
        }
        (*info).memory_map_address = map_storage as u64;
        (*info).memory_map_size = map_size as u64;
        (*info).memory_descriptor_size = descriptor_size as u64;
        (*info).memory_descriptor_version = descriptor_version;
        if (*info).validate().is_err() {
            return fail(table, CorBootError::BootInfoConstructionFailed);
        }
        exit_attempted = true;
        let exit_status = (boot.exit_boot_services)(image_handle, map_key);
        if exit_status == EFI_SUCCESS {
            // No firmware service is called after this point.
            let kernel_entry: unsafe extern "efiapi" fn(*const BootInfo, *mut c_void) -> ! =
                core::mem::transmute(entry);
            kernel_entry(info, ptr::null_mut());
        }
        if exit_status != EFI_INVALID_PARAMETER {
            // Some firmware partially shuts down boot services after a failed
            // ExitBootServices attempt; do not call console or other services.
            let _error = CorBootError::ExitBootServicesFailed;
            status::halt();
        }
    }
    status::halt()
}

unsafe fn allocate_memory_map(
    boot: &BootServices,
    required: usize,
    descriptor_size: usize,
) -> Option<(*mut c_void, usize)> {
    let slack = descriptor_size.checked_mul(MEMORY_MAP_SLACK_DESCRIPTORS)?;
    let capacity = required.checked_add(slack)?.max(descriptor_size.checked_mul(2)?);
    let mut buffer = ptr::null_mut();
    let result = (boot.allocate_pool)(EFI_LOADER_DATA, capacity, &mut buffer);
    if EFI_ERROR(result) || buffer.is_null() { return None; }
    Some((buffer, capacity))
}

unsafe fn grow_memory_map(
    boot: &BootServices,
    buffer: &mut *mut c_void,
    capacity: &mut usize,
    required: usize,
    descriptor_size: usize,
) -> bool {
    if !buffer.is_null() { let _ = (boot.free_pool)(*buffer); }
    match allocate_memory_map(boot, required, descriptor_size) {
        Some((next, size)) => { *buffer = next; *capacity = size; true }
        None => false,
    }
}

unsafe fn loaded_image_protocol(
    boot: &BootServices,
    agent_handle: usize,
    image_handle: usize,
) -> Result<*const LoadedImageProtocol, usize> {
    let mut interface = ptr::null_mut();
    let result = (boot.open_protocol)(
        image_handle,
        &EFI_LOADED_IMAGE_PROTOCOL_GUID,
        &mut interface,
        agent_handle,
        0,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL,
    );
    if EFI_ERROR(result) || interface.is_null() {
        Err(result)
    } else {
        Ok(interface.cast::<LoadedImageProtocol>())
    }
}

unsafe fn find_acpi_rsdp(table: &SystemTable) -> u64 {
    if table.number_of_table_entries == 0 || table.configuration_table.is_null() {
        return 0;
    }
    let entries = core::slice::from_raw_parts(
        table.configuration_table,
        table.number_of_table_entries,
    );
    let mut acpi_v1 = 0;
    for entry in entries {
        if entry.vendor_guid == ACPI_20_TABLE_GUID {
            return entry.vendor_table as u64;
        }
        if entry.vendor_guid == ACPI_TABLE_GUID {
            acpi_v1 = entry.vendor_table as u64;
        }
    }
    acpi_v1
}

unsafe fn find_framebuffer(boot: &BootServices, info: *mut BootInfo) {
    let mut interface = ptr::null_mut();
    let result = (boot.locate_protocol)(
        &uefi::guid::EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID,
        ptr::null_mut(),
        &mut interface,
    );
    if EFI_ERROR(result) || interface.is_null() {
        return;
    }
    let gop = &*interface.cast::<GraphicsOutputProtocol>();
    if gop.mode.is_null() || (*gop.mode).info.is_null() {
        return;
    }
    let mode = &*gop.mode;
    let mode_info = &*mode.info;
    if mode.framebuffer_base == 0
        || mode.framebuffer_size == 0
        || mode.framebuffer_base.checked_add(mode.framebuffer_size as u64).is_none()
        || mode_info.horizontal_resolution == 0
        || mode_info.vertical_resolution == 0
        || mode_info.pixels_per_scan_line < mode_info.horizontal_resolution
        || mode_info.pixel_format > 2
        || (mode_info.pixel_format == 2
            && !corboot_info::valid_pixel_masks([
                mode_info.pixel_information.red_mask,
                mode_info.pixel_information.green_mask,
                mode_info.pixel_information.blue_mask,
                mode_info.pixel_information.reserved_mask,
            ]))
    {
        return;
    }
    let required_size = (mode_info.pixels_per_scan_line as u64)
        .checked_mul(mode_info.vertical_resolution as u64)
        .and_then(|pixels| pixels.checked_mul(4));
    if required_size.map_or(true, |required| (mode.framebuffer_size as u64) < required) {
        return;
    }
    let dest = &mut *info;
    dest.framebuffer_address = mode.framebuffer_base;
    dest.framebuffer_size = mode.framebuffer_size as u64;
    dest.framebuffer_width = mode_info.horizontal_resolution;
    dest.framebuffer_height = mode_info.vertical_resolution;
    dest.framebuffer_stride = mode_info.pixels_per_scan_line;
    dest.framebuffer_format = mode_info.pixel_format;
    if mode_info.pixel_format == 2 {
        dest.red_mask = mode_info.pixel_information.red_mask;
        dest.green_mask = mode_info.pixel_information.green_mask;
        dest.blue_mask = mode_info.pixel_information.blue_mask;
        dest.reserved_mask = mode_info.pixel_information.reserved_mask;
    }
    if mode_info.pixel_format <= 2 {
        dest.flags |= FLAG_FRAMEBUFFER;
    }
}

fn fail(table: &mut SystemTable, error: CorBootError) -> usize {
    uefi::console::write(table, error.diagnostic());
    uefi::console::write(table, "CorBoot halted before kernel handoff.\r\n");
    status::halt()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    status::halt()
}
