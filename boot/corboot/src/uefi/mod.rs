//! Minimal UEFI ABI declarations used by CorBoot.
//!
//! These layouts and function signatures follow UEFI 2.10. Pointers and
//! protocol calls are only valid during the firmware boot-services session.

pub mod console;
pub mod file;
pub mod guid;
pub mod pe;

use core::{ffi::c_void, mem::size_of};

pub const EFI_SUCCESS: usize = 0;
pub const EFI_INVALID_PARAMETER: usize = (1usize << (usize::BITS - 1)) | 2;
pub const EFI_BUFFER_TOO_SMALL: usize = (1usize << (usize::BITS - 1)) | 5;
pub const EFI_LOADER_DATA: u32 = 2;
pub const EFI_OPEN_PROTOCOL_GET_PROTOCOL: u32 = 0x0000_0002;

#[inline]
#[allow(non_snake_case)] // Mirrors the UEFI specification's EFI_ERROR() macro name.
pub const fn EFI_ERROR(status: usize) -> bool {
    (status >> (usize::BITS - 1)) != 0
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SimpleTextOutputProtocol {
    pub reset: usize,
    pub output_string: unsafe extern "efiapi" fn(*mut Self, *const u16) -> usize,
    pub test_string: usize,
    pub query_mode: usize,
    pub set_mode: usize,
    pub set_attribute: usize,
    pub clear_screen: usize,
    pub set_cursor_position: usize,
    pub enable_cursor: usize,
    pub mode: usize,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *const c_void,
}

#[repr(C)]
pub struct SystemTable {
    pub header: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: usize,
    pub con_in: *mut c_void,
    pub console_out_handle: usize,
    pub con_out: *mut SimpleTextOutputProtocol,
    pub standard_error_handle: usize,
    pub std_err: *mut SimpleTextOutputProtocol,
    pub runtime_services: *mut c_void,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const ConfigurationTable,
}

#[repr(C)]
pub struct BootServices {
    pub header: TableHeader,
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    pub allocate_pages: usize,
    pub free_pages: usize,
    pub get_memory_map: unsafe extern "efiapi" fn(
        *mut usize,
        *mut c_void,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> usize,
    pub allocate_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut c_void) -> usize,
    pub free_pool: unsafe extern "efiapi" fn(*mut c_void) -> usize,
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: usize,
    pub reserved: *mut c_void,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    pub load_image: unsafe extern "efiapi" fn(
        u8,
        usize,
        *const c_void,
        *const c_void,
        usize,
        *mut usize,
    ) -> usize,
    pub start_image: usize,
    pub exit: usize,
    pub unload_image: unsafe extern "efiapi" fn(usize) -> usize,
    pub exit_boot_services: unsafe extern "efiapi" fn(usize, usize) -> usize,
    pub get_next_monotonic_count: usize,
    pub stall: usize,
    pub set_watchdog_timer: usize,
    pub connect_controller: usize,
    pub disconnect_controller: usize,
    pub open_protocol: unsafe extern "efiapi" fn(
        usize,
        *const Guid,
        *mut *mut c_void,
        usize,
        usize,
        u32,
    ) -> usize,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
    pub locate_protocol: unsafe extern "efiapi" fn(
        *const Guid,
        *const c_void,
        *mut *mut c_void,
    ) -> usize,
    pub install_multiple_protocol_interfaces: usize,
    pub uninstall_multiple_protocol_interfaces: usize,
    pub calculate_crc32: usize,
    pub copy_mem: usize,
    pub set_mem: usize,
    pub create_event_ex: usize,
}

#[repr(C)]
pub struct LoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: usize,
    pub system_table: *mut SystemTable,
    pub device_handle: usize,
    pub file_path: *mut c_void,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut u8,
    pub image_size: usize,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

#[repr(C)]
pub struct PixelBitmask {
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
}

#[repr(C)]
pub struct GraphicsOutputModeInfo {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: PixelBitmask,
    pub pixels_per_scan_line: u32,
}

#[repr(C)]
pub struct GraphicsOutputMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *mut GraphicsOutputModeInfo,
    pub size_of_info: usize,
    pub framebuffer_base: u64,
    pub framebuffer_size: usize,
}

#[repr(C)]
pub struct GraphicsOutputProtocol {
    pub query_mode: usize,
    pub set_mode: usize,
    pub blt: usize,
    pub mode: *mut GraphicsOutputMode,
}

const _: [(); 24] = [(); size_of::<TableHeader>()];
const _: [(); 120] = [(); size_of::<SystemTable>()];
const _: [(); 376] = [(); size_of::<BootServices>()];
const _: [(); 96] = [(); size_of::<LoadedImageProtocol>()];
const _: [(); 24] = [(); size_of::<ConfigurationTable>()];
const _: [(); 16] = [(); size_of::<PixelBitmask>()];
const _: [(); 36] = [(); size_of::<GraphicsOutputModeInfo>()];
const _: [(); 40] = [(); size_of::<GraphicsOutputMode>()];
const _: [(); 32] = [(); size_of::<GraphicsOutputProtocol>()];

pub mod status {
    #[inline]
    pub fn halt() -> ! {
        loop {
            unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)); }
        }
    }
}
