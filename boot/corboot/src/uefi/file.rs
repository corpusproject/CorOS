use core::{ffi::c_void, mem::size_of, ptr};

use super::{
    guid::{EFI_FILE_INFO_GUID, EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID},
    BootServices, LoadedImageProtocol, EFI_ERROR, EFI_LOADER_DATA, EFI_OPEN_PROTOCOL_GET_PROTOCOL,
};

const EFI_BUFFER_TOO_SMALL: usize = (1usize << (usize::BITS - 1)) | 5;
const EFI_FILE_MODE_READ: u64 = 1;
const MAX_KERNEL_BYTES: usize = 32 * 1024 * 1024;
const KERNEL_PATH_SLOT_A: &[u8] = b"\\EFI\\COROS\\CORKERNEL.EFI\0";
const KERNEL_PATH_SLOT_B: &[u8] = b"\\EFI\\COROS\\CORKERNEL_BACKUP.EFI\0";
const HIBERNATION_PATH: &[u8] = b"\\EFI\\COROS\\HIBER.DAT\0";
const INITRD_PATH: &[u8] = b"\\EFI\\COROS\\INITRD.IMG\0";

#[derive(Clone, Copy)]
pub enum FileError {
    NotFound,
    TooLarge,
    InvalidImage,
    Firmware,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // sha256/file_size are retained for diagnostics and future verification.
pub struct KernelLoadResult {
    pub handle: usize,
    pub slot: u32,
    pub sha256: [u8; 32],
    pub file_size: usize,
}

#[repr(C)]
struct SimpleFileSystemProtocol {
    revision: u64,
    open_volume: unsafe extern "efiapi" fn(*mut Self, *mut *mut FileProtocol) -> usize,
}

#[repr(C)]
struct FileProtocol {
    revision: u64,
    open: unsafe extern "efiapi" fn(
        *mut Self,
        *mut *mut FileProtocol,
        *const u16,
        u64,
        u64,
    ) -> usize,
    close: unsafe extern "efiapi" fn(*mut Self) -> usize,
    delete: usize,
    read: unsafe extern "efiapi" fn(*mut Self, *mut usize, *mut c_void) -> usize,
    write: usize,
    get_position: usize,
    set_position: usize,
    get_info: unsafe extern "efiapi" fn(
        *mut Self,
        *const super::Guid,
        *mut usize,
        *mut c_void,
    ) -> usize,
    set_info: usize,
    flush: usize,
    open_ex: usize,
    read_ex: usize,
    write_ex: usize,
    flush_ex: usize,
}

const _: [(); 16] = [(); size_of::<SimpleFileSystemProtocol>()];
const _: [(); 120] = [(); size_of::<FileProtocol>()];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = [
        0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let k = [
        0x428a2f98u32, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut block = [0u8; 64];
    let mut offset = 0;

    while offset + 64 <= data.len() {
        block.copy_from_slice(&data[offset..offset + 64]);
        process_block(&block, &mut h, &k);
        offset += 64;
    }

    let rem = data.len() - offset;
    for i in 0..rem {
        block[i] = data[offset + i];
    }
    block[rem] = 0x80;
    for i in (rem + 1)..64 {
        block[i] = 0;
    }

    if rem >= 56 {
        process_block(&block, &mut h, &k);
        block = [0u8; 64];
    }

    let len_bytes = bit_len.to_be_bytes();
    block[56..64].copy_from_slice(&len_bytes);
    process_block(&block, &mut h, &k);

    let mut out = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[inline(always)]
fn process_block(block: &[u8; 64], h: &mut [u32; 8], k: &[u32; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let mut a = h[0]; let mut b = h[1]; let mut c = h[2]; let mut d = h[3];
    let mut e = h[4]; let mut f = h[5]; let mut g = h[6]; let mut hh = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g; g = f; f = e; e = d.wrapping_add(temp1);
        d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Reads a specific file path into a pool buffer.
unsafe fn read_raw_file(
    boot: &BootServices,
    parent_image: usize,
    device_handle: usize,
    path_bytes: &[u8],
) -> Result<(*mut u8, usize), FileError> {
    let mut fs_interface = ptr::null_mut();
    let status = (boot.open_protocol)(
        device_handle,
        &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        &mut fs_interface,
        parent_image,
        0,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL,
    );
    if EFI_ERROR(status) || fs_interface.is_null() {
        return Err(FileError::Firmware);
    }
    let fs = &mut *fs_interface.cast::<SimpleFileSystemProtocol>();
    let mut root = ptr::null_mut();
    if EFI_ERROR((fs.open_volume)(fs, &mut root)) || root.is_null() {
        return Err(FileError::Firmware);
    }

    let mut path = [0u16; 64];
    for (out, byte) in path.iter_mut().zip(path_bytes.iter()) {
        *out = *byte as u16;
        if *byte == 0 {
            break;
        }
    }
    let mut file = ptr::null_mut();
    let open_status = ((*root).open)(root, &mut file, path.as_ptr(), EFI_FILE_MODE_READ, 0);
    let _ = ((*root).close)(root);
    if EFI_ERROR(open_status) || file.is_null() {
        return Err(FileError::NotFound);
    }

    let mut info_size = 0usize;
    let query_status = ((*file).get_info)(file, &EFI_FILE_INFO_GUID, &mut info_size, ptr::null_mut());
    if query_status != EFI_BUFFER_TOO_SMALL || info_size < 16 {
        let _ = ((*file).close)(file);
        return Err(FileError::Firmware);
    }
    let mut info = ptr::null_mut();
    let alloc_status = (boot.allocate_pool)(EFI_LOADER_DATA, info_size, &mut info);
    if EFI_ERROR(alloc_status) || info.is_null() {
        let _ = ((*file).close)(file);
        return Err(FileError::Firmware);
    }
    let mut actual_info_size = info_size;
    let info_status = ((*file).get_info)(file, &EFI_FILE_INFO_GUID, &mut actual_info_size, info);
    if EFI_ERROR(info_status) || actual_info_size < 16 {
        let _ = (boot.free_pool)(info);
        let _ = ((*file).close)(file);
        return Err(FileError::Firmware);
    }
    let file_size = ptr::read_unaligned(info.cast::<u64>().add(1)) as usize;
    let _ = (boot.free_pool)(info);
    if file_size == 0 {
        let _ = ((*file).close)(file);
        return Err(FileError::InvalidImage);
    }
    if file_size > MAX_KERNEL_BYTES {
        let _ = ((*file).close)(file);
        return Err(FileError::TooLarge);
    }

    let mut buffer = ptr::null_mut();
    let alloc_status = (boot.allocate_pool)(EFI_LOADER_DATA, file_size, &mut buffer);
    if EFI_ERROR(alloc_status) || buffer.is_null() {
        let _ = ((*file).close)(file);
        return Err(FileError::Firmware);
    }
    let mut read_size = file_size;
    let read_status = ((*file).read)(file, &mut read_size, buffer);
    let _ = ((*file).close)(file);
    if EFI_ERROR(read_status) || read_size != file_size {
        let _ = (boot.free_pool)(buffer);
        return Err(FileError::Firmware);
    }

    Ok((buffer.cast::<u8>(), file_size))
}

/// Reads and firmware-loads CorKernel with A/B slot redundancy and SHA-256 integrity calculation.
pub unsafe fn open_kernel_image(
    boot: &BootServices,
    parent_image: usize,
    device_handle: usize,
) -> Result<KernelLoadResult, FileError> {
    // Try Slot A first, then fallback to Slot B (Self-Healing A/B Dual Slot)
    let (buffer, file_size, slot) = match read_raw_file(boot, parent_image, device_handle, KERNEL_PATH_SLOT_A) {
        Ok((b, s)) => (b, s, 0u32),
        Err(_) => {
            // Attempt Slot B fallback
            let (b, s) = read_raw_file(boot, parent_image, device_handle, KERNEL_PATH_SLOT_B)?;
            (b, s, 1u32)
        }
    };

    let slice = core::slice::from_raw_parts(buffer, file_size);
    let sha256_digest = sha256(slice);

    let mut kernel_handle = 0usize;
    let load_status = (boot.load_image)(
        0,
        parent_image,
        ptr::null(),
        buffer.cast_const().cast::<c_void>(),
        file_size,
        &mut kernel_handle,
    );
    let _ = (boot.free_pool)(buffer.cast::<c_void>());
    if EFI_ERROR(load_status) || kernel_handle == 0 {
        return Err(FileError::Firmware);
    }

    Ok(KernelLoadResult {
        handle: kernel_handle,
        slot,
        sha256: sha256_digest,
        file_size,
    })
}

/// Checks if a fast startup / hibernation resume image exists on disk.
pub unsafe fn check_hibernation_file(
    boot: &BootServices,
    parent_image: usize,
    device_handle: usize,
) -> bool {
    match read_raw_file(boot, parent_image, device_handle, HIBERNATION_PATH) {
        Ok((buffer, _)) => {
            let _ = (boot.free_pool)(buffer.cast::<c_void>());
            true
        }
        Err(_) => false,
    }
}

/// Loads initramfs archive (/EFI/COROS/INITRD.IMG) into memory pool if present.
pub unsafe fn load_initrd(
    boot: &BootServices,
    parent_image: usize,
    device_handle: usize,
) -> Option<(*mut u8, usize)> {
    read_raw_file(boot, parent_image, device_handle, INITRD_PATH).ok()
}

pub unsafe fn own_loaded_image(
    boot: &BootServices,
    image_handle: usize,
    agent_handle: usize,
) -> Result<*const LoadedImageProtocol, usize> {
    let mut interface = ptr::null_mut();
    let result = (boot.open_protocol)(
        image_handle,
        &super::guid::EFI_LOADED_IMAGE_PROTOCOL_GUID,
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
