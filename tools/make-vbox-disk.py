import os
import struct
import sys
import subprocess

def create_fat32_image(esp_dir, output_img, size_mb=64):
    sector_size = 512
    total_sectors = size_mb * 1024 * 1024 // sector_size
    part_start_lba = 2048
    part_sectors = total_sectors - part_start_lba
    
    sectors_per_cluster = 1
    cluster_size = sector_size * sectors_per_cluster
    reserved_sectors = 32
    num_fats = 2
    
    # Calculate sectors per FAT
    total_clusters = (part_sectors - reserved_sectors) // sectors_per_cluster
    fat_size_bytes = (total_clusters + 2) * 4
    fat_sectors = (fat_size_bytes + sector_size - 1) // sector_size
    # Round fat_sectors to a nice number
    fat_sectors = ((fat_sectors + 31) // 32) * 32
    
    first_data_sector = reserved_sectors + (num_fats * fat_sectors)
    data_sectors = part_sectors - first_data_sector
    cluster_count = data_sectors // sectors_per_cluster
    
    if cluster_count < 65525:
        raise ValueError(f"Cluster count {cluster_count} too small for FAT32! Minimum is 65525.")
        
    img = bytearray(total_sectors * sector_size)
    
    # 1. MBR Partition Table
    # Signature
    img[510:512] = b"\x55\xaa"
    # Partition entry 0: Bootable, Type 0xEF (ESP)
    part_entry = bytearray(16)
    part_entry[0] = 0x80 # Bootable
    part_entry[1:4] = b"\x00\x20\x21" # CHS Start
    part_entry[4] = 0xEF # EFI System Partition
    part_entry[5:8] = b"\xfe\xff\xff" # CHS End
    struct.pack_into("<I", part_entry, 8, part_start_lba)
    struct.pack_into("<I", part_entry, 12, part_sectors)
    img[446:462] = part_entry
    
    # 2. VBR (Volume Boot Record)
    vbr_offset = part_start_lba * sector_size
    vbr = bytearray(512)
    vbr[0:3] = b"\xeb\x58\x90"
    vbr[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", vbr, 11, sector_size)
    vbr[13] = sectors_per_cluster
    struct.pack_into("<H", vbr, 14, reserved_sectors)
    vbr[16] = num_fats
    vbr[21] = 0xF8 # Media: Fixed disk
    struct.pack_into("<H", vbr, 24, 63) # SecPerTrk
    struct.pack_into("<H", vbr, 26, 255) # NumHeads
    struct.pack_into("<I", vbr, 28, part_start_lba) # HiddSec
    struct.pack_into("<I", vbr, 32, part_sectors) # TotSec32
    struct.pack_into("<I", vbr, 36, fat_sectors) # FATSz32
    struct.pack_into("<I", vbr, 44, 2) # RootClus = 2
    struct.pack_into("<H", vbr, 48, 1) # FSInfo = 1
    struct.pack_into("<H", vbr, 50, 6) # BkBootSec = 6
    vbr[64] = 0x80 # DrvNum
    vbr[66] = 0x29 # BootSig
    struct.pack_into("<I", vbr, 67, 0x12345678) # VolID
    vbr[71:82] = b"COROS ESP  "
    vbr[82:90] = b"FAT32   "
    vbr[510:512] = b"\x55\xaa"
    
    img[vbr_offset:vbr_offset+512] = vbr
    # Backup VBR at sector 6
    bkup_offset = vbr_offset + 6 * sector_size
    img[bkup_offset:bkup_offset+512] = vbr
    
    # FSInfo at sector 1
    fsinfo_offset = vbr_offset + sector_size
    fsinfo = bytearray(512)
    struct.pack_into("<I", fsinfo, 0, 0x41615252) # LeadSig
    struct.pack_into("<I", fsinfo, 484, 0x61417272) # StrucSig
    struct.pack_into("<I", fsinfo, 488, 0xFFFFFFFF) # Free_Count
    struct.pack_into("<I", fsinfo, 492, 0xFFFFFFFF) # Nxt_Free
    struct.pack_into("<I", fsinfo, 508, 0xAA550000) # TrailSig
    img[fsinfo_offset:fsinfo_offset+512] = fsinfo
    
    # 3. FAT Tables & Data Allocation
    fat = bytearray(fat_sectors * sector_size)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8) # Cluster 0
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF) # Cluster 1
    
    # Helper to set FAT entry
    def set_fat(cluster, val):
        struct.pack_into("<I", fat, cluster * 4, val & 0x0FFFFFFF)
        
    def get_cluster_offset(cluster):
        return vbr_offset + (first_data_sector + (cluster - 2) * sectors_per_cluster) * sector_size
        
    next_free_cluster = 2
    
    def alloc_cluster():
        nonlocal next_free_cluster
        c = next_free_cluster
        next_free_cluster += 1
        set_fat(c, 0x0FFFFFFF) # Mark as EOF initially
        return c
        
    def write_dir_entry(dir_cluster, index, name8, ext3, attr, first_cluster, file_size):
        offset = get_cluster_offset(dir_cluster) + index * 32
        entry = bytearray(32)
        entry[0:8] = name8.ljust(8).encode("ascii")
        entry[8:11] = ext3.ljust(3).encode("ascii")
        entry[11] = attr
        struct.pack_into("<H", entry, 20, (first_cluster >> 16) & 0xFFFF)
        struct.pack_into("<H", entry, 26, first_cluster & 0xFFFF)
        struct.pack_into("<I", entry, 28, file_size)
        img[offset:offset+32] = entry

    # Root Directory is Cluster 2
    root_cluster = alloc_cluster() # returns 2
    
    # Create EFI Directory -> Cluster 3
    efi_cluster = alloc_cluster()
    write_dir_entry(root_cluster, 0, "EFI", "", 0x10, efi_cluster, 0)
    
    # In EFI directory: . and .. and BOOT and COROS
    write_dir_entry(efi_cluster, 0, ".", "", 0x10, efi_cluster, 0)
    write_dir_entry(efi_cluster, 1, "..", "", 0x10, root_cluster, 0)
    
    boot_cluster = alloc_cluster()
    coros_cluster = alloc_cluster()
    write_dir_entry(efi_cluster, 2, "BOOT", "", 0x10, boot_cluster, 0)
    write_dir_entry(efi_cluster, 3, "COROS", "", 0x10, coros_cluster, 0)
    
    # In BOOT directory: . and .. and BOOTX64.EFI
    write_dir_entry(boot_cluster, 0, ".", "", 0x10, boot_cluster, 0)
    write_dir_entry(boot_cluster, 1, "..", "", 0x10, efi_cluster, 0)
    
    # In COROS directory: . and .. and CORKERNEL.EFI
    write_dir_entry(coros_cluster, 0, ".", "", 0x10, coros_cluster, 0)
    write_dir_entry(coros_cluster, 1, "..", "", 0x10, efi_cluster, 0)
    
    def copy_file_data(file_path):
        if not os.path.exists(file_path):
            return 0, 0
        with open(file_path, "rb") as f:
            data = f.read()
        size = len(data)
        if size == 0:
            return 0, 0
        chunks = [data[i:i+cluster_size] for i in range(0, size, cluster_size)]
        first_c = 0
        prev_c = 0
        for chunk in chunks:
            c = alloc_cluster()
            if first_c == 0:
                first_c = c
            if prev_c != 0:
                set_fat(prev_c, c)
            set_fat(c, 0x0FFFFFFF)
            prev_c = c
            c_offset = get_cluster_offset(c)
            img[c_offset:c_offset+len(chunk)] = chunk
        return first_c, size

    def lfn_checksum(shortname11):
        chk = 0
        for b in shortname11:
            chk = (((chk & 1) << 7) + (chk >> 1) + b) & 0xFF
        return chk

    def write_file_entry(dir_cluster, start_index, long_name, name8, ext3, first_cluster, file_size):
        short11 = (name8.ljust(8) + ext3.ljust(3)).encode("ascii")
        chk = lfn_checksum(short11)
        slices = [long_name[i:i+13] for i in range(0, len(long_name), 13)]
        num_entries = len(slices)
        cur_idx = start_index
        for idx, s in enumerate(reversed(slices)):
            seq = num_entries - idx
            if idx == 0:
                seq |= 0x40
            u16 = s.encode("utf-16le")
            if len(s) < 13:
                u16 += b"\x00\x00"
                while len(u16) < 26:
                    u16 += b"\xff\xff"
            entry = bytearray(32)
            entry[0] = seq
            entry[1:11] = u16[0:10]
            entry[11] = 0x0F
            entry[12] = 0x00
            entry[13] = chk
            entry[14:26] = u16[10:22]
            entry[26:28] = b"\x00\x00"
            entry[28:32] = u16[22:26]
            offset = get_cluster_offset(dir_cluster) + cur_idx * 32
            img[offset:offset+32] = entry
            cur_idx += 1
        write_dir_entry(dir_cluster, cur_idx, name8, ext3, 0x20, first_cluster, file_size)
        return cur_idx + 1

    bootx64_path = os.path.join(esp_dir, "EFI", "BOOT", "BOOTX64.EFI")
    corkernel_path = os.path.join(esp_dir, "EFI", "COROS", "CORKERNEL.EFI")
    
    c_boot, s_boot = copy_file_data(bootx64_path)
    if c_boot:
        write_file_entry(boot_cluster, 2, "BOOTX64.EFI", "BOOTX64", "EFI", c_boot, s_boot)
        
    cur_coros_idx = 2
    c_kern, s_kern = copy_file_data(corkernel_path)
    if c_kern:
        cur_coros_idx = write_file_entry(coros_cluster, cur_coros_idx, "CORKERNEL.EFI", "CORKER~1", "EFI", c_kern, s_kern)

    hesap_path = os.path.join(esp_dir, "EFI", "COROS", "HESAP.ELF")
    c_hesap, s_hesap = copy_file_data(hesap_path)
    if c_hesap:
        cur_coros_idx = write_file_entry(coros_cluster, cur_coros_idx, "HESAP.ELF", "HESAP", "ELF", c_hesap, s_hesap)

    app_path = os.path.join(esp_dir, "EFI", "COROS", "APP.ELF")
    c_app, s_app = copy_file_data(app_path)
    if c_app:
        cur_coros_idx = write_file_entry(coros_cluster, cur_coros_idx, "APP.ELF", "APP", "ELF", c_app, s_app)

    # Write FAT1 and FAT2
    fat1_offset = vbr_offset + reserved_sectors * sector_size
    img[fat1_offset:fat1_offset+len(fat)] = fat
    fat2_offset = fat1_offset + fat_sectors * sector_size
    img[fat2_offset:fat2_offset+len(fat)] = fat
    
    os.makedirs(os.path.dirname(os.path.abspath(output_img)), exist_ok=True)
    with open(output_img, "wb") as f:
        f.write(img)
    print(f"FAT32 disk image created: {output_img} ({size_mb} MB, {cluster_count} clusters)")

    # Convert to VDI if requested or if output_vdi is provided
    output_vdi = output_img.rsplit(".", 1)[0] + ".vdi"
    vbox_candidates = [
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        "VBoxManage",
    ]
    vbox_exe = None
    for cand in vbox_candidates:
        if os.path.exists(cand) or subprocess.run(["where", cand], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            vbox_exe = cand
            break
            
    if vbox_exe:
        if os.path.exists(output_vdi):
            os.remove(output_vdi)
        res = subprocess.run([vbox_exe, "convertfromraw", output_img, output_vdi, "--format", "VDI"], capture_output=True, text=True)
        if res.returncode == 0:
            print(f"VirtualBox disk image created: {output_vdi}")
        else:
            print(f"VBoxManage warning: {res.stderr.strip()}", file=sys.stderr)

if __name__ == "__main__":
    esp = sys.argv[1] if len(sys.argv) > 1 else "dist/esp"
    out = sys.argv[2] if len(sys.argv) > 2 else "dist/coros.img"
    create_fat32_image(esp, out)
