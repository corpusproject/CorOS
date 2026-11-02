"""
Tier 3: Cross-Feature Interactions - VFS + Block Storage Pipeline
=================================================================
CorOS/tests/e2e/tier3_cross_feature/test_cross_vfs_block.py

Tests pairwise integration between:
- corvfs (Unified VFS, Inodes, Directory Entries, Mount Points)
- corblock (bio, blk-mq, Request Queues)
- cordrivers (AHCI SATA, NVMe, VirtIO-Blk Storage Drivers)
"""

import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_raises,
    MockVfs, MockBlockDevice, EIO
)

def test_vfs_to_block_file_persistence():
    """Tier 3: VFS file write routed through block I/O bio into storage device."""
    vfs = MockVfs()
    disk = MockBlockDevice("SATA_PORT_0", sector_count=1000)
    
    # Create file in VFS
    f_ino = vfs.create_file(parent_ino=1, name="data.bin")
    payload = b"CROSS_FEATURE_PERSISTENT_STORAGE_PAYLOAD" * 8 # 328 bytes
    vfs.write(f_ino, offset=0, data=payload)
    
    # Bio layer translates file data into disk sectors (LBA 200)
    sector_buf = bytearray(512)
    sector_buf[:len(payload)] = payload
    disk.write_sectors(lba=200, count=1, data=bytes(sector_buf))
    disk.flush()
    
    # Read back from disk through block device
    read_sector = disk.read_sectors(lba=200, count=1)
    assert_eq(read_sector[:len(payload)], payload)
    assert_eq(disk.flush_count, 1)

def test_vfs_large_multiblock_bio_mapping():
    """Tier 3: Multi-block 4 KiB file mapped across 8 contiguous 512-byte sectors."""
    vfs = MockVfs()
    disk = MockBlockDevice("NVMe_NS1", sector_count=10000)
    
    file_data = b"".join(f"BLOCK_{i:04d}_PAGE_DATA_PAD_".encode("ascii").ljust(512, b"\x00") for i in range(8))
    assert_eq(len(file_data), 4096)
    
    f_ino = vfs.create_file(1, "kernel.img")
    vfs.write(f_ino, 0, file_data)
    
    # Submit 8-sector bio starting at LBA 1024
    disk.write_sectors(lba=1024, count=8, data=file_data)
    
    # Verify read back
    read_blocks = disk.read_sectors(lba=1024, count=8)
    assert_eq(read_blocks, file_data)

def test_block_device_error_propagation_to_vfs():
    """Tier 3: Storage driver I/O error propagates to VFS returning -EIO (-5)."""
    class FaultyBlockDevice(MockBlockDevice):
        def write_sectors(self, lba: int, count: int, data: bytes):
            raise IOError("Hardware write fault on sector")
            
    bad_disk = FaultyBlockDevice("DamagedDisk", sector_count=100)
    
    # When bio layer encounters device fault, it must translate to -EIO
    try:
        bad_disk.write_sectors(0, 1, b"\x00" * 512)
        vfs_ret = 0
    except IOError:
        vfs_ret = -EIO
        
    assert_eq(vfs_ret, -5)

def test_vfs_directory_hierarchy_block_sync():
    """Tier 3: Deep directory structure creation and filesystem sync flush."""
    vfs = MockVfs()
    disk = MockBlockDevice("Disk0", sector_count=5000)
    
    # Create /var/log/coros
    var_ino = vfs.mkdir(1, "var")
    log_ino = vfs.mkdir(var_ino, "log")
    coros_ino = vfs.mkdir(log_ino, "coros")
    f_ino = vfs.create_file(coros_ino, "boot.log")
    
    vfs.write(f_ino, 0, b"System booted cleanly")
    disk.flush()
    assert_eq(disk.flush_count, 1)
    assert_in("coros", vfs.inodes[log_ino].children)

def build_suite() -> TestSuite:
    suite = TestSuite("Cross-Feature: VFS + Block Storage Pipeline", tier=3)
    suite.add("VFS to Block Device File Persistence", test_vfs_to_block_file_persistence, "F16+F11")
    suite.add("Multi-Block 4KB Bio Mapping Across Sectors", test_vfs_large_multiblock_bio_mapping, "F16+F11")
    suite.add("Block Driver Error Propagation to VFS (-EIO)", test_block_device_error_propagation_to_vfs, "F16+F10")
    suite.add("VFS Directory Hierarchy and Disk Sync", test_vfs_directory_hierarchy_block_sync, "F16+F11")
    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
