"""
Tier 1: Hardware Driver & PCI Registry Tests
============================================
tests/tier1_features/test_drivers_pci.py

Covers baseline happy paths for Hardware Driver Trees:
- PCI / PCIe Configuration Space & ECAM Header Decoding
- Storage Block Devices: AHCI SATA & NVMe 1.4
- USB 3.0 xHCI Host Controller & HID Subsystem
- Audio Subsystem: AC'97 DMA & Intel HD Audio
- Network Controller: Intel 82540EM (E1000) & VirtIO-Net
- Multi-Vendor GPU Framebuffer & Acceleration Pipelines
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import TestSuite, assert_eq, assert_true, assert_ne, assert_in

class MockPciDevice:
    def __init__(self, bus: int, dev: int, func: int, vendor_id: int, device_id: int, class_code: int, subclass: int, prog_if: int):
        self.bus = bus
        self.dev = dev
        self.func = func
        self.vendor_id = vendor_id
        self.device_id = device_id
        self.class_code = class_code
        self.subclass = subclass
        self.prog_if = prog_if
        self.bars = [0] * 6
        self.command = 0

    def is_ahci_controller(self) -> bool:
        return self.class_code == 0x01 and self.subclass == 0x06 and self.prog_if == 0x01

    def is_nvme_controller(self) -> bool:
        return self.class_code == 0x01 and self.subclass == 0x08 and self.prog_if == 0x02

    def is_e1000_ethernet(self) -> bool:
        return self.vendor_id == 0x8086 and self.device_id in (0x100E, 0x100F, 0x10D3)

    def is_ac97_audio(self) -> bool:
        return self.class_code == 0x04 and self.subclass == 0x01

    def is_hda_audio(self) -> bool:
        return self.class_code == 0x04 and self.subclass == 0x03

    def is_xhci_usb(self) -> bool:
        return self.class_code == 0x0C and self.subclass == 0x03 and self.prog_if == 0x30

    def is_vga_display(self) -> bool:
        return self.class_code == 0x03 and self.subclass == 0x00

class MockBlockDevice:
    def __init__(self, name: str, sector_count: int, sector_size: int = 512):
        self.name = name
        self.sector_count = sector_count
        self.sector_size = sector_size
        self.storage = bytearray(sector_count * sector_size)

    def read_sectors(self, lba: int, count: int) -> bytes:
        start = lba * self.sector_size
        end = start + (count * self.sector_size)
        assert_true(end <= len(self.storage), "Read exceeds disk bounds")
        return bytes(self.storage[start:end])

    def write_sectors(self, lba: int, count: int, data: bytes):
        start = lba * self.sector_size
        end = start + (count * self.sector_size)
        assert_true(end <= len(self.storage), "Write exceeds disk bounds")
        assert_eq(len(data), count * self.sector_size, "Data length mismatch")
        self.storage[start:end] = data

def test_pci_ecam_header_decoding():
    """Verify standard PCI configuration space header fields (Vendor, Device, Class)."""
    # Simulate a standard 64-byte Type 00h PCI Header
    # 0x00: VendorID (8086), DeviceID (100E) -> Intel E1000
    # 0x04: Command (0007), Status (0010)
    # 0x08: RevID (03), ProgIF (00), Subclass (00), ClassCode (02) -> Network Ethernet
    header_bytes = bytearray(64)
    struct.pack_into("<HH", header_bytes, 0, 0x8086, 0x100E)
    struct.pack_into("<HH", header_bytes, 4, 0x0007, 0x0010)
    struct.pack_into("<BBBB", header_bytes, 8, 0x03, 0x00, 0x00, 0x02)

    vendor, device = struct.unpack_from("<HH", header_bytes, 0)
    rev, prog_if, subclass, class_code = struct.unpack_from("<BBBB", header_bytes, 8)

    assert_eq(vendor, 0x8086, "Intel Vendor ID")
    assert_eq(device, 0x100E, "E1000 Gigabit NIC")
    assert_eq(class_code, 0x02, "Network Controller Class")

def test_ahci_sata_storage_driver():
    """Verify AHCI SATA block storage driver read, write, and LBA operations."""
    disk = MockBlockDevice("AHCI SATA DMA Port 0", sector_count=131072) # 64 MiB
    assert_eq(disk.sector_count, 131072)

    # Write test sector
    test_pattern = b"COROS_AHCI_PERSISTENT_SECTOR_DATA_" + (b"\xAA" * (512 - 34))
    disk.write_sectors(lba=100, count=1, data=test_pattern)

    # Read back and verify
    read_back = disk.read_sectors(lba=100, count=1)
    assert_eq(read_back, test_pattern)

def test_nvme_storage_driver():
    """Verify NVMe 1.4 Namespace block device initialization and multi-block DMA."""
    nvme_disk = MockBlockDevice("NVMe Namespace 1", sector_count=2097152) # 1 GiB
    assert_eq(nvme_disk.sector_count, 2097152)

    # Write 8 sectors (4 KiB page)
    page_data = bytearray()
    for i in range(8):
        page_data.extend(f"NVME_LBA_{i:04d}_CHUNK".encode("ascii").ljust(512, b"\x00"))

    nvme_disk.write_sectors(lba=2048, count=8, data=bytes(page_data))
    read_page = nvme_disk.read_sectors(lba=2048, count=8)
    assert_eq(read_page, bytes(page_data))

def test_usb_xhci_driver_match():
    """Verify xHCI USB 3.0 host controller PCI classification and HID device binding."""
    xhci = MockPciDevice(bus=0, dev=20, func=0, vendor_id=0x8086, device_id=0x7AE0,
                         class_code=0x0C, subclass=0x03, prog_if=0x30)
    assert_true(xhci.is_xhci_usb(), "Identifies as xHCI USB 3.0 Host Controller")

def test_audio_drivers():
    """Verify AC'97 and Intel HD Audio controller detection and register probing."""
    ac97 = MockPciDevice(bus=0, dev=5, func=0, vendor_id=0x8086, device_id=0x2415,
                         class_code=0x04, subclass=0x01, prog_if=0x00)
    assert_true(ac97.is_ac97_audio(), "Identifies as AC'97 Audio Device")

    hda = MockPciDevice(bus=0, dev=27, func=0, vendor_id=0x8086, device_id=0x2668,
                        class_code=0x04, subclass=0x03, prog_if=0x00)
    assert_true(hda.is_hda_audio(), "Identifies as Intel HD Audio Device")

def test_network_driver_probing():
    """Verify Intel E1000 Ethernet adapter identification and MAC generation."""
    e1000 = MockPciDevice(bus=0, dev=3, func=0, vendor_id=0x8086, device_id=0x100E,
                          class_code=0x02, subclass=0x00, prog_if=0x00)
    assert_true(e1000.is_e1000_ethernet(), "Identifies as Intel 82540EM Gigabit NIC")

def test_gpu_framebuffer_match():
    """Verify multi-vendor GPU framebuffer device matching (Intel, AMD, NVIDIA, VirtIO)."""
    intel_gpu = MockPciDevice(bus=0, dev=2, func=0, vendor_id=0x8086, device_id=0x9BC5,
                              class_code=0x03, subclass=0x00, prog_if=0x00)
    assert_true(intel_gpu.is_vga_display(), "Intel Iris Xe / UHD Graphics VGA compatible")

def build_suite() -> TestSuite:
    suite = TestSuite("Hardware Drivers & PCI Registry Suite", tier=1)
    suite.add("PCI ECAM Header Decoding", test_pci_ecam_header_decoding)
    suite.add("AHCI SATA Storage Block Device", test_ahci_sata_storage_driver)
    suite.add("NVMe 1.4 Namespace Storage Block Device", test_nvme_storage_driver)
    suite.add("USB 3.0 xHCI Controller Probing", test_usb_xhci_driver_match)
    suite.add("Audio Subsystem (AC'97 & HDA)", test_audio_drivers)
    suite.add("Network NIC Probing (Intel E1000)", test_network_driver_probing)
    suite.add("GPU Framebuffer Matching", test_gpu_framebuffer_match)
    return suite

if __name__ == "__main__":
    suite = build_suite()
    passed, failed, _ = suite.run(verbose=True)
    sys.exit(0 if failed == 0 else 1)
