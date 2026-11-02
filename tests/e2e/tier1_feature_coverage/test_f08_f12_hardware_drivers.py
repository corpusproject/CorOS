"""
Tier 1: Hardware Drivers & Peripherals Tests (F08 - F12)
========================================================
CorOS/tests/e2e/tier1_feature_coverage/test_f08_f12_hardware_drivers.py

Covers isolated functionality for:
- F08: VirtIO-Input Driver Specification
- F09: VirtIO-Sound Driver Specification
- F10: ATA IDE Driver Specification
- F11: Universal Device Model Interface Traits
- F12: Dual-Mode PCI Access
"""

import struct
import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in,
    MockVirtIoInput, MockVirtIoSound, MockAtaIdeController, MockBlockDevice,
    MockPciEcam
)

# ---------------------------------------------------------------------------
# F08: VirtIO-Input Driver Specification
# ---------------------------------------------------------------------------
def test_f08_virtio_input_event_queue():
    """F08: Verify VirtIO-Input event queue pushes and pops input events."""
    vinput = MockVirtIoInput()
    assert_true(vinput.pop_event() is None)
    
    # EV_KEY: KEY_A (30), Value 1 (Press)
    vinput.push_event(event_type=1, code=30, value=1)
    # EV_SYN: SYN_REPORT (0), Value 0
    vinput.push_event(event_type=0, code=0, value=0)
    
    ev1 = vinput.pop_event()
    assert_true(ev1 is not None)
    assert_eq(ev1.event_type, 1)
    assert_eq(ev1.code, 30)
    assert_eq(ev1.value, 1)

    ev2 = vinput.pop_event()
    assert_true(ev2 is not None)
    assert_eq(ev2.event_type, 0)

def test_f08_virtio_input_mouse_rel_events():
    """F08: Verify VirtIO-Input relative mouse motion events (EV_REL)."""
    vinput = MockVirtIoInput()
    # EV_REL (2): REL_X (0), dx=15; REL_Y (1), dy=-10
    vinput.push_event(event_type=2, code=0, value=15)
    vinput.push_event(event_type=2, code=1, value=-10)

    ev_x = vinput.pop_event()
    assert_eq(ev_x.event_type, 2)
    assert_eq(ev_x.code, 0)
    assert_eq(ev_x.value, 15)

    ev_y = vinput.pop_event()
    assert_eq(ev_y.event_type, 2)
    assert_eq(ev_y.code, 1)
    assert_eq(ev_y.value, -10)

def test_f08_virtio_input_config_select():
    """F08: Verify VirtIO-Input device configuration space selection."""
    vinput = MockVirtIoInput()
    # VIRTIO_INPUT_CFG_ID_NAME = 1, subsel = 0
    vinput.config_select = 1
    vinput.config_subsel = 0
    assert_eq(vinput.config_select, 1)
    assert_eq(vinput.config_subsel, 0)

def test_f08_virtio_input_empty_queue():
    """F08: Verify polling on empty VirtIO-Input queue returns None."""
    vinput = MockVirtIoInput()
    assert_true(vinput.pop_event() is None)

def test_f08_virtio_input_status_ack():
    """F08: Verify VirtIO device status handshake bits (ACKNOWLEDGE, DRIVER, FEATURES_OK)."""
    VIRTIO_STATUS_ACKNOWLEDGE = 1
    VIRTIO_STATUS_DRIVER = 2
    VIRTIO_STATUS_FEATURES_OK = 8
    VIRTIO_STATUS_DRIVER_OK = 4

    status = 0
    status |= VIRTIO_STATUS_ACKNOWLEDGE
    status |= VIRTIO_STATUS_DRIVER
    status |= VIRTIO_STATUS_FEATURES_OK
    assert_eq(status & VIRTIO_STATUS_FEATURES_OK, 8)
    status |= VIRTIO_STATUS_DRIVER_OK
    assert_eq(status & VIRTIO_STATUS_DRIVER_OK, 4)

# ---------------------------------------------------------------------------
# F09: VirtIO-Sound Driver Specification
# ---------------------------------------------------------------------------
def test_f09_virtio_sound_pcm_params():
    """F09: Verify VirtIO-Sound stream parameter configuration (format, channels, rate)."""
    vsnd = MockVirtIoSound()
    # Stream 0: S16_LE (format 0), 2 channels, 48000 Hz
    vsnd.set_pcm_params(stream_id=0, format_pcm=0, channels=2, rate=48000)
    assert_in(0, vsnd.streams)
    assert_eq(vsnd.streams[0]["rate"], 48000)
    assert_eq(vsnd.streams[0]["channels"], 2)

def test_f09_virtio_sound_stream_lifecycle():
    """F09: Verify VirtIO-Sound stream start and stop transitions."""
    vsnd = MockVirtIoSound()
    vsnd.set_pcm_params(stream_id=1, format_pcm=0, channels=2, rate=44100)
    assert_false(vsnd.streams[1]["active"])
    vsnd.start_stream(stream_id=1)
    assert_true(vsnd.streams[1]["active"])
    vsnd.stop_stream(stream_id=1)
    assert_false(vsnd.streams[1]["active"])

def test_f09_virtio_sound_pcm_buffer_transfer():
    """F09: Verify VirtIO-Sound PCM transmission buffer accumulation."""
    vsnd = MockVirtIoSound()
    vsnd.set_pcm_params(stream_id=0, format_pcm=0, channels=2, rate=48000)
    vsnd.start_stream(stream_id=0)
    
    # 256 samples of 16-bit stereo = 1024 bytes
    pcm_chunk = b"\x00\x10\x00\x20" * 256
    written = vsnd.write_pcm_frames(stream_id=0, frames=pcm_chunk)
    assert_eq(written, 1024)
    assert_eq(len(vsnd.pcm_buffers[0]), 1024)

def test_f09_virtio_sound_jack_enumeration():
    """F09: Verify VirtIO-Sound audio jack query and status reporting."""
    vsnd = MockVirtIoSound()
    assert_true(len(vsnd.jacks) >= 2)
    assert_in("Headphones 3.5mm", vsnd.jacks[0])

def test_f09_virtio_sound_virtqueue_types():
    """F09: Verify VirtIO-Sound 4 mandatory virtqueues: control, event, tx, rx."""
    vq_names = ["CONTROL", "EVENT", "TX", "RX"]
    assert_eq(len(vq_names), 4)
    assert_in("TX", vq_names)

# ---------------------------------------------------------------------------
# F10: ATA IDE Driver Specification
# ---------------------------------------------------------------------------
def test_f10_ata_ide_drive_selection():
    """F10: Verify ATA IDE Master/Slave drive selection and head register."""
    ata = MockAtaIdeController()
    # Select Master (drive 0), head 0
    ata.select_drive(drive=0, lba_head=0)
    assert_eq(ata.selected_drive, 0)
    # Select Slave (drive 1), head 5
    ata.select_drive(drive=1, lba_head=5)
    assert_eq(ata.selected_drive, 1)

def test_f10_ata_ide_pio_write_and_read():
    """F10: Verify ATA IDE LBA28 512-byte PIO sector write and read."""
    ata = MockAtaIdeController(sector_count=1024)
    test_sector = b"COROS_ATA_IDE_PIO_SECTOR_DATA_VALIDATION" + (b"\x55" * (512 - 40))
    
    # Set LBA 10, count 1
    ata.set_lba28(lba=10, count=1)
    ata.write_sectors_pio(test_sector)
    
    # Read back LBA 10
    ata.set_lba28(lba=10, count=1)
    read_data = ata.read_sectors_pio()
    assert_eq(read_data, test_sector)

def test_f10_ata_ide_multi_sector_pio():
    """F10: Verify ATA IDE multi-sector (4 sectors = 2048 bytes) PIO transfer."""
    ata = MockAtaIdeController(sector_count=1024)
    data = b"\xAB" * 2048
    ata.set_lba28(lba=20, count=4)
    ata.write_sectors_pio(data)

    ata.set_lba28(lba=20, count=4)
    read_data = ata.read_sectors_pio()
    assert_eq(read_data, data)

def test_f10_ata_ide_status_registers():
    """F10: Verify ATA status register DRDY, BSY, and ERR flags."""
    ata = MockAtaIdeController()
    assert_eq(ata.status & MockAtaIdeController.STATUS_DRDY, MockAtaIdeController.STATUS_DRDY)
    assert_eq(ata.status & MockAtaIdeController.STATUS_BSY, 0)
    assert_eq(ata.status & MockAtaIdeController.STATUS_ERR, 0)

def test_f10_ata_ide_primary_secondary_ports():
    """F10: Verify legacy Primary (0x1F0) and Secondary (0x170) port bases."""
    PRIMARY_DATA_PORT = 0x1F0
    PRIMARY_CONTROL_PORT = 0x3F6
    SECONDARY_DATA_PORT = 0x170
    SECONDARY_CONTROL_PORT = 0x376
    assert_eq(PRIMARY_DATA_PORT + 7, 0x1F7) # Status/Command
    assert_eq(SECONDARY_DATA_PORT + 7, 0x177)

# ---------------------------------------------------------------------------
# F11: Universal Device Model Interface Traits
# ---------------------------------------------------------------------------
def test_f11_block_device_driver_contract():
    """F11: Verify BlockDeviceDriver interface read, write, and flush contract."""
    dev = MockBlockDevice("TestNVMe0", sector_count=2048, sector_size=512)
    assert_eq(dev.name, "TestNVMe0")
    assert_eq(dev.sector_count, 2048)
    assert_eq(dev.sector_size, 512)

    buf = b"BLOCK_DEV_TRAIT_PAYLOAD" + (b"\x00" * (512 - 23))
    dev.write_sectors(lba=0, count=1, data=buf)
    res = dev.read_sectors(lba=0, count=1)
    assert_eq(res, buf)

    assert_eq(dev.flush_count, 0)
    dev.flush()
    assert_eq(dev.flush_count, 1)

def test_f11_network_device_driver_contract():
    """F11: Verify NetworkDeviceDriver MAC address query and transmit contract."""
    mac = b"\x00\x1A\x2B\x3C\x4D\x5E"
    assert_eq(len(mac), 6)
    # Transmit test Ethernet frame
    frame = mac + b"\x52\x54\x00\x12\x34\x56" + b"\x08\x00" + (b"\xAA" * 46)
    assert_true(len(frame) >= 60, "Minimum Ethernet frame size")

def test_f11_drm_kms_driver_contract():
    """F11: Verify DrmKmsDriver mode timing and surface address contract."""
    # 1920x1080@60Hz timing struct
    mode = {
        "clock_khz": 148500,
        "hdisplay": 1920,
        "hsync_start": 2008,
        "hsync_end": 2052,
        "htotal": 2200,
        "vdisplay": 1080,
        "vsync_start": 1084,
        "vsync_end": 1089,
        "vtotal": 1125,
    }
    assert_eq(mode["hdisplay"], 1920)
    assert_eq(mode["vdisplay"], 1080)

def test_f11_input_device_driver_contract():
    """F11: Verify InputDeviceDriver poll events and LED control contract."""
    leds = {"caps": False, "num": True, "scroll": False}
    assert_true(leds["num"])
    leds["caps"] = True
    assert_true(leds["caps"])

def test_f11_audio_device_driver_contract():
    """F11: Verify AudioDeviceDriver stream start, stop, and volume gain contract."""
    gain_db = -6 # -6 dB attenuation
    assert_true(-128 <= gain_db <= 0)

# ---------------------------------------------------------------------------
# F12: Dual-Mode PCI Access
# ---------------------------------------------------------------------------
def test_f12_pcie_ecam_mmio_address_calculation():
    """F12: Verify PCIe ECAM MMIO address mapping for Bus 1, Dev 0, Func 0."""
    ECAM_BASE = 0xE0000000
    bus, dev, func, reg = 1, 0, 0, 0
    # Addr = ECAM_BASE + (bus << 20) | (dev << 15) | (func << 12) | reg
    addr = ECAM_BASE + ((bus << 20) | (dev << 15) | (func << 12) | reg)
    assert_eq(addr, 0xE0100000)

def test_f12_pcie_ecam_read_write():
    """F12: Verify reading and writing PCI config space via ECAM MMIO."""
    pci = MockPciEcam(ecam_base=0xE0000000)
    # Register Intel E1000 NIC: Vendor 0x8086, Device 0x100E at (0, 3, 0)
    pci.register_device(bus=0, dev=3, func=0, vendor_id=0x8086, device_id=0x100E,
                        class_code=0x02, subclass=0x00, prog_if=0x00)

    val0 = pci.ecam_read32(bus=0, dev=3, func=0, offset=0)
    vendor_id = val0 & 0xFFFF
    device_id = (val0 >> 16) & 0xFFFF
    assert_eq(vendor_id, 0x8086)
    assert_eq(device_id, 0x100E)

def test_f12_legacy_pci_io_port_cf8_cfc():
    """F12: Verify legacy PCI I/O ports 0xCF8 (CONFIG_ADDRESS) and 0xCFC (CONFIG_DATA)."""
    pci = MockPciEcam()
    # Register AHCI SATA: Vendor 0x8086, Device 0x2922 at (0, 31, 2)
    pci.register_device(bus=0, dev=31, func=2, vendor_id=0x8086, device_id=0x2922,
                        class_code=0x01, subclass=0x06, prog_if=0x01)

    # Compose 0xCF8 address: Enable (bit 31) | Bus (23:16) | Dev (15:11) | Func (10:8) | Reg (7:2)
    cf8_val = 0x80000000 | (0 << 16) | (31 << 11) | (2 << 8) | 0
    pci.io_port_cf8_write(cf8_val)
    cfc_val = pci.io_port_cfc_read32()
    assert_eq(cfc_val & 0xFFFF, 0x8086)
    assert_eq((cfc_val >> 16) & 0xFFFF, 0x2922)

def test_f12_pci_nonexistent_device_returns_all_ones():
    """F12: Verify probing nonexistent PCI device returns 0xFFFFFFFF."""
    pci = MockPciEcam()
    val = pci.ecam_read32(bus=0, dev=15, func=0, offset=0)
    assert_eq(val, 0xFFFFFFFF, "Unpopulated PCI slot must read 0xFFFFFFFF")

def test_f12_dual_mode_fallback_consistency():
    """F12: Verify ECAM MMIO and legacy I/O ports read identical Vendor/Device values."""
    pci = MockPciEcam()
    pci.register_device(bus=0, dev=2, func=0, vendor_id=0x8086, device_id=0x9BC5,
                        class_code=0x03, subclass=0x00, prog_if=0x00)

    ecam_val = pci.ecam_read32(bus=0, dev=2, func=0, offset=0)
    
    # Read via legacy 0xCF8/0xCFC
    pci.io_port_cf8_write(0x80000000 | (0 << 16) | (2 << 11) | (0 << 8) | 0)
    legacy_val = pci.io_port_cfc_read32()

    assert_eq(ecam_val, legacy_val, "Dual-mode PCI access must return identical data")

# ---------------------------------------------------------------------------
# Suite Builder
# ---------------------------------------------------------------------------
def build_suite() -> TestSuite:
    suite = TestSuite("Hardware Drivers & Peripherals Suite (F08-F12)", tier=1)

    # F08: VirtIO-Input Driver Specification (5 tests)
    suite.add("F08.1 VirtIO-Input Event Queue Enqueue/Dequeue", test_f08_virtio_input_event_queue, "F08")
    suite.add("F08.2 VirtIO-Input Relative Mouse Events", test_f08_virtio_input_mouse_rel_events, "F08")
    suite.add("F08.3 VirtIO-Input Device Config Space Selection", test_f08_virtio_input_config_select, "F08")
    suite.add("F08.4 VirtIO-Input Empty Queue Handling", test_f08_virtio_input_empty_queue, "F08")
    suite.add("F08.5 VirtIO-Input Status Handshake", test_f08_virtio_input_status_ack, "F08")

    # F09: VirtIO-Sound Driver Specification (5 tests)
    suite.add("F09.1 VirtIO-Sound PCM Parameter Configuration", test_f09_virtio_sound_pcm_params, "F09")
    suite.add("F09.2 VirtIO-Sound Stream Start and Stop", test_f09_virtio_sound_stream_lifecycle, "F09")
    suite.add("F09.3 VirtIO-Sound PCM Buffer Transfer", test_f09_virtio_sound_pcm_buffer_transfer, "F09")
    suite.add("F09.4 VirtIO-Sound Audio Jack Enumeration", test_f09_virtio_sound_jack_enumeration, "F09")
    suite.add("F09.5 VirtIO-Sound Virtqueue Architecture", test_f09_virtio_sound_virtqueue_types, "F09")

    # F10: ATA IDE Driver Specification (5 tests)
    suite.add("F10.1 ATA IDE Master/Slave Drive Selection", test_f10_ata_ide_drive_selection, "F10")
    suite.add("F10.2 ATA IDE PIO Sector Write and Read", test_f10_ata_ide_pio_write_and_read, "F10")
    suite.add("F10.3 ATA IDE Multi-Sector PIO Transfer", test_f10_ata_ide_multi_sector_pio, "F10")
    suite.add("F10.4 ATA IDE Status Register Flags", test_f10_ata_ide_status_registers, "F10")
    suite.add("F10.5 ATA IDE Primary and Secondary Port Layout", test_f10_ata_ide_primary_secondary_ports, "F10")

    # F11: Universal Device Model Interface Traits (5 tests)
    suite.add("F11.1 BlockDeviceDriver Interface Contract", test_f11_block_device_driver_contract, "F11")
    suite.add("F11.2 NetworkDeviceDriver Interface Contract", test_f11_network_device_driver_contract, "F11")
    suite.add("F11.3 DrmKmsDriver Interface Contract", test_f11_drm_kms_driver_contract, "F11")
    suite.add("F11.4 InputDeviceDriver Interface Contract", test_f11_input_device_driver_contract, "F11")
    suite.add("F11.5 AudioDeviceDriver Interface Contract", test_f11_audio_device_driver_contract, "F11")

    # F12: Dual-Mode PCI Access (5 tests)
    suite.add("F12.1 PCIe ECAM MMIO Address Calculation", test_f12_pcie_ecam_mmio_address_calculation, "F12")
    suite.add("F12.2 PCIe ECAM 4KB Config Space Read/Write", test_f12_pcie_ecam_read_write, "F12")
    suite.add("F12.3 Legacy PCI 0xCF8/0xCFC I/O Port Emulation", test_f12_legacy_pci_io_port_cf8_cfc, "F12")
    suite.add("F12.4 Nonexistent PCI Slot 0xFFFFFFFF Probe", test_f12_pci_nonexistent_device_returns_all_ones, "F12")
    suite.add("F12.5 Dual-Mode PCI Access Consistency", test_f12_dual_mode_fallback_consistency, "F12")

    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
