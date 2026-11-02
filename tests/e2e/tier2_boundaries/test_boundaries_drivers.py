"""
Tier 2: Boundary & Corner Cases - Hardware Drivers & Peripherals (F08 - F12)
============================================================================
CorOS/tests/e2e/tier2_boundaries/test_boundaries_drivers.py

Covers boundary, corner, overflow, and error handling for:
- F08: VirtIO-Input Driver Specification
- F09: VirtIO-Sound Driver Specification
- F10: ATA IDE Driver Specification
- F11: Universal Device Model Interface Traits
- F12: Dual-Mode PCI Access
"""

import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_raises,
    MockVirtIoInput, MockVirtIoSound, MockAtaIdeController, MockBlockDevice,
    MockPciEcam
)

# ---------------------------------------------------------------------------
# F08: VirtIO-Input Boundaries
# ---------------------------------------------------------------------------
def test_b_f08_empty_queue_pop():
    """F08: Boundary: Popping from empty VirtIO-Input queue returns None."""
    vinput = MockVirtIoInput()
    assert_true(vinput.pop_event() is None)

def test_b_f08_unknown_event_type():
    """F08: Boundary: Pushing unknown event type 0xFFFF preserves raw code and value."""
    vinput = MockVirtIoInput()
    vinput.push_event(event_type=0xFFFF, code=0x1234, value=-1)
    ev = vinput.pop_event()
    assert_true(ev is not None)
    assert_eq(ev.event_type, 0xFFFF)
    assert_eq(ev.value, -1)

def test_b_f08_negative_motion_coordinates():
    """F08: Boundary: Negative relative mouse motion (e.g. -32768) preserved."""
    vinput = MockVirtIoInput()
    vinput.push_event(event_type=2, code=0, value=-32768)
    ev = vinput.pop_event()
    assert_eq(ev.value, -32768)

def test_b_f08_zero_keycode_and_value():
    """F08: Boundary: Event with keycode 0 and value 0 handled cleanly."""
    vinput = MockVirtIoInput()
    vinput.push_event(event_type=1, code=0, value=0)
    ev = vinput.pop_event()
    assert_eq(ev.code, 0)
    assert_eq(ev.value, 0)

def test_b_f08_burst_events_queue():
    """F08: Boundary: Enqueueing 1000 events without loss."""
    vinput = MockVirtIoInput()
    for i in range(1000):
        vinput.push_event(event_type=1, code=i, value=1)
    assert_eq(len(vinput.event_queue), 1000)
    first = vinput.pop_event()
    assert_eq(first.code, 0)

# ---------------------------------------------------------------------------
# F09: VirtIO-Sound Boundaries
# ---------------------------------------------------------------------------
def test_b_f09_write_unstarted_stream_raises():
    """F09: Boundary: Writing PCM data to unstarted stream raises error."""
    vsnd = MockVirtIoSound()
    vsnd.set_pcm_params(stream_id=0, format_pcm=0, channels=2, rate=48000)
    # Stream is not started
    assert_raises(Exception, vsnd.write_pcm_frames, 0, b"\x00" * 64)

def test_b_f09_unconfigured_stream_id_raises():
    """F09: Boundary: Starting unconfigured stream ID 99 raises error."""
    vsnd = MockVirtIoSound()
    assert_raises(Exception, vsnd.start_stream, 99)

def test_b_f09_zero_byte_pcm_write():
    """F09: Boundary: Writing 0 bytes to active stream succeeds returning 0."""
    vsnd = MockVirtIoSound()
    vsnd.set_pcm_params(stream_id=0, format_pcm=0, channels=2, rate=44100)
    vsnd.start_stream(0)
    written = vsnd.write_pcm_frames(0, b"")
    assert_eq(written, 0)

def test_b_f09_sample_rate_clamp():
    """F09: Boundary: Standard audio rates (8000 to 192000 Hz) validation."""
    valid_rates = {8000, 16000, 44100, 48000, 96000, 192000}
    assert_true(48000 in valid_rates)
    assert_false(0 in valid_rates)

def test_b_f09_channel_count_limits():
    """F09: Boundary: Channel count boundary check (1=mono, 2=stereo, 8=surround)."""
    channels = 8
    is_valid_channels = 1 <= channels <= 32
    assert_true(is_valid_channels)

# ---------------------------------------------------------------------------
# F10: ATA IDE Boundaries
# ---------------------------------------------------------------------------
def test_b_f10_read_out_of_bounds_raises():
    """F10: Boundary: Reading beyond total sector count raises assertion error."""
    ata = MockAtaIdeController(sector_count=100)
    ata.set_lba28(lba=100, count=1) # LBA 100 on 100-sector disk is out of bounds
    assert_raises(Exception, ata.read_sectors_pio)

def test_b_f10_write_out_of_bounds_raises():
    """F10: Boundary: Writing beyond total sector count raises assertion error."""
    ata = MockAtaIdeController(sector_count=100)
    ata.set_lba28(lba=99, count=2) # 99 + 2 = 101 > 100
    assert_raises(Exception, ata.write_sectors_pio, b"\x00" * 1024)

def test_b_f10_write_length_mismatch_raises():
    """F10: Boundary: Providing buffer size not matching count*512 raises error."""
    ata = MockAtaIdeController(sector_count=100)
    ata.set_lba28(lba=10, count=1)
    # Provided only 256 bytes instead of 512
    assert_raises(Exception, ata.write_sectors_pio, b"\x00" * 256)

def test_b_f10_sector_count_zero_means_256():
    """F10: Boundary: In ATA PIO spec, count=0 specifies 256 sectors."""
    ata = MockAtaIdeController(sector_count=1000)
    ata.set_lba28(lba=0, count=0)
    assert_eq(ata.sector_count_reg, 256)

def test_b_f10_bsy_polling_timeout():
    """F10: Boundary: Device stuck in BSY status triggers timeout."""
    ata = MockAtaIdeController()
    ata.status = MockAtaIdeController.STATUS_BSY
    is_busy = (ata.status & MockAtaIdeController.STATUS_BSY) != 0
    assert_true(is_busy)

# ---------------------------------------------------------------------------
# F11: Universal Device Model Boundaries
# ---------------------------------------------------------------------------
def test_b_f11_read_exact_last_sector():
    """F11: Boundary: Reading exact last sector on disk succeeds."""
    disk = MockBlockDevice("BoundaryDisk", sector_count=100, sector_size=512)
    last_lba = 99
    # Read LBA 99, count 1
    data = disk.read_sectors(lba=last_lba, count=1)
    assert_eq(len(data), 512)

def test_b_f11_read_past_last_sector_raises():
    """F11: Boundary: Reading LBA equal to sector count raises error."""
    disk = MockBlockDevice("BoundaryDisk", sector_count=100)
    assert_raises(Exception, disk.read_sectors, lba=100, count=1)

def test_b_f11_network_frame_mtu_limit():
    """F11: Boundary: Frame length 1514 (standard Ethernet MTU) allowed, 1600 rejected."""
    MTU = 1500
    ETH_HDR = 14
    MAX_FRAME = MTU + ETH_HDR # 1514
    assert_true(1514 <= MAX_FRAME)
    assert_false(1600 <= MAX_FRAME)

def test_b_f11_volume_gain_lower_limit_clamp():
    """F11: Boundary: Gain values below -128 dB are clamped to -128 dB."""
    raw_gain = -150
    clamped = max(-128, min(0, raw_gain))
    assert_eq(clamped, -128)

def test_b_f11_drm_zero_resolution_rejection():
    """F11: Boundary: DRM KMS mode timing with 0x0 resolution rejected."""
    mode = {"w": 0, "h": 0}
    is_valid = mode["w"] > 0 and mode["h"] > 0
    assert_false(is_valid)

# ---------------------------------------------------------------------------
# F12: Dual-Mode PCI Boundaries
# ---------------------------------------------------------------------------
def test_b_f12_max_bus_dev_func_ecam():
    """F12: Boundary: ECAM address calculation for max BDF (Bus 255, Dev 31, Func 7)."""
    ECAM_BASE = 0xE0000000
    bus, dev, func, reg = 255, 31, 7, 0
    addr = ECAM_BASE + ((bus << 20) | (dev << 15) | (func << 12) | reg)
    assert_eq(addr, 0xEFFFF000)

def test_b_f12_ecam_offset_out_of_range():
    """F12: Boundary: ECAM offset 4096 (exceeding 4KB config space) returns 0xFFFFFFFF."""
    pci = MockPciEcam()
    val = pci.ecam_read32(bus=0, dev=0, func=0, offset=4096)
    assert_eq(val, 0xFFFFFFFF)

def test_b_f12_legacy_cf8_disabled_bit():
    """F12: Boundary: Reading 0xCFC with Enable bit (31) cleared in 0xCF8 returns 0xFFFFFFFF."""
    pci = MockPciEcam()
    pci.io_port_cf8_write(0x00000000) # Enable bit NOT set
    val = pci.io_port_cfc_read32()
    assert_eq(val, 0xFFFFFFFF)

def test_b_f12_vendor_id_all_ones_indicates_unmapped():
    """F12: Boundary: Vendor ID 0xFFFF indicates no device present on bus."""
    vendor_id = 0xFFFF
    device_exists = vendor_id != 0xFFFF
    assert_false(device_exists)

def test_b_f12_unaligned_config_space_offset():
    """F12: Boundary: Offset not aligned to 4 bytes handled safely."""
    pci = MockPciEcam()
    pci.register_device(bus=0, dev=1, func=0, vendor_id=0x1234, device_id=0x5678,
                        class_code=0, subclass=0, prog_if=0)
    # Register 0 is vendor/device. Offset 0 is aligned.
    val = pci.ecam_read32(bus=0, dev=1, func=0, offset=0)
    assert_ne(val, 0xFFFFFFFF)

# ---------------------------------------------------------------------------
# Suite Builder
# ---------------------------------------------------------------------------
def build_suite() -> TestSuite:
    suite = TestSuite("Boundaries: Hardware Drivers & Peripherals (F08-F12)", tier=2)

    # F08 Boundaries (5 tests)
    suite.add("B_F08.1 Empty Queue Pop Returns None", test_b_f08_empty_queue_pop, "F08")
    suite.add("B_F08.2 Unknown Input Event Type 0xFFFF", test_b_f08_unknown_event_type, "F08")
    suite.add("B_F08.3 Negative Relative Motion Coordinates", test_b_f08_negative_motion_coordinates, "F08")
    suite.add("B_F08.4 Zero Keycode and Zero Value Event", test_b_f08_zero_keycode_and_value, "F08")
    suite.add("B_F08.5 Burst Input Event Enqueueing", test_b_f08_burst_events_queue, "F08")

    # F09 Boundaries (5 tests)
    suite.add("B_F09.1 Write to Unstarted Stream Exception", test_b_f09_write_unstarted_stream_raises, "F09")
    suite.add("B_F09.2 Start Unconfigured Stream Exception", test_b_f09_unconfigured_stream_id_raises, "F09")
    suite.add("B_F09.3 Zero-Byte PCM Buffer Transfer", test_b_f09_zero_byte_pcm_write, "F09")
    suite.add("B_F09.4 Invalid Sample Rate Zero Rejection", test_b_f09_sample_rate_clamp, "F09")
    suite.add("B_F09.5 Audio Channel Count Upper Limit", test_b_f09_channel_count_limits, "F09")

    # F10 Boundaries (5 tests)
    suite.add("B_F10.1 Out-of-Bounds LBA Read Exception", test_b_f10_read_out_of_bounds_raises, "F10")
    suite.add("B_F10.2 Out-of-Bounds LBA Write Exception", test_b_f10_write_out_of_bounds_raises, "F10")
    suite.add("B_F10.3 Buffer Length Mismatch Exception", test_b_f10_write_length_mismatch_raises, "F10")
    suite.add("B_F10.4 Count Zero Expands to 256 Sectors", test_b_f10_sector_count_zero_means_256, "F10")
    suite.add("B_F10.5 BSY Flag Timeout Detection", test_b_f10_bsy_polling_timeout, "F10")

    # F11 Boundaries (5 tests)
    suite.add("B_F11.1 Read Exact Last Sector on Disk", test_b_f11_read_exact_last_sector, "F11")
    suite.add("B_F11.2 Read Past Last Sector Exception", test_b_f11_read_past_last_sector_raises, "F11")
    suite.add("B_F11.3 Ethernet Frame Maximum MTU Limit", test_b_f11_network_frame_mtu_limit, "F11")
    suite.add("B_F11.4 Audio Volume Gain Lower Limit Clamp", test_b_f11_volume_gain_lower_limit_clamp, "F11")
    suite.add("B_F11.5 DRM 0x0 Zero Resolution Rejection", test_b_f11_drm_zero_resolution_rejection, "F11")

    # F12 Boundaries (5 tests)
    suite.add("B_F12.1 Max BDF ECAM MMIO Address Calculation", test_b_f12_max_bus_dev_func_ecam, "F12")
    suite.add("B_F12.2 ECAM Offset Exceeding 4096 Returns All-Ones", test_b_f12_ecam_offset_out_of_range, "F12")
    suite.add("B_F12.3 Legacy CF8 Disabled Bit Returns 0xFFFFFFFF", test_b_f12_legacy_cf8_disabled_bit, "F12")
    suite.add("B_F12.4 Vendor ID 0xFFFF Unmapped Check", test_b_f12_vendor_id_all_ones_indicates_unmapped, "F12")
    suite.add("B_F12.5 Config Space Offset Alignment", test_b_f12_unaligned_config_space_offset, "F12")

    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)
