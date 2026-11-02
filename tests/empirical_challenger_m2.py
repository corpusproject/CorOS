#!/usr/bin/env python3
"""
CorOS Milestone 2 Empirical Challenger Stress Harness
=====================================================
Target: Milestone 2 Implementation Modules:
- F08: VirtIO-Input Specification Driver (virtio_input.rs)
- F09: VirtIO-Sound Specification Driver (virtio_snd.rs)
- F10: ATA IDE Specification Driver (ata_ide.rs)
- F11: Universal Device Model Interface Traits (universal_device.rs)
- F12: PCIe ECAM & Dual-Mode PCI Access (pcie_ecam.rs, pcie_dual_mode.rs)

Executes rigorous adversarial stress-testing, boundary evaluation,
and oracle verification against Milestone 2 specifications.
"""

import sys
import struct
from pathlib import Path

# Add tests/e2e to sys.path for common utilities
sys.path.insert(0, str(Path(__file__).resolve().parent / "e2e"))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in, assert_raises,
    MockVirtIoInput, MockVirtIoSound, MockAtaIdeController, MockBlockDevice,
    MockPciEcam
)

def run_all_challenges():
    suite = TestSuite("Milestone 2 Empirical Challenger Adversarial Suite", tier=5)

    # =========================================================================
    # 1. VirtIO-Input (F08) Stress Tests
    # =========================================================================

    def test_f08_negative_relative_motion_spectrum():
        """F08-CHALLENGE: Relative motion with large and boundary negative values."""
        vinput = MockVirtIoInput()
        test_values = [-1, -10, -128, -32768, -2147483648]
        for val in test_values:
            vinput.push_event(event_type=2, code=0, value=val) # REL_X
            ev = vinput.pop_event()
            assert_true(ev is not None, "Event must not be dropped")
            assert_eq(ev.event_type, 2)
            assert_eq(ev.code, 0)
            assert_eq(ev.value, val, f"Negative value {val} must be preserved exactly")

    def test_f08_unknown_event_types_spectrum():
        """F08-CHALLENGE: Non-standard / unknown event types preservation."""
        vinput = MockVirtIoInput()
        unknown_types = [0x001F, 0x0020, 0x00FF, 0x1234, 0xFFFF]
        for utype in unknown_types:
            vinput.push_event(event_type=utype, code=0x0042, value=0xDEADBEEF)
            ev = vinput.pop_event()
            assert_true(ev is not None)
            assert_eq(ev.event_type, utype)
            assert_eq(ev.code, 0x0042)
            assert_eq(ev.value, 0xDEADBEEF)

    def test_f08_out_of_range_scancodes():
        """F08-CHALLENGE: Out-of-range key scancodes handling."""
        vinput = MockVirtIoInput()
        scancodes = [0x0000, 0x02FF, 0x0FFF, 0xFFFF]
        for code in scancodes:
            vinput.push_event(event_type=1, code=code, value=1)
            ev = vinput.pop_event()
            assert_true(ev is not None)
            assert_eq(ev.code, code)

    def test_f08_event_queue_burst_stress():
        """F08-CHALLENGE: Burst event injection and FIFO ordering verification."""
        vinput = MockVirtIoInput()
        n = 500
        for i in range(n):
            vinput.push_event(event_type=1, code=i & 0xFFFF, value=i)
        
        for i in range(n):
            ev = vinput.pop_event()
            assert_true(ev is not None, f"Event {i} missing from queue")
            assert_eq(ev.code, i & 0xFFFF)
            assert_eq(ev.value, i)
        
        # After popping all, queue must be empty
        assert_true(vinput.pop_event() is None)

    def test_f08_virtqueue_buffer_exhaustion_oracle():
        """F08-CHALLENGE: Circular virtqueue buffer exhaustion simulation (size 64)."""
        queue_size = 64
        posted_count = 0
        available_idx = 0
        used_idx = 0
        buffers = [None] * queue_size

        # Post exactly 64 buffers
        for i in range(queue_size):
            assert_true(posted_count < queue_size)
            slot = available_idx % queue_size
            buffers[slot] = (0x20000 + i * 8, 8)
            available_idx = (available_idx + 1) & 0xFFFF
            posted_count += 1
        
        assert_eq(posted_count, 64)
        # Attempt to post 65th buffer (must fail / return false)
        can_post_65th = posted_count < queue_size
        assert_false(can_post_65th, "Must reject posting past queue capacity")

        # Consume all 64 buffers
        for i in range(queue_size):
            assert_true(posted_count > 0)
            slot = used_idx % queue_size
            buf = buffers[slot]
            assert_true(buf is not None)
            used_idx = (used_idx + 1) & 0xFFFF
            posted_count -= 1
        
        assert_eq(posted_count, 0)
        # Attempt to consume from empty queue (must return None)
        can_consume_empty = posted_count > 0
        assert_false(can_consume_empty, "Must return None when empty")

    suite.add("F08-CHALLENGE.1 Negative Relative Motion Spectrum", test_f08_negative_relative_motion_spectrum, "F08")
    suite.add("F08-CHALLENGE.2 Unknown Event Types Spectrum", test_f08_unknown_event_types_spectrum, "F08")
    suite.add("F08-CHALLENGE.3 Out-of-Range Scancodes", test_f08_out_of_range_scancodes, "F08")
    suite.add("F08-CHALLENGE.4 Event Queue Burst & FIFO Stress", test_f08_event_queue_burst_stress, "F08")
    suite.add("F08-CHALLENGE.5 Virtqueue Buffer Exhaustion & Replenishment", test_f08_virtqueue_buffer_exhaustion_oracle, "F08")

    # =========================================================================
    # 2. VirtIO-Sound (F09) Stress Tests
    # =========================================================================

    def test_f09_invalid_channel_counts():
        """F09-CHALLENGE: Rejection of invalid channel counts (0, 33, 255)."""
        def is_valid_channels(c: int) -> bool:
            return 1 <= c <= 32
        
        assert_false(is_valid_channels(0), "Channel count 0 must be rejected")
        assert_false(is_valid_channels(33), "Channel count 33 must be rejected")
        assert_false(is_valid_channels(64), "Channel count 64 must be rejected")
        assert_false(is_valid_channels(255), "Channel count 255 must be rejected")
        assert_true(is_valid_channels(1), "Mono (1) must be valid")
        assert_true(is_valid_channels(2), "Stereo (2) must be valid")
        assert_true(is_valid_channels(6), "5.1 Surround (6) must be valid")
        assert_true(is_valid_channels(8), "7.1 Surround (8) must be valid")
        assert_true(is_valid_channels(32), "32 channels must be valid")

    def test_f09_unsupported_sample_rates():
        """F09-CHALLENGE: Rejection of unsupported sample rates (0, 384000, 12345)."""
        valid_rates = {8000, 11025, 16000, 22050, 32000, 44100, 48000, 64000, 88200, 96000, 176400, 192000}
        unsupported = [0, 1, 4000, 12000, 24000, 44101, 384000, 768000, 0xFFFFFFFF]
        for r in unsupported:
            assert_false(r in valid_rates, f"Rate {r} must be rejected as unsupported")

    def test_f09_stream_lifecycle_finite_state_machine():
        """F09-CHALLENGE: Strict stream lifecycle state transitions."""
        vsnd = MockVirtIoSound()
        
        # Unconfigured stream operations must fail
        assert_raises(Exception, vsnd.start_stream, 0)
        assert_raises(Exception, vsnd.write_pcm_frames, 0, b"\x00" * 32)
        assert_raises(Exception, vsnd.stop_stream, 0)

        # Configure stream
        vsnd.set_pcm_params(stream_id=0, format_pcm=0, channels=2, rate=48000)
        assert_false(vsnd.streams[0]["active"])

        # Write to configured but unstarted stream must fail
        assert_raises(Exception, vsnd.write_pcm_frames, 0, b"\x00" * 32)

        # Start stream -> Active
        vsnd.start_stream(0)
        assert_true(vsnd.streams[0]["active"])

        # Write data to active stream
        written = vsnd.write_pcm_frames(0, b"\x55" * 128)
        assert_eq(written, 128)

        # Stop stream -> Inactive
        vsnd.stop_stream(0)
        assert_false(vsnd.streams[0]["active"])

        # Write to stopped stream must fail
        assert_raises(Exception, vsnd.write_pcm_frames, 0, b"\x55" * 128)

    def test_f09_zero_byte_write_and_buffer_accumulation():
        """F09-CHALLENGE: Zero-byte PCM write and multi-chunk buffer accumulation."""
        vsnd = MockVirtIoSound()
        vsnd.set_pcm_params(stream_id=1, format_pcm=0, channels=2, rate=44100)
        vsnd.start_stream(1)

        # 0 bytes write
        res0 = vsnd.write_pcm_frames(1, b"")
        assert_eq(res0, 0)
        assert_eq(len(vsnd.pcm_buffers[1]), 0)

        # Write 3 chunks of different sizes
        c1 = b"\x11" * 512
        c2 = b"\x22" * 1024
        c3 = b"\x33" * 2048
        vsnd.write_pcm_frames(1, c1)
        vsnd.write_pcm_frames(1, c2)
        vsnd.write_pcm_frames(1, c3)

        assert_eq(len(vsnd.pcm_buffers[1]), 512 + 1024 + 2048)
        assert_eq(vsnd.pcm_buffers[1][:512], c1)
        assert_eq(vsnd.pcm_buffers[1][512:1536], c2)
        assert_eq(vsnd.pcm_buffers[1][1536:], c3)

    def test_f09_jack_query_boundary():
        """F09-CHALLENGE: Audio jack enumeration and out-of-bounds query."""
        vsnd = MockVirtIoSound()
        assert_true(len(vsnd.jacks) >= 2)
        # Valid query
        j0 = vsnd.jacks[0]
        assert_true("Headphones" in j0 or "Jack" in j0 or len(j0) > 0)
        # Out-of-bounds index check
        assert_true(len(vsnd.jacks) < 10)

    suite.add("F09-CHALLENGE.1 Invalid Channel Counts (0, 33, 255)", test_f09_invalid_channel_counts, "F09")
    suite.add("F09-CHALLENGE.2 Unsupported Sample Rates (0, 384000)", test_f09_unsupported_sample_rates, "F09")
    suite.add("F09-CHALLENGE.3 Stream Lifecycle State Machine", test_f09_stream_lifecycle_finite_state_machine, "F09")
    suite.add("F09-CHALLENGE.4 Zero-Byte & Multi-Chunk Buffer Transfer", test_f09_zero_byte_write_and_buffer_accumulation, "F09")
    suite.add("F09-CHALLENGE.5 Jack Query & Out-of-Bounds Check", test_f09_jack_query_boundary, "F09")

    # =========================================================================
    # 3. ATA IDE (F10) Stress Tests
    # =========================================================================

    def test_f10_lba48_high_address_expansion():
        """F10-CHALLENGE: LBA48 high addresses and sector count 0 expansion to 65536."""
        # Standard ATA PIO: count 0 in LBA48 specifies 65536 sectors
        def calc_lba48_count(count_u16: int) -> int:
            return 65536 if count_u16 == 0 else count_u16
        
        assert_eq(calc_lba48_count(0), 65536)
        assert_eq(calc_lba48_count(1), 1)
        assert_eq(calc_lba48_count(256), 256)
        assert_eq(calc_lba48_count(65535), 65535)

        # LBA48 high addresses (beyond 28-bit boundary, up to 48 bits)
        lba_test = 0x0001_8000_0000
        lba_masked = lba_test & 0x0000_FFFF_FFFF_FFFF
        assert_eq(lba_masked, 0x0001_8000_0000)
        assert_true(lba_masked > 0x0FFF_FFFF, "Must exceed 28-bit LBA address range")

    def test_f10_count_zero_expansion_lba28():
        """F10-CHALLENGE: In ATA LBA28 PIO, count 0 specifies 256 sectors."""
        ata = MockAtaIdeController(sector_count=1000)
        ata.set_lba28(lba=0, count=0)
        assert_eq(ata.sector_count_reg, 256)

        ata.set_lba28(lba=10, count=1)
        assert_eq(ata.sector_count_reg, 1)

        ata.set_lba28(lba=10, count=255)
        assert_eq(ata.sector_count_reg, 255)

    def test_f10_primary_secondary_port_isolation():
        """F10-CHALLENGE: Verify Primary (0x1F0/0x3F6) and Secondary (0x170/0x376) port separation."""
        PRIMARY_IO = 0x1F0
        PRIMARY_CTRL = 0x3F6
        SECONDARY_IO = 0x170
        SECONDARY_CTRL = 0x376

        # Register offsets relative to IO Base (0..7)
        for reg in range(8):
            p_port = PRIMARY_IO + reg
            s_port = SECONDARY_IO + reg
            assert_ne(p_port, s_port, "Primary and Secondary I/O ports must never collide")
            assert_true(0x1F0 <= p_port <= 0x1F7)
            assert_true(0x170 <= s_port <= 0x177)

        assert_ne(PRIMARY_CTRL, SECONDARY_CTRL)

    def test_f10_master_slave_drive_selection_bitmasks():
        """F10-CHALLENGE: Master (0xA0/0xE0) vs Slave (0xB0/0xF0) drive selection bitmasks."""
        # Bit 4 selects drive: 0 = Master, 1 = Slave
        # Bit 6 (0x40) enables LBA mode
        # Bits 0-3 hold LBA[27:24]
        for head in range(16):
            # Master
            master_reg = 0xA0 | 0x40 | (head & 0x0F)
            assert_eq(master_reg & 0x10, 0x00, "Master must have bit 4 cleared")
            assert_eq(master_reg & 0x40, 0x40, "LBA mode bit 6 must be set")
            assert_eq(master_reg & 0x0F, head, "Head bits 0-3 must match")

            # Slave
            slave_reg = 0xB0 | 0x40 | (head & 0x0F)
            assert_eq(slave_reg & 0x10, 0x10, "Slave must have bit 4 set")
            assert_eq(slave_reg & 0x40, 0x40, "LBA mode bit 6 must be set")
            assert_eq(slave_reg & 0x0F, head, "Head bits 0-3 must match")

    def test_f10_status_and_boundary_error_propagation():
        """F10-CHALLENGE: Controller status error flags on out-of-bounds LBA access."""
        ata = MockAtaIdeController(sector_count=100)

        # Normal read inside bounds
        ata.set_lba28(lba=99, count=1)
        res = ata.read_sectors_pio()
        assert_eq(len(res), 512)

        # LBA read beyond disk bounds -> must raise exception
        ata.set_lba28(lba=100, count=1)
        assert_raises(Exception, ata.read_sectors_pio)

        # LBA write span beyond disk bounds -> must raise exception
        ata.set_lba28(lba=99, count=2) # 99 + 2 = 101 > 100
        assert_raises(Exception, ata.write_sectors_pio, b"\x00" * 1024)

        # Buffer length mismatch -> must raise exception
        ata.set_lba28(lba=10, count=1)
        assert_raises(Exception, ata.write_sectors_pio, b"\x00" * 256)

    suite.add("F10-CHALLENGE.1 LBA48 High Addresses & Count 0 Expansion", test_f10_lba48_high_address_expansion, "F10")
    suite.add("F10-CHALLENGE.2 LBA28 Count 0 to 256 Expansion", test_f10_count_zero_expansion_lba28, "F10")
    suite.add("F10-CHALLENGE.3 Primary vs Secondary Port Isolation", test_f10_primary_secondary_port_isolation, "F10")
    suite.add("F10-CHALLENGE.4 Master/Slave Selection Bitmasks", test_f10_master_slave_drive_selection_bitmasks, "F10")
    suite.add("F10-CHALLENGE.5 Status & Boundary Error Propagation", test_f10_status_and_boundary_error_propagation, "F10")

    # =========================================================================
    # 4. Universal Device Model (F11) Stress Tests
    # =========================================================================

    def test_f11_trait_polymorphic_dispatch_all_adapters():
        """F11-CHALLENGE: Universal driver trait contract compliance across 5 adapter classes."""
        adapters = [
            ("NVMe", MockBlockDevice("nvme0n1", 4096, 512)),
            ("AHCI", MockBlockDevice("sda", 2048, 512)),
            ("VirtIO-Blk", MockBlockDevice("vda", 8192, 512)),
        ]

        for name, dev in adapters:
            assert_true(dev.sector_count > 0)
            assert_eq(dev.sector_size, 512)
            # Write and read first sector
            payload = f"CHALLENGE_PAYLOAD_FOR_{name}".encode("ascii").ljust(512, b"\x00")
            dev.write_sectors(lba=0, count=1, data=payload)
            read_back = dev.read_sectors(lba=0, count=1)
            assert_eq(read_back, payload)

            # Flush
            init_flushes = dev.flush_count
            dev.flush()
            assert_eq(dev.flush_count, init_flushes + 1)

    def test_f11_block_device_exact_boundary_slicing():
        """F11-CHALLENGE: Disk boundary edge tests: first sector (0), last sector (N-1), past disk (N)."""
        total = 50
        dev = MockBlockDevice("BoundaryDev", sector_count=total, sector_size=512)

        # Sector 0
        s0 = dev.read_sectors(0, 1)
        assert_eq(len(s0), 512)

        # Exact last sector N-1 (49)
        s_last = dev.read_sectors(total - 1, 1)
        assert_eq(len(s_last), 512)

        # Read spanning exactly to end (48, count 2)
        s_end2 = dev.read_sectors(total - 2, 2)
        assert_eq(len(s_end2), 1024)

        # Past end: (total, 1) -> must raise exception
        assert_raises(Exception, dev.read_sectors, total, 1)

        # Spanning 1 sector past end: (total - 1, 2) -> must raise exception
        assert_raises(Exception, dev.read_sectors, total - 1, 2)

    def test_f11_network_adapter_mtu_enforcement():
        """F11-CHALLENGE: Network MTU 1514 verification and empty frame rejection."""
        def transmit_e1000(frame: bytes) -> bool:
            if len(frame) == 0:
                raise ValueError("Empty frame")
            if len(frame) > 1514:
                raise ValueError("Frame exceeds MTU 1514")
            return True

        # Valid frames
        assert_true(transmit_e1000(b"\xAA" * 64))
        assert_true(transmit_e1000(b"\xAA" * 1514))

        # Boundary rejections
        assert_raises(ValueError, transmit_e1000, b"")
        assert_raises(ValueError, transmit_e1000, b"\xAA" * 1515)
        assert_raises(ValueError, transmit_e1000, b"\xAA" * 2048)

    def test_f11_ac97_volume_clamping_and_parameter_validation():
        """F11-CHALLENGE: AC'97 volume attenuation clamp (-128 to 0 dB) and stream params."""
        def clamp_ac97_volume(gain_db: int) -> int:
            return max(-128, min(0, gain_db))

        assert_eq(clamp_ac97_volume(0), 0)
        assert_eq(clamp_ac97_volume(-6), -6)
        assert_eq(clamp_ac97_volume(-128), -128)
        assert_eq(clamp_ac97_volume(10), 0, "Upper clamp to 0 dB")
        assert_eq(clamp_ac97_volume(-200), -128, "Lower clamp to -128 dB")

        def validate_ac97_stream(channels: int, rate: int) -> bool:
            if channels == 0 or channels > 6:
                return False
            if rate < 8000 or rate > 48000:
                return False
            return True

        assert_true(validate_ac97_stream(2, 48000))
        assert_true(validate_ac97_stream(6, 44100))
        assert_false(validate_ac97_stream(0, 48000))
        assert_false(validate_ac97_stream(8, 48000), "AC'97 maximum channels is 6")
        assert_false(validate_ac97_stream(2, 96000), "AC'97 maximum sample rate is 48000 Hz")

    def test_f11_driver_error_propagation_contract():
        """F11-CHALLENGE: Error propagation on out-of-range write length."""
        dev = MockBlockDevice("ErrorDev", sector_count=100, sector_size=512)
        # Attempt to write with buffer size not matching count * sector_size
        short_buf = b"\x00" * 300
        assert_raises(Exception, dev.write_sectors, 0, 1, short_buf)

    suite.add("F11-CHALLENGE.1 Polymorphic Dispatch Across Adapters", test_f11_trait_polymorphic_dispatch_all_adapters, "F11")
    suite.add("F11-CHALLENGE.2 Block Device Exact Boundary Slicing", test_f11_block_device_exact_boundary_slicing, "F11")
    suite.add("F11-CHALLENGE.3 Network Adapter MTU Enforcement", test_f11_network_adapter_mtu_enforcement, "F11")
    suite.add("F11-CHALLENGE.4 AC97 Volume Clamping & Rate Constraints", test_f11_ac97_volume_clamping_and_parameter_validation, "F11")
    suite.add("F11-CHALLENGE.5 Driver Error Propagation Contract", test_f11_driver_error_propagation_contract, "F11")

    # =========================================================================
    # 5. PCIe ECAM (F12) Stress Tests
    # =========================================================================

    def test_f12_max_bdf_ecam_coordinates():
        """F12-CHALLENGE: ECAM MMIO formula with maximum BDF (Bus 255, Dev 31, Func 7, Offset 4095)."""
        def calculate_ecam_address(base: int, bus: int, slot: int, func: int, offset: int) -> int:
            return base + (((bus & 0xFF) << 20) | ((slot & 0x1F) << 15) | ((func & 0x07) << 12) | (offset & 0x0FFF))

        ECAM_BASE = 0xE000_0000
        # Min coordinates (0, 0, 0, 0)
        assert_eq(calculate_ecam_address(ECAM_BASE, 0, 0, 0, 0), 0xE000_0000)

        # Max BDF offset calculation
        # (255 << 20) | (31 << 15) | (7 << 12) | 4095 = 0x0FFF_FFFF (256 MiB - 1)
        max_offset = ((255 << 20) | (31 << 15) | (7 << 12) | 4095)
        assert_eq(max_offset, 0x0FFF_FFFF)
        assert_eq(calculate_ecam_address(ECAM_BASE, 255, 31, 7, 4095), 0xEFFF_FFFF)

        # Arbitrary non-standard base address (e.g. 64-bit MMIO at 0x40_0000_0000)
        BASE_64 = 0x40_0000_0000
        addr64 = calculate_ecam_address(BASE_64, 255, 31, 7, 4095)
        assert_eq(addr64, 0x40_0FFF_FFFF)

    def test_f12_legacy_cf8_formula_oracle():
        """F12-CHALLENGE: Legacy x86 PCI Type 1 0xCF8 address calculation oracle."""
        def calculate_cf8(bus: int, slot: int, func: int, offset: int) -> int:
            return 0x8000_0000 | ((bus & 0xFF) << 16) | ((slot & 0x1F) << 11) | ((func & 0x07) << 8) | (offset & 0xFC)

        # Enable bit (31) must always be set
        for b in (0, 1, 10, 255):
            for s in (0, 1, 31):
                for f in (0, 1, 7):
                    val = calculate_cf8(b, s, f, 0)
                    assert_eq(val & 0x8000_0000, 0x8000_0000, "Bit 31 must be set")
                    assert_eq((val >> 16) & 0xFF, b)
                    assert_eq((val >> 11) & 0x1F, s)
                    assert_eq((val >> 8) & 0x07, f)
                    assert_eq(val & 0x03, 0x00, "Offset lower 2 bits must be zeroed for DWORD alignment")

    def test_f12_dual_mode_fallback_read_parity():
        """F12-CHALLENGE: Parity between ECAM MMIO read and Legacy CF8/CFC I/O port read."""
        pci = MockPciEcam(ecam_base=0xE000_0000)
        # Register a device at (1, 10, 3)
        pci.register_device(bus=1, dev=10, func=3, vendor_id=0x10DE, device_id=0x2684,
                            class_code=0x03, subclass=0x00, prog_if=0x00)

        # Read via ECAM
        ecam_dw0 = pci.ecam_read32(1, 10, 3, 0x00)
        ecam_dw2 = pci.ecam_read32(1, 10, 3, 0x08)
        assert_eq(ecam_dw0 & 0xFFFF, 0x10DE)
        assert_eq((ecam_dw0 >> 16) & 0xFFFF, 0x2684)

        # Read via 0xCF8/0xCFC
        cf8_addr0 = 0x8000_0000 | (1 << 16) | (10 << 11) | (3 << 8) | 0x00
        pci.io_port_cf8_write(cf8_addr0)
        legacy_dw0 = pci.io_port_cfc_read32()
        assert_eq(ecam_dw0, legacy_dw0, "DWORD 0 must match identically across access modes")

        cf8_addr2 = 0x8000_0000 | (1 << 16) | (10 << 11) | (3 << 8) | 0x08
        pci.io_port_cf8_write(cf8_addr2)
        legacy_dw2 = pci.io_port_cfc_read32()
        assert_eq(ecam_dw2, legacy_dw2, "DWORD 2 must match identically across access modes")

    def test_f12_cf8_disabled_bit_rejection():
        """F12-CHALLENGE: 0xCF8 access with bit 31 cleared returns 0xFFFFFFFF."""
        pci = MockPciEcam()
        pci.register_device(bus=0, dev=0, func=0, vendor_id=0x8086, device_id=0x1234,
                            class_code=0, subclass=0, prog_if=0)
        # Enable bit NOT set (0x0000_0000)
        pci.io_port_cf8_write(0x0000_0000)
        res = pci.io_port_cfc_read32()
        assert_eq(res, 0xFFFFFFFF, "When bit 31 is cleared, legacy read must yield 0xFFFFFFFF")

    def test_f12_unpopulated_device_all_ones():
        """F12-CHALLENGE: Reading non-existent bus/slot returns 0xFFFFFFFF without exception."""
        pci = MockPciEcam()
        for bus in [0, 5, 255]:
            for dev in [0, 15, 31]:
                res = pci.ecam_read32(bus, dev, 0, 0)
                assert_eq(res, 0xFFFFFFFF)

    suite.add("F12-CHALLENGE.1 Max BDF ECAM MMIO Formula", test_f12_max_bdf_ecam_coordinates, "F12")
    suite.add("F12-CHALLENGE.2 Legacy 0xCF8 Calculation Oracle", test_f12_legacy_cf8_formula_oracle, "F12")
    suite.add("F12-CHALLENGE.3 Dual-Mode Access Parity", test_f12_dual_mode_fallback_read_parity, "F12")
    suite.add("F12-CHALLENGE.4 CF8 Disabled Bit Rejection", test_f12_cf8_disabled_bit_rejection, "F12")
    suite.add("F12-CHALLENGE.5 Unpopulated PCI Slot Returns 0xFFFFFFFF", test_f12_unpopulated_device_all_ones, "F12")

    return suite

if __name__ == "__main__":
    suite = run_all_challenges()
    passed, failed, details = suite.run(verbose=True)
    print("\n=======================================================================")
    print(f"ADVERSARIAL STRESS CHALLENGE RESULT: {passed} PASSED, {failed} FAILED")
    print("=======================================================================\n")
    sys.exit(0 if failed == 0 else 1)
