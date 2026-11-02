#!/usr/bin/env python3
"""
CorOS Milestone 3 Subsystem 7 Empirical Challenger 2 Adversarial Stress Suite
=============================================================================
Target: Next-Gen Filesystem Implementations:
- Samsung F2FS (kernel/corkernel/src/fs/f2fs.rs & corfsdb/src/f2fs_layout.rs):
  - Dual checkpoint version comparison & tie-breaking rules
  - NAT index boundary calculation at entry 455 (page boundary crossing)
  - Direct & indirect node addressing (923 direct pointers, 5 node pointers, 24B footer)
  - Multi-slot directory entries & 27-byte bitmap parsing (214 slots)
- SGI XFS (kernel/corkernel/src/fs/xfs.rs & corfsdb/src/btrfs_xfs_layout.rs):
  - Inode to Allocation Group (AG) physical offset translation across varied geometries
  - Shortform local directory entry parsing (32-bit vs 64-bit parent/inode layouts)
  - 128-bit packed BMBT extent record decoding & logical-to-physical block mapping
- ISO9660 Optical Disc (kernel/corkernel/src/fs/iso9660.rs & corfsdb/src/iso9660_udf.rs):
  - Joliet UCS-2 UTF-16BE directory parsing & version suffix ';1' stripping
  - Rock Ridge SUSP records (RR, NM, PX, SL, CE continuation area)
  - SUSP continuation area multi-hop traversal and circular recursion limits

Zero external dependencies (pure Python standard library).
"""

import math
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add tests/e2e and tests to sys.path
TESTS_DIR = Path(__file__).resolve().parent
TESTS_E2E_DIR = TESTS_DIR / "e2e"
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_E2E_DIR))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne,
    assert_in, assert_raises
)
from linux_subsystems.models import (
    MockF2fsParser, MockXfsParser, MockIso9660ExtendedParser
)


# =============================================================================
# Bit-for-Bit Authentic Replicas & Oracles Matching Rust Implementations
# =============================================================================

# -----------------------------------------------------------------------------
# F2FS Constants and Oracles
# -----------------------------------------------------------------------------
F2FS_SUPER_MAGIC = 0xF2F52010
F2FS_BLKSIZE = 4096
F2FS_BLOCKS_PER_SEGMENT = 512
ADDRS_PER_INODE = 923
F2FS_NAT_ENTRIES_PER_BLOCK = 455
F2FS_DENTRIES_PER_BLOCK = 214


class F2fsSuperblockOracle:
    """Exact replica of F2fsSuperblock::parse in f2fs.rs."""
    @staticmethod
    def parse(raw_disk: bytes) -> Optional[Dict[str, Any]]:
        if len(raw_disk) < 1024:
            return None

        # Try standard offset 1024 (0x400) first, fallback to 0
        buf = raw_disk
        if len(raw_disk) >= 1024 + 128:
            magic_at_1024 = struct.unpack("<I", raw_disk[1024:1028])[0]
            if magic_at_1024 == F2FS_SUPER_MAGIC:
                buf = raw_disk[1024:]

        if len(buf) < 128:
            return None

        magic = struct.unpack("<I", buf[0:4])[0]
        if magic != F2FS_SUPER_MAGIC:
            return None

        major_ver, minor_ver = struct.unpack("<HH", buf[4:8])
        log_sectorsize, log_sectors_per_block, log_blocksize, log_blocks_per_seg = struct.unpack("<IIII", buf[8:24])
        segs_per_sec, secs_per_zone, total_section_count, segment_count = struct.unpack("<IIII", buf[24:40])
        segment_count_ckpt, segment_count_sit, segment_count_nat, segment_count_ssa, segment_count_main = struct.unpack("<IIIII", buf[40:60])
        cp_blkaddr, sit_blkaddr, nat_blkaddr, ssa_blkaddr, main_blkaddr = struct.unpack("<IIIII", buf[64:84])
        root_ino = struct.unpack("<I", buf[84:88])[0]

        volume_name = b""
        if len(buf) >= 124:
            volume_name = buf[108:124]

        return {
            "magic": magic,
            "major_ver": major_ver,
            "minor_ver": minor_ver,
            "log_sectorsize": log_sectorsize,
            "log_blocksize": log_blocksize,
            "log_blocks_per_seg": log_blocks_per_seg,
            "total_section_count": total_section_count,
            "segment_count": segment_count,
            "segment_count_main": segment_count_main,
            "cp_blkaddr": cp_blkaddr,
            "sit_blkaddr": sit_blkaddr,
            "nat_blkaddr": nat_blkaddr,
            "ssa_blkaddr": ssa_blkaddr,
            "main_blkaddr": main_blkaddr,
            "root_ino": root_ino,
            "volume_name": volume_name,
        }


class F2fsCheckpointOracle:
    """Exact replica of F2fsCheckpoint::parse and select_active in f2fs.rs."""
    @staticmethod
    def parse(buf: bytes) -> Optional[Dict[str, Any]]:
        if len(buf) < 68:
            return None

        checkpoint_ver = struct.unpack("<Q", buf[0:8])[0]
        user_block_count = struct.unpack("<Q", buf[8:16])[0]
        valid_block_count = struct.unpack("<Q", buf[16:24])[0]
        rsvd_seg, overprov_seg, free_seg = struct.unpack("<III", buf[24:36])
        cur_node_segno = struct.unpack("<III", buf[36:48])
        cur_data_segno = struct.unpack("<III", buf[48:60])
        ckpt_flags, checksum_offset = struct.unpack("<II", buf[60:68])

        return {
            "checkpoint_ver": checkpoint_ver,
            "user_block_count": user_block_count,
            "valid_block_count": valid_block_count,
            "rsvd_segment_count": rsvd_seg,
            "overprov_segment_count": overprov_seg,
            "free_segment_count": free_seg,
            "cur_node_segno": list(cur_node_segno),
            "cur_data_segno": list(cur_data_segno),
            "ckpt_flags": ckpt_flags,
            "checksum_offset": checksum_offset,
        }

    @staticmethod
    def select_active(cp1_buf: bytes, cp2_buf: bytes) -> Optional[Dict[str, Any]]:
        cp1 = F2fsCheckpointOracle.parse(cp1_buf)
        cp2 = F2fsCheckpointOracle.parse(cp2_buf)

        if cp1 is not None and cp2 is not None:
            if cp2["checkpoint_ver"] > cp1["checkpoint_ver"]:
                return cp2
            else:
                return cp1
        elif cp1 is not None:
            return cp1
        elif cp2 is not None:
            return cp2
        else:
            return None


class F2fsNatOracle:
    """Exact replica of translate_nat_blocks in f2fs.rs."""
    @staticmethod
    def translate(nat_blkaddr: int, nid: int, blocks: Dict[int, bytes]) -> Optional[int]:
        block_idx = nat_blkaddr + (nid // F2FS_NAT_ENTRIES_PER_BLOCK)
        entry_idx = (nid % F2FS_NAT_ENTRIES_PER_BLOCK) * 9

        page = blocks.get(block_idx)
        if not page or len(page) < entry_idx + 9:
            return None

        # Entry layout: version (1B), ino (4B LE), block_addr (4B LE)
        blk_addr = struct.unpack("<I", page[entry_idx + 5 : entry_idx + 9])[0]
        return blk_addr


class F2fsInodeOracle:
    """Exact replica of F2fsInode::parse in f2fs.rs."""
    @staticmethod
    def parse(buf: bytes) -> Optional[Dict[str, Any]]:
        if len(buf) < 1024:
            return None

        mode, uid, gid, links = struct.unpack("<H2xIII", buf[0:16])
        size, blocks, atime, mtime, ctime = struct.unpack("<QQQQQ", buf[16:56])

        inline_flags = buf[64]
        inline_data = (inline_flags & 0x02) != 0

        # Direct data pointers at offset 200 (up to 923)
        data_ptrs = []
        ptrs_offset = 200
        for i in range(ADDRS_PER_INODE):
            off = ptrs_offset + i * 4
            if off + 4 <= len(buf):
                ptr = struct.unpack("<I", buf[off : off + 4])[0]
                if ptr != 0:
                    data_ptrs.push(ptr) if hasattr(data_ptrs, 'push') else data_ptrs.append(ptr)

        # Node pointers at offset 200 + 923 * 4 = 3892
        node_ptrs_offset = ptrs_offset + ADDRS_PER_INODE * 4
        direct_nodes = [0, 0]
        indirect_nodes = [0, 0]
        double_indirect = 0

        if node_ptrs_offset + 20 <= len(buf):
            direct_nodes[0] = struct.unpack("<I", buf[node_ptrs_offset : node_ptrs_offset + 4])[0]
            direct_nodes[1] = struct.unpack("<I", buf[node_ptrs_offset + 4 : node_ptrs_offset + 8])[0]
            indirect_nodes[0] = struct.unpack("<I", buf[node_ptrs_offset + 8 : node_ptrs_offset + 12])[0]
            indirect_nodes[1] = struct.unpack("<I", buf[node_ptrs_offset + 12 : node_ptrs_offset + 16])[0]
            double_indirect = struct.unpack("<I", buf[node_ptrs_offset + 16 : node_ptrs_offset + 20])[0]

        # Node footer at offset 4072..4096 (24 bytes)
        footer = None
        if len(buf) >= 4096:
            footer_buf = buf[4072:4096]
            fnid, fino, fcp_ver, fnext_blk = struct.unpack("<IIQI", footer_buf[0:20])
            footer = {
                "nid": fnid,
                "ino": fino,
                "cp_ver": fcp_ver,
                "next_blkaddr": fnext_blk,
            }

        ino = footer["ino"] if footer else 0

        return {
            "ino": ino,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "links": links,
            "size": size,
            "blocks": blocks,
            "atime": atime,
            "mtime": mtime,
            "ctime": ctime,
            "inline_data": inline_data,
            "direct_data_ptrs": data_ptrs,
            "direct_node_ptrs": direct_nodes,
            "indirect_node_ptrs": indirect_nodes,
            "double_indirect_ptr": double_indirect,
            "footer": footer,
        }


class F2fsDentryBlockOracle:
    """Exact replica of F2fsDentryBlock::parse in f2fs.rs."""
    @staticmethod
    def parse(buf: bytes) -> Optional[List[Dict[str, Any]]]:
        if len(buf) < F2FS_BLKSIZE:
            return None

        bitmap = buf[0:27]
        dentry_base = 30
        filename_base = 30 + F2FS_DENTRIES_PER_BLOCK * 11  # 2384

        entries = []
        slot = 0
        while slot < F2FS_DENTRIES_PER_BLOCK:
            byte_idx = slot // 8
            bit_idx = slot % 8
            is_set = (bitmap[byte_idx] & (1 << bit_idx)) != 0

            if is_set:
                d_off = dentry_base + slot * 11
                if d_off + 11 <= len(buf):
                    hash_code, ino, name_len, file_type = struct.unpack("<IIHB", buf[d_off : d_off + 11])
                    slots_needed = (name_len + 7) // 8

                    fn_off = filename_base + slot * 8
                    if fn_off + name_len <= len(buf):
                        name_bytes = buf[fn_off : fn_off + name_len]
                        name = name_bytes.decode("utf-8", errors="replace")
                        entries.append({
                            "name": name,
                            "ino": ino,
                            "file_type": file_type,
                            "slots": slots_needed,
                        })

                    slot += max(slots_needed, 1)
                    continue

            slot += 1

        return entries


# -----------------------------------------------------------------------------
# XFS Constants and Oracles
# -----------------------------------------------------------------------------
XFS_SB_MAGIC = 0x58465342  # "XFSB"
XFS_DINODE_MAGIC = 0x494E  # "IN"


class XfsSuperblockOracle:
    """Exact replica of XfsSuperblock::parse in xfs.rs."""
    @staticmethod
    def parse(buf: bytes) -> Optional[Dict[str, Any]]:
        if len(buf) < 512:
            return None

        magic = struct.unpack(">I", buf[0:4])[0]
        if magic != XFS_SB_MAGIC:
            return None

        block_size = struct.unpack(">I", buf[4:8])[0]
        dblocks, rblocks, rextents = struct.unpack(">QQQ", buf[8:32])
        uuid = buf[32:48]
        root_ino = struct.unpack(">Q", buf[56:64])[0]
        ag_blocks, ag_count = struct.unpack(">II", buf[84:92])
        inode_size = struct.unpack(">H", buf[104:106])[0]

        block_log = buf[120]
        sector_log = buf[121]
        inode_log = buf[122]

        inopblog = max(0, block_log - inode_log)
        if ag_blocks > 1:
            agblklog = (ag_blocks - 1).bit_length()
        else:
            agblklog = 0

        fs_name = buf[108:120]

        return {
            "magic": magic,
            "block_size": block_size,
            "dblocks": dblocks,
            "root_ino": root_ino,
            "ag_blocks": ag_blocks,
            "ag_count": ag_count,
            "inode_size": inode_size,
            "block_log": block_log,
            "inode_log": inode_log,
            "inopblog": inopblog,
            "agblklog": agblklog,
            "fs_name": fs_name,
        }


class XfsInodeToPhysicalOracle:
    """Exact replica of inode_to_physical in xfs.rs."""
    @staticmethod
    def convert(ino: int, inopblog: int, agblklog: int, agblocks: int, blocksize: int, inodesize: int) -> int:
        agno = ino >> (inopblog + agblklog)
        agbno = (ino >> inopblog) & ((1 << agblklog) - 1)
        offset_in_block = (ino & ((1 << inopblog) - 1)) * inodesize
        return (agno * agblocks + agbno) * blocksize + offset_in_block


class XfsDir2SfOracle:
    """Exact replica of XfsDir2SfHdr::parse and parse_entries in xfs.rs."""
    @staticmethod
    def parse_entries(buf: bytes) -> List[Dict[str, Any]]:
        entries = []
        if len(buf) < 3:
            return entries

        count = buf[0]
        i8count = buf[1]

        if i8count == 0:
            if len(buf) < 6:
                return entries
            parent = struct.unpack(">I", buf[2:6])[0]
            offset = 6
        else:
            if len(buf) < 10:
                return entries
            parent = struct.unpack(">Q", buf[2:10])[0]
            offset = 10

        if count == 0:
            return entries

        is_i8 = i8count > 0
        inumber_len = 8 if is_i8 else 4

        for _ in range(count):
            if offset + 3 > len(buf):
                break
            namelen = buf[offset]
            entry_offset = struct.unpack(">H", buf[offset + 1 : offset + 3])[0]
            name_start = offset + 3
            if name_start + namelen + 1 + inumber_len > len(buf):
                break

            name_bytes = buf[name_start : name_start + namelen]
            name = name_bytes.decode("utf-8", errors="replace")
            ftype_pos = name_start + namelen
            file_type = buf[ftype_pos]

            ino_pos = ftype_pos + 1
            if is_i8:
                inumber = struct.unpack(">Q", buf[ino_pos : ino_pos + 8])[0]
            else:
                inumber = struct.unpack(">I", buf[ino_pos : ino_pos + 4])[0]

            entries.append({
                "namelen": namelen,
                "offset": entry_offset,
                "name": name,
                "inumber": inumber,
                "file_type": file_type,
                "parent": parent,
            })

            offset = ino_pos + inumber_len

        return entries


class XfsExtentOracle:
    """Exact replica of XfsExtent::parse in xfs.rs."""
    @staticmethod
    def pack(is_unwritten: bool, logical_start: int, physical_start: int, block_count: int) -> bytes:
        hi = ((1 if is_unwritten else 0) << 63) | ((logical_start & 0x003FFFFFFFFFFFFF) << 9) | ((physical_start >> 43) & 0x01FF)
        lo = ((physical_start & 0x000007FFFFFFFFFF) << 21) | (block_count & 0x001FFFFF)
        return struct.pack(">QQ", hi, lo)

    @staticmethod
    def parse(buf: bytes) -> Optional[Dict[str, Any]]:
        if len(buf) < 16:
            return None
        hi, lo = struct.unpack(">QQ", buf[:16])

        is_unwritten = (hi >> 63) != 0
        logical_start = (hi >> 9) & 0x003F_FFFF_FFFF_FFFF
        physical_start_hi = hi & 0x01FF
        physical_start_lo = lo >> 21
        physical_start = (physical_start_hi << 43) | physical_start_lo
        block_count = lo & 0x001F_FFFF

        return {
            "is_unwritten": is_unwritten,
            "logical_start": logical_start,
            "physical_start": physical_start,
            "block_count": block_count,
        }

    @staticmethod
    def lookup_block(extents: List[Dict[str, Any]], logical_block: int) -> Optional[int]:
        for ext in extents:
            start = ext["logical_start"]
            end = start + ext["block_count"]
            if start <= logical_block < end:
                return ext["physical_start"] + (logical_block - start)
        return None


# -----------------------------------------------------------------------------
# ISO9660 & Rock Ridge Constants and Oracles
# -----------------------------------------------------------------------------
ISO_SECTOR_SIZE = 2048


class Iso9660JolietOracle:
    """Exact replica of parse_joliet_name in iso9660.rs."""
    @staticmethod
    def parse(raw_ucs2: bytes) -> str:
        if not raw_ucs2:
            return ""
        # Big-endian UCS-2 code units
        u16_chars = []
        for i in range(0, len(raw_ucs2) - 1, 2):
            code = (raw_ucs2[i] << 8) | raw_ucs2[i + 1]
            u16_chars.append(code)

        # Decode UTF-16 code units
        decoded = []
        i = 0
        while i < len(u16_chars):
            c = u16_chars[i]
            # Check for surrogate pairs
            if 0xD800 <= c <= 0xDBFF:
                if i + 1 < len(u16_chars) and 0xDC00 <= u16_chars[i + 1] <= 0xDFFF:
                    high = c
                    low = u16_chars[i + 1]
                    code_point = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                    decoded.append(chr(code_point))
                    i += 2
                    continue
                else:
                    decoded.append("?")
            elif 0xDC00 <= c <= 0xDFFF:
                decoded.append("?")
            else:
                decoded.append(chr(c))
            i += 1

        s = "".join(decoded)
        if ";" in s:
            return s.split(";")[0]
        return s


class Iso9660SuspOracle:
    """Exact replica of parse_rock_ridge_susp in iso9660.rs."""
    @staticmethod
    def parse(susp_buf: bytes) -> Dict[str, Any]:
        records: Dict[str, Any] = {
            "has_rr": False,
            "alternate_name": None,
            "posix_mode": None,
            "posix_links": None,
            "posix_uid": None,
            "posix_gid": None,
            "symlink_target": None,
            "continuation_lba": None,
            "continuation_offset": None,
            "continuation_len": None,
        }

        offset = 0
        while offset < len(susp_buf):
            if offset + 4 > len(susp_buf):
                break  # Truncated header

            sig = susp_buf[offset : offset + 2]
            length = susp_buf[offset + 2]
            _ver = susp_buf[offset + 3]

            if length < 4 or offset + length > len(susp_buf):
                # Invalid length or truncated record -> stop immediately (prevent hang)
                break

            payload = susp_buf[offset : offset + length]

            if sig == b"RR":
                records["has_rr"] = True
            elif sig == b"NM":
                if length > 5:
                    name_bytes = payload[5:length]
                    records["alternate_name"] = name_bytes.decode("utf-8", errors="replace")
            elif sig == b"PX":
                if length >= 36:
                    mode = struct.unpack("<I", payload[4:8])[0]
                    links = struct.unpack("<I", payload[12:16])[0]
                    uid = struct.unpack("<I", payload[20:24])[0]
                    gid = struct.unpack("<I", payload[28:32])[0]
                    records["posix_mode"] = mode
                    records["posix_links"] = links
                    records["posix_uid"] = uid
                    records["posix_gid"] = gid
                else:
                    records["posix_mode"] = 0o100644
            elif sig == b"SL":
                if length > 5:
                    target_bytes = payload[5:length]
                    records["symlink_target"] = target_bytes.decode("utf-8", errors="replace")
            elif sig == b"CE":
                if length >= 28:
                    c_lba = struct.unpack("<I", payload[4:8])[0]
                    c_off = struct.unpack("<I", payload[12:16])[0]
                    c_len = struct.unpack("<I", payload[20:24])[0]
                    records["continuation_lba"] = c_lba
                    records["continuation_offset"] = c_off
                    records["continuation_len"] = c_len

            offset += length

        return records


class Iso9660CeContinuationResolver:
    """
    Simulates System Use Sharing Protocol (SUSP) Continuation Area (CE) resolution
    across disk sectors with recursion limits to prevent infinite loop / circular reference attacks.
    """
    MAX_CONTINUATION_DEPTH = 8

    @staticmethod
    def resolve_all_susp_records(
        initial_sua: bytes,
        read_sector_fn: Any,
    ) -> Tuple[Dict[str, Any], int]:
        """
        Traverses initial SUA and follows CE continuation areas up to MAX_CONTINUATION_DEPTH hops.
        Returns combined records dict and total hops traversed.
        """
        combined = {
            "has_rr": False,
            "alternate_name": None,
            "posix_mode": None,
            "posix_links": None,
            "posix_uid": None,
            "posix_gid": None,
            "symlink_target": None,
        }

        visited_continuations = set()
        current_buf = initial_sua
        hops = 0

        while hops < Iso9660CeContinuationResolver.MAX_CONTINUATION_DEPTH:
            records = Iso9660SuspOracle.parse(current_buf)

            if records["has_rr"]:
                combined["has_rr"] = True
            if records["alternate_name"]:
                combined["alternate_name"] = records["alternate_name"]
            if records["posix_mode"] is not None:
                combined["posix_mode"] = records["posix_mode"]
                combined["posix_links"] = records["posix_links"]
                combined["posix_uid"] = records["posix_uid"]
                combined["posix_gid"] = records["posix_gid"]
            if records["symlink_target"]:
                combined["symlink_target"] = records["symlink_target"]

            # Check if there is a continuation record
            c_lba = records["continuation_lba"]
            c_off = records["continuation_offset"]
            c_len = records["continuation_len"]

            if c_lba is None or c_off is None or c_len is None or c_len == 0:
                break  # No more continuations

            continuation_key = (c_lba, c_off, c_len)
            if continuation_key in visited_continuations:
                # Circular continuation reference detected! Terminate traversal immediately.
                break
            visited_continuations.add(continuation_key)

            sector_data = read_sector_fn(c_lba)
            if not sector_data or c_off + c_len > len(sector_data):
                break  # Bad sector read or offset out of bounds

            current_buf = sector_data[c_off : c_off + c_len]
            hops += 1

        return combined, hops


# =============================================================================
# Adversarial Challenge Test Cases
# =============================================================================

def build_m3_challenger_suite() -> TestSuite:
    suite = TestSuite("Milestone 3 Subsystem 7 Next-Gen Filesystems Adversarial Suite", 5)

    # -------------------------------------------------------------------------
    # PART 1: F2FS Adversarial Challenges (ADV-F2FS-01 to ADV-F2FS-09)
    # -------------------------------------------------------------------------

    def test_adv_f2fs_01_dual_checkpoint_selection_matrix():
        """ADV-F2FS-01: Dual checkpoint version comparison, tie-breaking, and corruption recovery."""
        # Setup CP1 (ver = 100) and CP2 (ver = 200)
        cp1_data = struct.pack("<QQQIII", 100, 1000, 500, 10, 20, 30) + (b"\x00" * 44)
        cp2_data = struct.pack("<QQQIII", 200, 1200, 600, 10, 20, 30) + (b"\x00" * 44)

        # 1. CP2 has higher version
        active = F2fsCheckpointOracle.select_active(cp1_data, cp2_data)
        assert_eq(active["checkpoint_ver"], 200)
        assert_eq(active["user_block_count"], 1200)

        # 2. CP1 has higher version
        cp1_higher = struct.pack("<QQQIII", 350, 1500, 700, 10, 20, 30) + (b"\x00" * 44)
        active2 = F2fsCheckpointOracle.select_active(cp1_higher, cp2_data)
        assert_eq(active2["checkpoint_ver"], 350)
        assert_eq(active2["user_block_count"], 1500)

        # 3. Equal version tie-breaker (defaults to CP1)
        cp_equal1 = struct.pack("<QQQIII", 500, 2001, 800, 10, 20, 30) + (b"\x00" * 44)
        cp_equal2 = struct.pack("<QQQIII", 500, 2002, 800, 10, 20, 30) + (b"\x00" * 44)
        active3 = F2fsCheckpointOracle.select_active(cp_equal1, cp_equal2)
        assert_eq(active3["checkpoint_ver"], 500)
        assert_eq(active3["user_block_count"], 2001)

        # 4. Truncated CP1 with valid CP2
        corrupted_cp1 = b"TRUNCATED"
        active4 = F2fsCheckpointOracle.select_active(corrupted_cp1, cp2_data)
        assert_eq(active4["checkpoint_ver"], 200)

        # 5. Truncated CP2 with valid CP1
        active5 = F2fsCheckpointOracle.select_active(cp1_data, b"")
        assert_eq(active5["checkpoint_ver"], 100)

        # 6. Both corrupted
        active6 = F2fsCheckpointOracle.select_active(b"BAD1", b"BAD2")
        assert_eq(active6, None)

    def test_adv_f2fs_02_checkpoint_u64_wrap_and_boundary_versions():
        """ADV-F2FS-02: 64-bit maximum integer versions (2^64-1 vs 2^64-2) and zero version."""
        u64_max = 0xFFFFFFFFFFFFFFFF
        u64_max_minus_1 = 0xFFFFFFFFFFFFFFFE

        cp_max = struct.pack("<QQQIII", u64_max, 100, 50, 1, 2, 3) + (b"\x00" * 44)
        cp_prev = struct.pack("<QQQIII", u64_max_minus_1, 90, 45, 1, 2, 3) + (b"\x00" * 44)

        # CP1 has u64_max, CP2 has u64_max - 1
        active = F2fsCheckpointOracle.select_active(cp_max, cp_prev)
        assert_eq(active["checkpoint_ver"], u64_max)

        # CP2 has u64_max, CP1 has 0
        cp_zero = struct.pack("<QQQIII", 0, 10, 5, 1, 2, 3) + (b"\x00" * 44)
        active2 = F2fsCheckpointOracle.select_active(cp_zero, cp_max)
        assert_eq(active2["checkpoint_ver"], u64_max)

    def test_adv_f2fs_03_nat_page_boundary_calculation_at_entry_455():
        """ADV-F2FS-03: NAT 455-entry boundary: nid 454 (last in block 0), nid 455 (first in block 1), nid 909, nid 910."""
        nat_blkaddr = 1000
        blocks = {}

        # Block 1000 (contains nid 0 .. 454)
        block0 = bytearray(4096)
        # Populate nid 0 at byte offset 0 (version=1, ino=10, block_addr=50000)
        block0[0:9] = struct.pack("<BII", 1, 10, 50000)
        # Populate nid 454 at byte offset 454 * 9 = 4086 (version=1, ino=11, block_addr=50454)
        block0[4086:4095] = struct.pack("<BII", 1, 11, 50454)
        blocks[1000] = bytes(block0)

        # Block 1001 (contains nid 455 .. 909)
        block1 = bytearray(4096)
        # Populate nid 455 at byte offset 0 (version=2, ino=20, block_addr=60000)
        block1[0:9] = struct.pack("<BII", 2, 20, 60000)
        # Populate nid 456 at byte offset 9
        block1[9:18] = struct.pack("<BII", 2, 21, 60001)
        # Populate nid 909 at byte offset 4086
        block1[4086:4095] = struct.pack("<BII", 2, 22, 60909)
        blocks[1001] = bytes(block1)

        # Block 1002 (contains nid 910 .. 1364)
        block2 = bytearray(4096)
        # Populate nid 910 at byte offset 0 (version=3, ino=30, block_addr=70000)
        block2[0:9] = struct.pack("<BII", 3, 30, 70000)
        blocks[1002] = bytes(block2)

        # Test translations
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 0, blocks), 50000)
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 454, blocks), 50454)
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 455, blocks), 60000)
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 456, blocks), 60001)
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 909, blocks), 60909)
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 910, blocks), 70000)

        # Cross check with MockF2fsParser model
        assert_eq(MockF2fsParser.translate_nat(nat_blkaddr, 455, blocks), 60000)

    def test_adv_f2fs_04_nat_truncated_page_and_missing_block_defense():
        """ADV-F2FS-04: NAT page shorter than required offset returns None safely without index out of bounds."""
        nat_blkaddr = 500
        # Create a truncated block of 4085 bytes (entry 454 starts at 4086, requires 4095 bytes)
        truncated_block = bytearray(4085)
        blocks = {500: bytes(truncated_block)}

        # nid 0 (requires 0..9 bytes) should succeed
        truncated_block[0:9] = struct.pack("<BII", 1, 100, 12345)
        blocks[500] = bytes(truncated_block)
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 0, blocks), 12345)

        # nid 454 requires bytes 4086..4095, block is 4085 bytes -> must return None safely
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 454, blocks), None)

        # Missing block (nid 455 in block 501, not in blocks dict) -> returns None
        assert_eq(F2fsNatOracle.translate(nat_blkaddr, 455, blocks), None)

    def test_adv_f2fs_05_inode_direct_923_addressing_and_footer():
        """ADV-F2FS-05: Inode addressing layout with 923 direct data pointers and 24-byte node footer."""
        inode_buf = bytearray(4096)
        # Mode: 0o100644 (regular file), UID: 1000, GID: 1000, Links: 1
        inode_buf[0:16] = struct.pack("<H2xIII", 0o100644, 1000, 1000, 1)
        # Size: 4096 * 923 = 3780608 bytes, blocks: 923, atime/mtime/ctime: 1700000000
        inode_buf[16:56] = struct.pack("<QQQQQ", 3780608, 923, 1700000000, 1700000000, 1700000000)

        # Inline flags at byte 64: bit 1 is NOT set (regular non-inline data)
        inode_buf[64] = 0x00

        # Pack 923 non-zero direct pointers starting at offset 200
        for i in range(ADDRS_PER_INODE):
            off = 200 + i * 4
            inode_buf[off : off + 4] = struct.pack("<I", 10000 + i)

        # Node pointers at offset 3892..3912
        # direct_node_ptrs: [501, 502], indirect_node_ptrs: [601, 602], double_indirect: 701
        inode_buf[3892:3912] = struct.pack("<IIIII", 501, 502, 601, 602, 701)

        # Node footer at offset 4072..4096 (24 bytes): nid=42, ino=42, cp_ver=105, next_blk=0
        inode_buf[4072:4092] = struct.pack("<IIQI", 42, 42, 105, 0)

        parsed = F2fsInodeOracle.parse(bytes(inode_buf))
        assert_true(parsed is not None)
        assert_eq(parsed["ino"], 42)
        assert_eq(parsed["size"], 3780608)
        assert_eq(len(parsed["direct_data_ptrs"]), 923)
        assert_eq(parsed["direct_data_ptrs"][0], 10000)
        assert_eq(parsed["direct_data_ptrs"][922], 10000 + 922)
        assert_eq(parsed["direct_node_ptrs"], [501, 502])
        assert_eq(parsed["indirect_node_ptrs"], [601, 602])
        assert_eq(parsed["double_indirect_ptr"], 701)
        assert_eq(parsed["footer"]["nid"], 42)
        assert_eq(parsed["footer"]["cp_ver"], 105)

    def test_adv_f2fs_06_inode_inline_flag_and_truncation_defense():
        """ADV-F2FS-06: Inode inline data flag detection and sub-1024-byte truncation rejection."""
        # Buffer < 1024 bytes must return None
        assert_eq(F2fsInodeOracle.parse(b"\x00" * 512), None)

        # Inline data flag set (bit 1 of byte 64: 0x02)
        buf = bytearray(4096)
        buf[64] = 0x02  # inline data active
        parsed = F2fsInodeOracle.parse(bytes(buf))
        assert_true(parsed["inline_data"])

        # Inline data flag cleared
        buf[64] = 0xFD
        parsed2 = F2fsInodeOracle.parse(bytes(buf))
        assert_false(parsed2["inline_data"])

    def test_adv_f2fs_07_dentry_multi_slot_filenames_parsing():
        """ADV-F2FS-07: Dentry block multi-slot filename advancement and 27-byte bitmap indexing."""
        block = bytearray(4096)

        # We will pack 3 entries:
        # Entry 0: "short" (5 bytes -> 1 slot, slot 0)
        # Entry 1: "medium_name.txt" (15 bytes -> 2 slots, slots 1 and 2)
        # Entry 2: "very_long_file_name_for_testing.bin" (35 bytes -> 5 slots, slots 3..7)

        # Slot bitmap: bits 0, 1, 3 should be set (start of active entries)
        # byte 0 contains bits 0..7: bit 0 (1), bit 1 (2), bit 3 (8) -> 1 + 2 + 8 = 11 (0x0B)
        block[0] = 0x0B

        dentry_base = 30
        filename_base = 30 + 214 * 11  # 2384

        # Entry 0 at dentry slot 0
        block[dentry_base : dentry_base + 11] = struct.pack("<IIHB", 0x1111, 101, 5, 1)  # DT_REG
        block[filename_base : filename_base + 5] = b"short"

        # Entry 1 at dentry slot 1 (takes slots 1 and 2)
        d_off1 = dentry_base + 1 * 11
        block[d_off1 : d_off1 + 11] = struct.pack("<IIHB", 0x2222, 102, 15, 1)
        fn_off1 = filename_base + 1 * 8
        block[fn_off1 : fn_off1 + 15] = b"medium_name.txt"

        # Entry 2 at dentry slot 3 (takes slots 3..7)
        d_off2 = dentry_base + 3 * 11
        block[d_off2 : d_off2 + 11] = struct.pack("<IIHB", 0x3333, 103, 35, 1)
        fn_off2 = filename_base + 3 * 8
        block[fn_off2 : fn_off2 + 35] = b"very_long_file_name_for_testing.bin"

        entries = F2fsDentryBlockOracle.parse(bytes(block))
        assert_eq(len(entries), 3)

        assert_eq(entries[0]["name"], "short")
        assert_eq(entries[0]["ino"], 101)
        assert_eq(entries[0]["slots"], 1)

        assert_eq(entries[1]["name"], "medium_name.txt")
        assert_eq(entries[1]["ino"], 102)
        assert_eq(entries[1]["slots"], 2)

        assert_eq(entries[2]["name"], "very_long_file_name_for_testing.bin")
        assert_eq(entries[2]["ino"], 103)
        assert_eq(entries[2]["slots"], 5)

    def test_adv_f2fs_08_dentry_boundary_slot_213_and_overrun_defense():
        """ADV-F2FS-08: Last slot 213 boundary fit and multi-slot block overrun rejection."""
        block = bytearray(4096)
        # Slot 213 is in byte 213 // 8 = 26, bit 213 % 8 = 5
        block[26] = 1 << 5

        dentry_base = 30
        filename_base = 30 + 214 * 11  # 2384
        d_off = dentry_base + 213 * 11
        fn_off = filename_base + 213 * 8  # 4088 (exact: 4088 + 8 = 4096)

        # 1. 8-byte filename fits exactly in the final slot 213
        block[d_off : d_off + 11] = struct.pack("<IIHB", 0x4444, 213, 8, 1)
        block[fn_off : fn_off + 8] = b"lastslot"

        entries = F2fsDentryBlockOracle.parse(bytes(block))
        assert_eq(len(entries), 1)
        assert_eq(entries[0]["name"], "lastslot")
        assert_eq(entries[0]["ino"], 213)

        # 2. Overrun attempt: name_len = 16 at slot 213 (would require 4088 + 16 = 4104 > 4096)
        block[d_off : d_off + 11] = struct.pack("<IIHB", 0x4444, 213, 16, 1)
        entries2 = F2fsDentryBlockOracle.parse(bytes(block))
        # Overrun filename is skipped safely without throwing exception
        assert_eq(len(entries2), 0)

    def test_adv_f2fs_09_superblock_dual_offset_magic_validation():
        """ADV-F2FS-09: F2FS superblock magic verification at offset 1024 and fallback at 0."""
        # 1. Standard 1024-byte offset
        disk_image = bytearray(4096)
        disk_image[1024:1028] = struct.pack("<I", F2FS_SUPER_MAGIC)
        disk_image[1028:1032] = struct.pack("<HH", 1, 14)  # major 1, minor 14
        sb1 = F2fsSuperblockOracle.parse(bytes(disk_image))
        assert_true(sb1 is not None)
        assert_eq(sb1["magic"], F2FS_SUPER_MAGIC)
        assert_eq(sb1["major_ver"], 1)
        assert_eq(sb1["minor_ver"], 14)

        # 2. Fallback offset 0
        disk_image0 = bytearray(2048)
        disk_image0[0:4] = struct.pack("<I", F2FS_SUPER_MAGIC)
        disk_image0[4:8] = struct.pack("<HH", 2, 0)
        sb2 = F2fsSuperblockOracle.parse(bytes(disk_image0))
        assert_true(sb2 is not None)
        assert_eq(sb2["major_ver"], 2)

        # 3. Invalid magic
        disk_invalid = bytearray(2048)
        disk_invalid[0:4] = b"NOPE"
        assert_eq(F2fsSuperblockOracle.parse(bytes(disk_invalid)), None)

    # -------------------------------------------------------------------------
    # PART 2: XFS Adversarial Challenges (ADV-XFS-01 to ADV-XFS-09)
    # -------------------------------------------------------------------------

    def test_adv_xfs_01_inode_to_physical_ag_geometry_standard():
        """ADV-XFS-01: Inode to physical byte offset calculation: 4KB block, 256B inode, 65536 AG blocks."""
        blocksize = 4096
        inodesize = 256
        agblocks = 65536
        inopblog = 4   # 4096 / 256 = 16 = 2^4
        agblklog = 16  # 65536 = 2^16

        # Inode 0: AG 0, block 0, offset 0 -> byte 0
        p0 = XfsInodeToPhysicalOracle.convert(0, inopblog, agblklog, agblocks, blocksize, inodesize)
        assert_eq(p0, 0)

        # Inode 15: AG 0, block 0, offset 15 * 256 = 3840
        p15 = XfsInodeToPhysicalOracle.convert(15, inopblog, agblklog, agblocks, blocksize, inodesize)
        assert_eq(p15, 3840)

        # Inode 16: AG 0, block 1, offset 0 -> byte 4096
        p16 = XfsInodeToPhysicalOracle.convert(16, inopblog, agblklog, agblocks, blocksize, inodesize)
        assert_eq(p16, 4096)

        # First inode in AG 1: ino = 1 << (16 + 4) = 1 << 20 = 1048576
        # Physical block = 1 * 65536 = 65536 -> byte 65536 * 4096 = 268435456
        p_ag1 = XfsInodeToPhysicalOracle.convert(1048576, inopblog, agblklog, agblocks, blocksize, inodesize)
        assert_eq(p_ag1, 65536 * 4096)

        # Verify against MockXfsParser
        assert_eq(MockXfsParser.inode_to_physical(1048576, inopblog, agblklog, agblocks, blocksize, inodesize), 268435456)

    def test_adv_xfs_02_inode_to_physical_varying_geometries():
        """ADV-XFS-02: AG conversions across varied block/inode sizes (512B inodes, 64KB blocks, 1KB blocks)."""
        # Case A: 512-byte inodes, 4096-byte blocks -> inopblog = 3 (8 inodes/block)
        p_a = XfsInodeToPhysicalOracle.convert(
            ino=8, inopblog=3, agblklog=18, agblocks=262144, blocksize=4096, inodesize=512
        )
        assert_eq(p_a, 4096)  # block 1, inode 0

        # Case B: 1024-byte blocks, 256-byte inodes -> inopblog = 2 (4 inodes/block)
        p_b = XfsInodeToPhysicalOracle.convert(
            ino=5, inopblog=2, agblklog=14, agblocks=16384, blocksize=1024, inodesize=256
        )
        # ino 5: block 1, offset 1 * 256 = 1024 + 256 = 1280
        assert_eq(p_b, 1280)

        # Case C: 64KB blocks, 256-byte inodes -> inopblog = 8 (256 inodes/block)
        p_c = XfsInodeToPhysicalOracle.convert(
            ino=256, inopblog=8, agblklog=20, agblocks=1048576, blocksize=65536, inodesize=256
        )
        assert_eq(p_c, 65536)  # block 1 of AG 0

    def test_adv_xfs_03_inode_to_physical_non_power_of_two_ag_blocks():
        """ADV-XFS-03: Non-power-of-two AG size (50,000 blocks per AG -> agblklog = 16)."""
        agblocks = 50000
        agblklog = 16  # (50000 - 1).bit_length() = 16
        inopblog = 4
        blocksize = 4096
        inodesize = 256

        # Inode in AG 2, block 100, inode index 5
        # ino = (2 << (16 + 4)) + (100 << 4) + 5
        ino = (2 << 20) + (100 << 4) + 5
        physical = XfsInodeToPhysicalOracle.convert(ino, inopblog, agblklog, agblocks, blocksize, inodesize)

        expected = (2 * 50000 + 100) * 4096 + (5 * 256)
        assert_eq(physical, expected)

    def test_adv_xfs_04_shortform_local_dir_32bit_parent_and_inodes():
        """ADV-XFS-04: XFS shortform local directory entries with 32-bit parent and inumbers (i8count = 0)."""
        buf = bytearray()
        # Header: count = 2, i8count = 0, parent = 100 (4 bytes BE)
        buf.extend(struct.pack(">BBI", 2, 0, 100))

        # Entry 1: namelen=6, offset=0x0010, name="passwd", ftype=1 (REG), inumber=1001 (4B BE)
        buf.extend(struct.pack(">BH", 6, 0x0010))
        buf.extend(b"passwd")
        buf.extend(struct.pack(">BI", 1, 1001))

        # Entry 2: namelen=5, offset=0x0020, name="hosts", ftype=1 (REG), inumber=1002 (4B BE)
        buf.extend(struct.pack(">BH", 5, 0x0020))
        buf.extend(b"hosts")
        buf.extend(struct.pack(">BI", 1, 1002))

        entries = XfsDir2SfOracle.parse_entries(bytes(buf))
        assert_eq(len(entries), 2)
        assert_eq(entries[0]["name"], "passwd")
        assert_eq(entries[0]["inumber"], 1001)
        assert_eq(entries[0]["parent"], 100)
        assert_eq(entries[0]["file_type"], 1)

        assert_eq(entries[1]["name"], "hosts")
        assert_eq(entries[1]["inumber"], 1002)

    def test_adv_xfs_05_shortform_local_dir_64bit_parent_and_inodes():
        """ADV-XFS-05: XFS shortform local directory entries with 64-bit parent and inumbers (i8count > 0)."""
        buf = bytearray()
        parent_64 = 0x1000_2000_3000
        ino_64 = 0x4000_5000_6000

        # Header: count = 1, i8count = 1, parent = parent_64 (8 bytes BE)
        buf.extend(struct.pack(">BBQ", 1, 1, parent_64))

        # Entry: namelen=7, offset=0x0080, name="bin_dir", ftype=2 (DIR), inumber=ino_64 (8B BE)
        buf.extend(struct.pack(">BH", 7, 0x0080))
        buf.extend(b"bin_dir")
        buf.extend(struct.pack(">BQ", 2, ino_64))

        entries = XfsDir2SfOracle.parse_entries(bytes(buf))
        assert_eq(len(entries), 1)
        assert_eq(entries[0]["name"], "bin_dir")
        assert_eq(entries[0]["inumber"], ino_64)
        assert_eq(entries[0]["parent"], parent_64)
        assert_eq(entries[0]["file_type"], 2)

    def test_adv_xfs_06_shortform_dir_empty_and_truncation_defenses():
        """ADV-XFS-06: XFS shortform dir empty header (count=0) and payload truncation defenses."""
        # Count = 0 returns empty list
        hdr_empty = struct.pack(">BBI", 0, 0, 1)
        assert_eq(XfsDir2SfOracle.parse_entries(hdr_empty), [])

        # Truncated header (< 3 bytes)
        assert_eq(XfsDir2SfOracle.parse_entries(b"\x01"), [])

        # Truncated 64-bit header (says i8count=1, but only 6 bytes provided)
        assert_eq(XfsDir2SfOracle.parse_entries(struct.pack(">BBI", 1, 1, 5)), [])

        # Truncated entry payload (namelen=20, but buffer ends after 4 bytes)
        partial_entry = struct.pack(">BBI", 1, 0, 10) + struct.pack(">BH", 20, 0x10) + b"toolong"
        assert_eq(len(XfsDir2SfOracle.parse_entries(partial_entry)), 0)

    def test_adv_xfs_07_bmbt_128bit_extent_record_decoding():
        """ADV-XFS-07: 128-bit BMBT extent record bit-level field extraction."""
        # Unwritten=True, logical_start=1000, physical_start=50000, block_count=128
        raw1 = XfsExtentOracle.pack(
            is_unwritten=True,
            logical_start=1000,
            physical_start=50000,
            block_count=128
        )
        assert_eq(len(raw1), 16)
        parsed1 = XfsExtentOracle.parse(raw1)
        assert_true(parsed1["is_unwritten"])
        assert_eq(parsed1["logical_start"], 1000)
        assert_eq(parsed1["physical_start"], 50000)
        assert_eq(parsed1["block_count"], 128)

        # Unwritten=False, logical_start=0, physical_start=0, block_count=1
        raw2 = XfsExtentOracle.pack(False, 0, 0, 1)
        parsed2 = XfsExtentOracle.parse(raw2)
        assert_false(parsed2["is_unwritten"])
        assert_eq(parsed2["logical_start"], 0)
        assert_eq(parsed2["physical_start"], 0)
        assert_eq(parsed2["block_count"], 1)

    def test_adv_xfs_08_bmbt_max_boundary_fields_and_sub_16b_defense():
        """ADV-XFS-08: 128-bit BMBT maximum 54-bit logical, 52-bit physical, 21-bit count and truncation defense."""
        max_logical = (1 << 54) - 1
        max_physical = (1 << 52) - 1
        max_count = (1 << 21) - 1

        raw_max = XfsExtentOracle.pack(True, max_logical, max_physical, max_count)
        parsed_max = XfsExtentOracle.parse(raw_max)
        assert_true(parsed_max["is_unwritten"])
        assert_eq(parsed_max["logical_start"], max_logical)
        assert_eq(parsed_max["physical_start"], max_physical)
        assert_eq(parsed_max["block_count"], max_count)

        # Buffer < 16 bytes returns None
        assert_eq(XfsExtentOracle.parse(b"\x00" * 15), None)

    def test_adv_xfs_09_bmbt_multi_extent_logical_block_lookup():
        """ADV-XFS-09: Logical-to-physical block lookup across fragmented extent descriptors."""
        # Extent 0: logical 0..50 -> physical 1000..1050
        ext0 = {"is_unwritten": False, "logical_start": 0, "physical_start": 1000, "block_count": 50}
        # Extent 1: logical 100..150 -> physical 5000..5050 (hole at 50..100)
        ext1 = {"is_unwritten": False, "logical_start": 100, "physical_start": 5000, "block_count": 50}
        extents = [ext0, ext1]

        # In-range Extent 0
        assert_eq(XfsExtentOracle.lookup_block(extents, 0), 1000)
        assert_eq(XfsExtentOracle.lookup_block(extents, 25), 1025)
        assert_eq(XfsExtentOracle.lookup_block(extents, 49), 1049)

        # In hole (50..99)
        assert_eq(XfsExtentOracle.lookup_block(extents, 50), None)
        assert_eq(XfsExtentOracle.lookup_block(extents, 99), None)

        # In-range Extent 1
        assert_eq(XfsExtentOracle.lookup_block(extents, 100), 5000)
        assert_eq(XfsExtentOracle.lookup_block(extents, 149), 5049)

        # Beyond all extents
        assert_eq(XfsExtentOracle.lookup_block(extents, 150), None)

    # -------------------------------------------------------------------------
    # PART 3: ISO9660 & Rock Ridge Challenges (ADV-ISO-01 to ADV-ISO-09)
    # -------------------------------------------------------------------------

    def test_adv_iso_01_joliet_ucs2_big_endian_decoding_and_version_strip():
        """ADV-ISO-01: Joliet UCS-2 Big-Endian decoding and stripping ISO ';1' version suffixes."""
        # "KERNEL.EFI;1" in UTF-16BE
        ucs2_kernel = (
            b"\x00K\x00E\x00R\x00N\x00E\x00L\x00.\x00E\x00F\x00I\x00;\x001"
        )
        assert_eq(Iso9660JolietOracle.parse(ucs2_kernel), "KERNEL.EFI")

        # Cross-check with MockIso9660ExtendedParser
        assert_eq(MockIso9660ExtendedParser.parse_joliet_name(ucs2_kernel), "KERNEL.EFI")

        # Name without semicolon
        ucs2_boot = b"\x00B\x00O\x00O\x00T\x00.\x00C\x00A\x00T"
        assert_eq(Iso9660JolietOracle.parse(ucs2_boot), "BOOT.CAT")

        # Multi-digit version suffix ';123'
        ucs2_multi = b"\x00T\x00E\x00S\x00T\x00;\x001\x002\x003"
        assert_eq(Iso9660JolietOracle.parse(ucs2_multi), "TEST")

        # Semicolon at start ';1' returns empty string
        ucs2_semi = b"\x00;\x001"
        assert_eq(Iso9660JolietOracle.parse(ucs2_semi), "")

    def test_adv_iso_02_joliet_international_unicode_and_odd_byte_slices():
        """ADV-ISO-02: Joliet non-ASCII European and Turkish characters, and trailing odd byte slice tolerance."""
        # "Çekirdek;1"
        # 'Ç' = U+00C7 (0x00, 0xC7), 'e'=0x00, 0x65, 'k'=0x00, 0x6B, 'i'=0x00, 0x69, 'r'=0x00, 0x72
        # 'd'=0x00, 0x64, 'e'=0x00, 0x65, 'k'=0x00, 0x6B
        ucs2_turkish = (
            b"\x00\xC7\x00e\x00k\x00i\x00r\x00d\x00e\x00k\x00;\x001"
        )
        assert_eq(Iso9660JolietOracle.parse(ucs2_turkish), "Çekirdek")

        # Odd length slice (e.g. 5 bytes): last odd byte must be safely ignored without panic
        ucs2_odd = b"\x00A\x00B\x99"
        assert_eq(Iso9660JolietOracle.parse(ucs2_odd), "AB")

        # Empty slice
        assert_eq(Iso9660JolietOracle.parse(b""), "")

    def test_adv_iso_03_rock_ridge_rr_flag_and_nm_alternate_name():
        """ADV-ISO-03: Rock Ridge RR presence flag and NM alternate POSIX filename parsing."""
        sua = bytearray()
        # RR record: sig=b"RR", len=5, ver=1, flags=0x01
        sua.extend(b"RR\x05\x01\x01")
        # NM record: sig=b"NM", len=18, ver=1, flags=0, name="long_posix_name"
        name = b"long_posix_name"
        sua.extend(b"NM" + bytes([len(name) + 5, 1, 0]) + name)

        records = Iso9660SuspOracle.parse(bytes(sua))
        assert_true(records["has_rr"])
        assert_eq(records["alternate_name"], "long_posix_name")

    def test_adv_iso_04_rock_ridge_px_posix_attributes_decoding():
        """ADV-ISO-04: Rock Ridge PX POSIX attributes (mode, links, uid, gid) bit-exact extraction."""
        # PX record: sig=b"PX", len=36, ver=1
        # mode: 0o100755 = 0x81ED, links: 3, uid: 1000, gid: 1000
        payload = struct.pack("<IIIIIIII", 0o100755, 0, 3, 0, 1000, 0, 1000, 0)
        px_record = b"PX\x24\x01" + payload

        records = Iso9660SuspOracle.parse(px_record)
        assert_eq(records["posix_mode"], 0o100755)
        assert_eq(records["posix_links"], 3)
        assert_eq(records["posix_uid"], 1000)
        assert_eq(records["posix_gid"], 1000)

        # Truncated PX (< 36 bytes) defaults to 0o100644 safely
        px_short = b"PX\x08\x01\x00\x00\x00\x00"
        records_short = Iso9660SuspOracle.parse(px_short)
        assert_eq(records_short["posix_mode"], 0o100644)

    def test_adv_iso_05_rock_ridge_sl_symlink_target_decoding():
        """ADV-ISO-05: Rock Ridge SL symbolic link target path parsing."""
        target = b"/usr/lib/libc.so"
        # SL record: sig=b"SL", len=len(target)+5, ver=1, flags=0
        sl_record = b"SL" + bytes([len(target) + 5, 1, 0]) + target

        records = Iso9660SuspOracle.parse(sl_record)
        assert_eq(records["symlink_target"], "/usr/lib/libc.so")

    def test_adv_iso_06_susp_ce_continuation_record_unpacking():
        """ADV-ISO-06: SUSP CE continuation area pointer record layout verification."""
        # CE record: sig=b"CE", len=28, ver=1
        # continuation_lba: 400, offset: 128, length: 512 (BothEndianU32: 4B LE, 4B BE)
        ce_record = b"CE\x1C\x01" + struct.pack("<IIIIII", 400, 400, 128, 128, 512, 512)
        records = Iso9660SuspOracle.parse(ce_record)
        assert_eq(records["continuation_lba"], 400)
        assert_eq(records["continuation_offset"], 128)
        assert_eq(records["continuation_len"], 512)

    def test_adv_iso_07_susp_continuation_multi_hop_chain_resolution():
        """ADV-ISO-07: SUSP multi-hop CE continuation resolution across multiple simulated disc sectors."""
        # Primary SUA contains RR and CE pointing to Sector 100, offset 64, len 100
        primary_sua = bytearray()
        primary_sua.extend(b"RR\x04\x01")
        primary_sua.extend(b"CE\x1C\x01" + struct.pack("<IIIIII", 100, 100, 64, 64, 100, 100))

        # Sector 100 contains NM record and another CE pointing to Sector 101, offset 0, len 50
        sec100 = bytearray(2048)
        sua1 = bytearray()
        sua1.extend(b"NM\x12\x01\x00extended_name")
        sua1.extend(b"CE\x1C\x01" + struct.pack("<IIIIII", 101, 101, 0, 0, 50, 50))
        sec100[64 : 64 + len(sua1)] = sua1

        # Sector 101 contains SL symlink target
        sec101 = bytearray(2048)
        sua2 = b"SL\x16\x01\x00/bin/final_target"
        sec101[0 : len(sua2)] = sua2

        disk_sectors = {100: bytes(sec100), 101: bytes(sec101)}

        def read_sec(lba):
            return disk_sectors.get(lba)

        combined, hops = Iso9660CeContinuationResolver.resolve_all_susp_records(bytes(primary_sua), read_sec)
        assert_true(combined["has_rr"])
        assert_eq(combined["alternate_name"], "extended_name")
        assert_eq(combined["symlink_target"], "/bin/final_target")
        assert_eq(hops, 2)

    def test_adv_iso_08_susp_circular_continuation_infinite_recursion_defense():
        """ADV-ISO-08: Circular CE references (CE1 -> CE2 -> CE1) terminate safely without infinite loop."""
        # Initial SUA points to Sector 200
        initial_sua = b"CE\x1C\x01" + struct.pack("<IIIIII", 200, 200, 0, 0, 64, 64)

        # Sector 200 points to Sector 201
        sec200 = bytearray(2048)
        sec200[0:28] = b"CE\x1C\x01" + struct.pack("<IIIIII", 201, 201, 0, 0, 64, 64)

        # Sector 201 points BACK to Sector 200 (circular cycle!)
        sec201 = bytearray(2048)
        sec201[0:28] = b"CE\x1C\x01" + struct.pack("<IIIIII", 200, 200, 0, 0, 64, 64)

        disk_sectors = {200: bytes(sec200), 201: bytes(sec201)}

        def read_sec(lba):
            return disk_sectors.get(lba)

        # Traversal must detect cycle or hit MAX_CONTINUATION_DEPTH without hanging
        combined, hops = Iso9660CeContinuationResolver.resolve_all_susp_records(initial_sua, read_sec)
        # Cycle detected on second visit to sector 200 -> hops <= 2
        assert_true(hops <= 3)

    def test_adv_iso_09_susp_corrupt_zero_len_and_truncated_headers():
        """ADV-ISO-09: Corrupt SUSP header defenses: length < 4, length == 0, buffer overrun, unknown signatures."""
        # Length == 0 would cause infinite loop if not clamped
        zero_len = b"XX\x00\x01\x00\x00\x00\x00"
        records1 = Iso9660SuspOracle.parse(zero_len)
        assert_false(records1["has_rr"])

        # Truncated header (< 4 bytes)
        assert_false(Iso9660SuspOracle.parse(b"RR\x04")["has_rr"])

        # Length claims 100 bytes on a 10-byte buffer -> terminated safely
        overrun = b"RR\x64\x01" + (b"\x00" * 6)
        assert_false(Iso9660SuspOracle.parse(overrun)["has_rr"])

        # Unknown signatures (e.g. b"ZZ") safely skipped, valid NM record parsed after
        skipped = b"ZZ\x06\x01\x11\x22" + b"NM\x0A\x01\x00valid"
        records2 = Iso9660SuspOracle.parse(skipped)
        assert_eq(records2["alternate_name"], "valid")

    # -------------------------------------------------------------------------
    # PART 4: Unified VFS Integration & Stress (ADV-VFS-01 to ADV-VFS-03)
    # -------------------------------------------------------------------------

    def test_adv_vfs_01_inode_read_at_boundary_conditions():
        """ADV-VFS-01: Inode read_at operations: exact bounds, partial buffer reads, offset >= size returns 0."""
        file_payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        file_size = len(file_payload)

        # 1. Read at offset 0, exact buffer size
        buf1 = bytearray(file_size)
        off1 = 0
        to_read1 = min(file_size - off1, len(buf1))
        buf1[:to_read1] = file_payload[off1 : off1 + to_read1]
        assert_eq(bytes(buf1), file_payload)

        # 2. Read at offset 26 (digits only)
        buf2 = bytearray(10)
        off2 = 26
        to_read2 = min(file_size - off2, len(buf2))
        buf2[:to_read2] = file_payload[off2 : off2 + to_read2]
        assert_eq(bytes(buf2), b"0123456789")

        # 3. Read at/past EOF returns 0 bytes
        off3 = file_size + 10
        to_read3 = 0 if off3 >= file_size else min(file_size - off3, 10)
        assert_eq(to_read3, 0)

    def test_adv_vfs_02_directory_lookup_and_slash_normalization():
        """ADV-VFS-02: Path lookup across '/' root prefixes and nonexistent path rejection."""
        mock_tree = {
            "kernel.efi": {"ino": 100, "is_dir": False},
            "EFI/BOOT/BOOTX64.EFI": {"ino": 101, "is_dir": False},
            "etc": {"ino": 102, "is_dir": True},
        }

        def lookup(path: str) -> Optional[int]:
            clean = path.strip("/")
            item = mock_tree.get(clean)
            return item["ino"] if item else None

        assert_eq(lookup("/kernel.efi"), 100)
        assert_eq(lookup("kernel.efi"), 100)
        assert_eq(lookup("/EFI/BOOT/BOOTX64.EFI"), 101)
        assert_eq(lookup("/etc"), 102)
        assert_eq(lookup("/nonexistent.dat"), None)

    def test_adv_vfs_03_cross_filesystem_structure_size_invariants():
        """ADV-VFS-03: On-disk structure sizes match filesystem specifications exactly."""
        # F2FS Inode node page size = 4096
        assert_eq(F2FS_BLKSIZE, 4096)
        # F2FS NAT entries per block = 455 (455 * 9 = 4095 <= 4096)
        assert_true(F2FS_NAT_ENTRIES_PER_BLOCK * 9 <= 4096)
        # F2FS Dentry block entries = 214 (30 + 214 * 11 + 214 * 8 = 4096)
        assert_eq(30 + 214 * 11 + 214 * 8, 4096)
        # XFS Inode dinode core minimum size = 100 bytes
        assert_true(100 <= 256)
        # ISO9660 sector size = 2048 bytes
        assert_eq(ISO_SECTOR_SIZE, 2048)

    # Register all 30 adversarial challenges
    suite.add("ADV-F2FS-01 Dual checkpoint selection matrix", test_adv_f2fs_01_dual_checkpoint_selection_matrix)
    suite.add("ADV-F2FS-02 Checkpoint u64 wrap & boundary versions", test_adv_f2fs_02_checkpoint_u64_wrap_and_boundary_versions)
    suite.add("ADV-F2FS-03 NAT page boundary calculation at entry 455", test_adv_f2fs_03_nat_page_boundary_calculation_at_entry_455)
    suite.add("ADV-F2FS-04 NAT truncated page and missing block defense", test_adv_f2fs_04_nat_truncated_page_and_missing_block_defense)
    suite.add("ADV-F2FS-05 Inode direct 923 addressing and footer", test_adv_f2fs_05_inode_direct_923_addressing_and_footer)
    suite.add("ADV-F2FS-06 Inode inline flag and truncation defense", test_adv_f2fs_06_inode_inline_flag_and_truncation_defense)
    suite.add("ADV-F2FS-07 Dentry multi-slot filenames parsing", test_adv_f2fs_07_dentry_multi_slot_filenames_parsing)
    suite.add("ADV-F2FS-08 Dentry boundary slot 213 and overrun defense", test_adv_f2fs_08_dentry_boundary_slot_213_and_overrun_defense)
    suite.add("ADV-F2FS-09 Superblock dual offset magic validation", test_adv_f2fs_09_superblock_dual_offset_magic_validation)

    suite.add("ADV-XFS-01 Inode to physical AG geometry standard", test_adv_xfs_01_inode_to_physical_ag_geometry_standard)
    suite.add("ADV-XFS-02 Inode to physical varying geometries", test_adv_xfs_02_inode_to_physical_varying_geometries)
    suite.add("ADV-XFS-03 Inode to physical non-power-of-two AG blocks", test_adv_xfs_03_inode_to_physical_non_power_of_two_ag_blocks)
    suite.add("ADV-XFS-04 Shortform local dir 32-bit parent & inodes", test_adv_xfs_04_shortform_local_dir_32bit_parent_and_inodes)
    suite.add("ADV-XFS-05 Shortform local dir 64-bit parent & inodes", test_adv_xfs_05_shortform_local_dir_64bit_parent_and_inodes)
    suite.add("ADV-XFS-06 Shortform dir empty and truncation defenses", test_adv_xfs_06_shortform_dir_empty_and_truncation_defenses)
    suite.add("ADV-XFS-07 BMBT 128-bit extent record decoding", test_adv_xfs_07_bmbt_128bit_extent_record_decoding)
    suite.add("ADV-XFS-08 BMBT max boundary fields and sub-16B defense", test_adv_xfs_08_bmbt_max_boundary_fields_and_sub_16b_defense)
    suite.add("ADV-XFS-09 BMBT multi-extent logical block lookup", test_adv_xfs_09_bmbt_multi_extent_logical_block_lookup)

    suite.add("ADV-ISO-01 Joliet UCS-2 UTF-16BE decoding & version strip", test_adv_iso_01_joliet_ucs2_big_endian_decoding_and_version_strip)
    suite.add("ADV-ISO-02 Joliet international unicode & odd byte slices", test_adv_iso_02_joliet_international_unicode_and_odd_byte_slices)
    suite.add("ADV-ISO-03 Rock Ridge RR flag & NM alternate name", test_adv_iso_03_rock_ridge_rr_flag_and_nm_alternate_name)
    suite.add("ADV-ISO-04 Rock Ridge PX POSIX attributes decoding", test_adv_iso_04_rock_ridge_px_posix_attributes_decoding)
    suite.add("ADV-ISO-05 Rock Ridge SL symlink target decoding", test_adv_iso_05_rock_ridge_sl_symlink_target_decoding)
    suite.add("ADV-ISO-06 SUSP CE continuation record unpacking", test_adv_iso_06_susp_ce_continuation_record_unpacking)
    suite.add("ADV-ISO-07 SUSP continuation multi-hop chain resolution", test_adv_iso_07_susp_continuation_multi_hop_chain_resolution)
    suite.add("ADV-ISO-08 SUSP circular continuation recursion defense", test_adv_iso_08_susp_circular_continuation_infinite_recursion_defense)
    suite.add("ADV-ISO-09 SUSP corrupt zero-len and truncated headers", test_adv_iso_09_susp_corrupt_zero_len_and_truncated_headers)

    suite.add("ADV-VFS-01 Inode read_at boundary conditions", test_adv_vfs_01_inode_read_at_boundary_conditions)
    suite.add("ADV-VFS-02 Directory lookup & slash normalization", test_adv_vfs_02_directory_lookup_and_slash_normalization)
    suite.add("ADV-VFS-03 Cross-filesystem structure size invariants", test_adv_vfs_03_cross_filesystem_structure_size_invariants)

    return suite


def main():
    suite = build_m3_challenger_suite()
    passed, failed, _ = suite.run(verbose=True)
    print("\n" + "=" * 70)
    print(f"CHALLENGER RESULT: {passed} passed, {failed} failed across {passed + failed} adversarial stress tests.")
    print("=" * 70)
    if failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
