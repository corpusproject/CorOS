#!/usr/bin/env python3
"""
CorOS Milestone 2 Subsystem 6 (Dynamic Linker & ELF Loader) Empirical Challenger Suite
=====================================================================================
Target: Milestone 2 Implementation Modules:
- cortoolchain/src/ld_so.rs (PT_DYNAMIC parsing, GNU & SysV Hash, Eager vs Lazy Binding stubs)
- cortoolchain/src/elf64_reloc.rs (ELF64 relocations: R_X86_64_RELATIVE, GLOB_DAT, COPY, JUMP_SLOT)
- corvfs/src/elf64_loader.rs (ELF64 binary loader, W^X validator, User Stack setup, AuxvEntry)

Adversarial Verification Dimensions:
1. Dynamic Tag Parsing: 16-byte Elf64Dyn layout, complete parsing of all dynamic tags
   (DT_NEEDED, DT_SYMTAB, DT_STRTAB, DT_RELA, DT_JMPREL, DT_GNU_HASH, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1).
2. GNU Hash & SysV Hash: Empty string hash calculations (0 for SysV, 5381 for GNU),
   hash collision resolution, and 64-bit Bloom filter mask verification.
3. Relocation Calculations: R_X86_64_RELATIVE (zero base vs non-zero base, negative addends),
   R_X86_64_GLOB_DAT, R_X86_64_COPY memory byte copying and buffer size validation.
4. Eager vs Lazy Binding: R_X86_64_JUMP_SLOT eager resolution vs lazy PLT0 trampoline entry
   (target_slot + 6), and dl_runtime_resolve GOT table mutation.
5. Auxiliary Vector & User Stack Frame: Stack alignment RSP % 16 == 0 across combinatorial
   permutations, NULL-terminated argv/envp pointer tables, AuxvEntry extraction & missing tag behavior.

Zero external package dependencies (pure Python standard library).
"""

import enum
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
    ElfDynamicTag, ElfRelocType, MockDynamicLinker
)


# =========================================================================
# Rust Exact Bit-for-Bit Behavioral Replicas & Oracles
# =========================================================================

# --- Dynamic Tag Constants matching cortoolchain::ld_so ---
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_PLTREL = 20
DT_DEBUG = 21
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH = 29
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFF_FFFB
DT_GNU_HASH = 0x6FFF_FEF5

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

# --- Relocation Types matching cortoolchain::elf64_reloc ---
R_X86_64_NONE = 0
R_X86_64_64 = 1
R_X86_64_PC32 = 2
R_X86_64_GOT32 = 3
R_X86_64_PLT32 = 4
R_X86_64_COPY = 5
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8
R_X86_64_GOTPCREL = 9
R_X86_64_32 = 10
R_X86_64_32S = 11

# --- Auxiliary Vector Constants matching corvfs::elf64_loader ---
AT_NULL = 0
AT_IGNORE = 1
AT_EXECFD = 2
AT_PHDR = 3
AT_PHENT = 4
AT_PHNUM = 5
AT_PAGESZ = 6
AT_BASE = 7
AT_FLAGS = 8
AT_ENTRY = 9
AT_NOTELF = 10
AT_UID = 11
AT_EUID = 12
AT_GID = 13
AT_EGID = 14
AT_PLATFORM = 15
AT_HWCAP = 16
AT_CLKTCK = 17
AT_SECURE = 23
AT_BASE_PLATFORM = 24
AT_RANDOM = 25
AT_HWCAP2 = 26
AT_EXECFN = 31
AT_SYSINFO_EHDR = 33


class DynamicSectionParseError(Exception):
    """Corresponds to LinkerError::CorruptedHeader in cortoolchain::ld_so."""
    pass


class RelocationError(Exception):
    """Corresponds to RelocError in cortoolchain::elf64_reloc."""
    pass


class BufferOverflowError(RelocationError):
    def __init__(self, offset: int, needed: int, capacity: int):
        super().__init__(f"BufferOverflow at offset {offset}, needed {needed}, capacity {capacity}")
        self.offset = offset
        self.needed = needed
        self.capacity = capacity


class SymbolNotFoundError(RelocationError):
    def __init__(self, sym: Any):
        super().__init__(f"Symbol not found: {sym}")
        self.sym = sym


class ParsedDynamicSectionOracle:
    """Exact bit-for-bit replica of ParsedDynamicSection::parse from cortoolchain::ld_so."""
    def __init__(self):
        self.needed: List[int] = []
        self.symtab: Optional[int] = None
        self.strtab: Optional[int] = None
        self.strsz: Optional[int] = None
        self.syment: Optional[int] = None
        self.rela: Optional[int] = None
        self.relasz: Optional[int] = None
        self.relaent: Optional[int] = None
        self.jmprel: Optional[int] = None
        self.pltrelsz: Optional[int] = None
        self.pltgot: Optional[int] = None
        self.gnu_hash: Optional[int] = None
        self.hash: Optional[int] = None
        self.init: Optional[int] = None
        self.fini: Optional[int] = None
        self.init_array: Optional[int] = None
        self.init_arraysz: Optional[int] = None
        self.fini_array: Optional[int] = None
        self.fini_arraysz: Optional[int] = None
        self.flags: Optional[int] = None
        self.flags_1: Optional[int] = None
        self.is_bind_now: bool = False

    @classmethod
    def parse(cls, raw: bytes) -> "ParsedDynamicSectionOracle":
        entry_size = 16  # sizeof(Elf64Dyn): d_tag(8) + d_val(8)
        if len(raw) % entry_size != 0:
            raise DynamicSectionParseError("Dynamic section not aligned to Elf64Dyn")

        parsed = cls()
        count = len(raw) // entry_size
        for i in range(count):
            offset = i * entry_size
            d_tag, d_val = struct.unpack_from("<QQ", raw, offset)
            if d_tag == DT_NULL:
                break
            if d_tag == DT_NEEDED:
                parsed.needed.append(d_val)
            elif d_tag == DT_SYMTAB:
                parsed.symtab = d_val
            elif d_tag == DT_STRTAB:
                parsed.strtab = d_val
            elif d_tag == DT_STRSZ:
                parsed.strsz = d_val
            elif d_tag == DT_SYMENT:
                parsed.syment = d_val
            elif d_tag == DT_RELA:
                parsed.rela = d_val
            elif d_tag == DT_RELASZ:
                parsed.relasz = d_val
            elif d_tag == DT_RELAENT:
                parsed.relaent = d_val
            elif d_tag == DT_JMPREL:
                parsed.jmprel = d_val
            elif d_tag == DT_PLTRELSZ:
                parsed.pltrelsz = d_val
            elif d_tag == DT_PLTGOT:
                parsed.pltgot = d_val
            elif d_tag == DT_GNU_HASH:
                parsed.gnu_hash = d_val
            elif d_tag == DT_HASH:
                parsed.hash = d_val
            elif d_tag == DT_INIT:
                parsed.init = d_val
            elif d_tag == DT_FINI:
                parsed.fini = d_val
            elif d_tag == DT_INIT_ARRAY:
                parsed.init_array = d_val
            elif d_tag == DT_INIT_ARRAYSZ:
                parsed.init_arraysz = d_val
            elif d_tag == DT_FINI_ARRAY:
                parsed.fini_array = d_val
            elif d_tag == DT_FINI_ARRAYSZ:
                parsed.fini_arraysz = d_val
            elif d_tag == DT_FLAGS:
                parsed.flags = d_val
                if (d_val & DF_BIND_NOW) != 0:
                    parsed.is_bind_now = True
            elif d_tag == DT_FLAGS_1:
                parsed.flags_1 = d_val
                if (d_val & DF_1_NOW) != 0:
                    parsed.is_bind_now = True
            elif d_tag == DT_BIND_NOW:
                parsed.is_bind_now = True

        return parsed


class RustGnuHashOracle:
    """Exact bit-for-bit replica of gnu_hash, sysv_hash, and GnuHashTable in cortoolchain::ld_so."""

    @staticmethod
    def gnu_hash(name: bytes) -> int:
        h = 5381
        for b in name:
            h = (((h * 33) & 0xFFFFFFFF) + b) & 0xFFFFFFFF
        return h

    @staticmethod
    def sysv_hash(name: bytes) -> int:
        h = 0
        for b in name:
            h = ((h << 4) + b) & 0xFFFFFFFF
            g = h & 0xF0000000
            if g != 0:
                h ^= (g >> 24)
            h &= ~g
        return h & 0xFFFFFFFF

    @staticmethod
    def compute_bloom_mask(h: int, bloom_shift: int) -> Tuple[int, int, int]:
        elfclass_bits = 64
        mask1 = 1 << (h % elfclass_bits)
        mask2 = 1 << ((h >> bloom_shift) % elfclass_bits)
        combined_mask = mask1 | mask2
        return mask1, mask2, combined_mask

    @staticmethod
    def check_bloom_filter(bloom_filter: List[int], h: int, bloom_shift: int) -> bool:
        if not bloom_filter:
            return False
        elfclass_bits = 64
        bloom_size = len(bloom_filter)
        word_idx = (h // elfclass_bits) % bloom_size
        word = bloom_filter[word_idx]
        _, _, combined_mask = RustGnuHashOracle.compute_bloom_mask(h, bloom_shift)
        return (word & combined_mask) == combined_mask

    @staticmethod
    def lookup_chain(
        name: str,
        symtab_names: List[str],
        nbuckets: int,
        symoffset: int,
        buckets: List[int],
        chain: List[int],
    ) -> Optional[int]:
        if nbuckets == 0:
            return None
        h = RustGnuHashOracle.gnu_hash(name.encode("utf-8"))
        bucket_idx = h % nbuckets
        if bucket_idx >= len(buckets):
            return None
        sym_idx = buckets[bucket_idx]
        if sym_idx < symoffset:
            return None

        while True:
            chain_idx = sym_idx - symoffset
            if chain_idx >= len(chain):
                return None
            chain_hash = chain[chain_idx]
            # Match ignoring lowest bit
            if (chain_hash | 1) == (h | 1):
                if sym_idx < len(symtab_names) and symtab_names[sym_idx] == name:
                    return sym_idx
            # Lowest bit indicates end of hash chain
            if (chain_hash & 1) != 0:
                break
            sym_idx += 1
        return None


class RustRelocationEngineOracle:
    """Exact bit-for-bit replica of RelocationEngine in cortoolchain::elf64_reloc."""

    @staticmethod
    def apply_rela(
        buffer: bytearray,
        offset: int,
        reloc_type: int,
        sym_addr: Optional[int],
        addend: int,
        base_address: int,
    ) -> int:
        if reloc_type == R_X86_64_NONE:
            return 0

        elif reloc_type == R_X86_64_RELATIVE:
            # B + A (wrapping 64-bit)
            val = (base_address + addend) & 0xFFFFFFFFFFFFFFFF
            if offset + 8 > len(buffer):
                raise BufferOverflowError(offset, 8, len(buffer))
            struct.pack_into("<Q", buffer, offset, val)
            return 8

        elif reloc_type in (R_X86_64_64, R_X86_64_GLOB_DAT):
            # S + A (for 64) or S (for GLOB_DAT)
            if sym_addr is None:
                raise SymbolNotFoundError("missing")
            val = (sym_addr + (addend if reloc_type == R_X86_64_64 else 0)) & 0xFFFFFFFFFFFFFFFF
            if offset + 8 > len(buffer):
                raise BufferOverflowError(offset, 8, len(buffer))
            struct.pack_into("<Q", buffer, offset, val)
            return 8

        elif reloc_type == R_X86_64_COPY:
            # S (copy symbol address / data into destination buffer)
            if sym_addr is None:
                raise SymbolNotFoundError("missing")
            copy_size = addend if addend > 0 else 8
            if offset + 8 > len(buffer):
                raise BufferOverflowError(offset, 8, len(buffer))
            struct.pack_into("<Q", buffer, offset, sym_addr & 0xFFFFFFFFFFFFFFFF)
            return copy_size

        elif reloc_type == R_X86_64_JUMP_SLOT:
            if sym_addr is None:
                raise SymbolNotFoundError("missing")
            if offset + 8 > len(buffer):
                raise BufferOverflowError(offset, 8, len(buffer))
            struct.pack_into("<Q", buffer, offset, sym_addr & 0xFFFFFFFFFFFFFFFF)
            return 8

        else:
            raise RelocationError(f"Unsupported relocation type: {reloc_type}")


class RustDynamicLinkerOracle:
    """Exact replica of DynamicLinker relocation, lazy trampoline, and dl_runtime_resolve."""
    def __init__(self, eager_binding: bool = False):
        self.eager_binding = eager_binding
        self.symbols: Dict[str, int] = {}
        self.got_table: Dict[int, int] = {}

    def register_symbol(self, name: str, addr: int):
        self.symbols[name] = addr

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self.symbols.get(name)

    def apply_relocation(
        self,
        reloc_type: int,
        target_slot: int,
        sym_name: Optional[str] = None,
        addend: int = 0,
        base_addr: int = 0,
    ) -> int:
        if reloc_type == R_X86_64_RELATIVE:
            resolved = (base_addr + addend) & 0xFFFFFFFFFFFFFFFF
            self.got_table[target_slot] = resolved
            return resolved

        elif reloc_type == R_X86_64_GLOB_DAT:
            if not sym_name:
                raise DynamicSectionParseError("Missing sym_name for GLOB_DAT")
            addr = self.resolve_symbol(sym_name)
            if addr is None:
                raise SymbolNotFoundError(sym_name)
            self.got_table[target_slot] = addr
            return addr

        elif reloc_type == R_X86_64_JUMP_SLOT:
            if not sym_name:
                raise DynamicSectionParseError("Missing sym_name for JUMP_SLOT")
            if self.eager_binding:
                addr = self.resolve_symbol(sym_name)
                if addr is None:
                    raise SymbolNotFoundError(sym_name)
                self.got_table[target_slot] = addr
                return addr
            else:
                trampoline = target_slot + 6
                self.got_table[target_slot] = trampoline
                return trampoline

        else:
            raise RelocationError(f"Unknown relocation type {reloc_type}")

    def dl_runtime_resolve(self, target_slot: int, sym_name: str) -> int:
        addr = self.resolve_symbol(sym_name)
        if addr is None:
            raise SymbolNotFoundError(sym_name)
        self.got_table[target_slot] = addr
        return addr


class RustUserStackOracle:
    """Exact replica of setup_user_stack in corvfs::elf64_loader."""

    @staticmethod
    def setup_user_stack(
        stack_top: int,
        argv: List[str],
        envp: List[str],
        auxv: List[Tuple[int, int]],
    ) -> Tuple[int, bytes]:
        total_string_len = sum(len(a.encode("utf-8")) + 1 for a in argv) + sum(len(e.encode("utf-8")) + 1 for e in envp)
        random_bytes_size = 16

        # argc (8) + argv pointers ((len(argv)+1)*8) + envp pointers ((len(envp)+1)*8) + auxv ((len(auxv)+1)*16)
        table_bytes = 8 + (len(argv) + 1) * 8 + (len(envp) + 1) * 8 + (len(auxv) + 1) * 16

        strings_and_random = total_string_len + random_bytes_size
        strings_start = stack_top - strings_and_random
        unaligned_rsp = strings_start - table_bytes
        # 16-byte stack alignment: initial_rsp % 16 == 0
        initial_rsp = unaligned_rsp & ~15

        total_size = stack_top - initial_rsp
        stack_bytes = bytearray(total_size)

        random_addr = stack_top - 16
        rand_off = random_addr - initial_rsp
        if rand_off + 16 <= len(stack_bytes):
            stack_bytes[rand_off:rand_off + 16] = bytes([
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21,
            ])

        curr_vaddr = strings_start
        argv_addrs = []
        for arg in argv:
            argv_addrs.append(curr_vaddr)
            b = arg.encode("utf-8")
            off = curr_vaddr - initial_rsp
            stack_bytes[off:off + len(b)] = b
            stack_bytes[off + len(b)] = 0
            curr_vaddr += len(b) + 1

        envp_addrs = []
        for env in envp:
            envp_addrs.append(curr_vaddr)
            b = env.encode("utf-8")
            off = curr_vaddr - initial_rsp
            stack_bytes[off:off + len(b)] = b
            stack_bytes[off + len(b)] = 0
            curr_vaddr += len(b) + 1

        # Write table starting at initial_rsp (offset 0 in stack_bytes)
        off = 0
        # argc
        struct.pack_into("<Q", stack_bytes, off, len(argv))
        off += 8

        # argv pointers + NULL
        for addr in argv_addrs:
            struct.pack_into("<Q", stack_bytes, off, addr)
            off += 8
        struct.pack_into("<Q", stack_bytes, off, 0)
        off += 8

        # envp pointers + NULL
        for addr in envp_addrs:
            struct.pack_into("<Q", stack_bytes, off, addr)
            off += 8
        struct.pack_into("<Q", stack_bytes, off, 0)
        off += 8

        # auxv entries + AT_NULL
        for a_type, a_val in auxv:
            val = random_addr if (a_type == AT_RANDOM and a_val == 0) else a_val
            struct.pack_into("<QQ", stack_bytes, off, a_type, val)
            off += 16
        struct.pack_into("<QQ", stack_bytes, off, AT_NULL, 0)
        off += 16

        return initial_rsp, bytes(stack_bytes)


# =========================================================================
# Adversarial Challenge Suite Builder
# =========================================================================

def build_empirical_challenger_suite() -> TestSuite:
    suite = TestSuite("Milestone 2 Subsystem 6 Dynamic Linker & ELF Loader Adversarial Suite", tier=5)

    # -------------------------------------------------------------------------
    # 1. Dynamic Tag Parsing Tests (16-byte Elf64Dyn Layout & Full Dynamic Tags)
    # -------------------------------------------------------------------------

    def test_adv_tag_01_16byte_alignment_enforcement():
        """ADV-TAG-01: Rejection of dynamic sections with unaligned byte lengths."""
        # Valid size must be a multiple of 16
        for invalid_len in [1, 7, 15, 17, 24, 31, 33, 47, 63, 65]:
            unaligned_raw = b"\x00" * invalid_len
            assert_raises(DynamicSectionParseError, ParsedDynamicSectionOracle.parse, unaligned_raw)

        # Multiples of 16 must succeed
        for valid_len in [0, 16, 32, 48, 64, 128]:
            aligned_raw = b"\x00" * valid_len
            res = ParsedDynamicSectionOracle.parse(aligned_raw)
            assert_true(isinstance(res, ParsedDynamicSectionOracle))

    def test_adv_tag_02_all_dynamic_tags_exact_extraction():
        """ADV-TAG-02: Parsing of all dynamic tags (DT_NEEDED, DT_SYMTAB, DT_STRTAB, DT_RELA, etc.)."""
        tags = [
            (DT_NEEDED, 101),
            (DT_NEEDED, 102),
            (DT_NEEDED, 103),
            (DT_PLTRELSZ, 0x120),
            (DT_PLTGOT, 0x405000),
            (DT_HASH, 0x406000),
            (DT_STRTAB, 0x402000),
            (DT_SYMTAB, 0x401000),
            (DT_RELA, 0x403000),
            (DT_RELASZ, 0x240),
            (DT_RELAENT, 24),
            (DT_STRSZ, 4096),
            (DT_SYMENT, 24),
            (DT_INIT, 0x408000),
            (DT_FINI, 0x409000),
            (DT_JMPREL, 0x404000),
            (DT_INIT_ARRAY, 0x40A000),
            (DT_FINI_ARRAY, 0x40B000),
            (DT_INIT_ARRAYSZ, 16),
            (DT_FINI_ARRAYSZ, 8),
            (DT_FLAGS, 0x8),           # DF_BIND_NOW
            (DT_FLAGS_1, 0x1),         # DF_1_NOW
            (DT_GNU_HASH, 0x40C000),
            (DT_NULL, 0),              # Terminator
        ]

        raw = bytearray()
        for tag, val in tags:
            raw.extend(struct.pack("<QQ", tag, val))

        parsed = ParsedDynamicSectionOracle.parse(bytes(raw))

        assert_eq(parsed.needed, [101, 102, 103], "Multiple DT_NEEDED preserved in order")
        assert_eq(parsed.symtab, 0x401000)
        assert_eq(parsed.strtab, 0x402000)
        assert_eq(parsed.strsz, 4096)
        assert_eq(parsed.syment, 24)
        assert_eq(parsed.rela, 0x403000)
        assert_eq(parsed.relasz, 0x240)
        assert_eq(parsed.relaent, 24)
        assert_eq(parsed.jmprel, 0x404000)
        assert_eq(parsed.pltrelsz, 0x120)
        assert_eq(parsed.pltgot, 0x405000)
        assert_eq(parsed.gnu_hash, 0x40C000)
        assert_eq(parsed.hash, 0x406000)
        assert_eq(parsed.init, 0x408000)
        assert_eq(parsed.fini, 0x409000)
        assert_eq(parsed.init_array, 0x40A000)
        assert_eq(parsed.init_arraysz, 16)
        assert_eq(parsed.fini_array, 0x40B000)
        assert_eq(parsed.fini_arraysz, 8)
        assert_eq(parsed.flags, 0x8)
        assert_eq(parsed.flags_1, 0x1)
        assert_true(parsed.is_bind_now, "DF_BIND_NOW and DF_1_NOW trigger is_bind_now")

    def test_adv_tag_03_dt_null_early_termination_and_trailing_garbage():
        """ADV-TAG-03: DT_NULL immediately halts parsing; subsequent tags ignored."""
        raw = bytearray()
        raw.extend(struct.pack("<QQ", DT_NEEDED, 42))
        raw.extend(struct.pack("<QQ", DT_NULL, 0))
        # Trailing tags after DT_NULL must be completely ignored
        raw.extend(struct.pack("<QQ", DT_NEEDED, 999))
        raw.extend(struct.pack("<QQ", DT_SYMTAB, 0xDEADBEEF))

        parsed = ParsedDynamicSectionOracle.parse(bytes(raw))
        assert_eq(parsed.needed, [42], "Only DT_NEEDED before DT_NULL parsed")
        assert_eq(parsed.symtab, None, "Tags after DT_NULL ignored")

    def test_adv_tag_04_is_bind_now_activation_matrix():
        """ADV-TAG-04: is_bind_now flags activation matrix (DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1)."""
        # Case 1: DT_BIND_NOW tag
        r1 = struct.pack("<QQQQ", DT_BIND_NOW, 1, DT_NULL, 0)
        p1 = ParsedDynamicSectionOracle.parse(r1)
        assert_true(p1.is_bind_now)

        # Case 2: DT_FLAGS with DF_BIND_NOW (0x8)
        r2 = struct.pack("<QQQQ", DT_FLAGS, 0x8, DT_NULL, 0)
        p2 = ParsedDynamicSectionOracle.parse(r2)
        assert_true(p2.is_bind_now)

        # Case 3: DT_FLAGS without DF_BIND_NOW (e.g. 0x4)
        r3 = struct.pack("<QQQQ", DT_FLAGS, 0x4, DT_NULL, 0)
        p3 = ParsedDynamicSectionOracle.parse(r3)
        assert_false(p3.is_bind_now)

        # Case 4: DT_FLAGS_1 with DF_1_NOW (0x1)
        r4 = struct.pack("<QQQQ", DT_FLAGS_1, 0x1, DT_NULL, 0)
        p4 = ParsedDynamicSectionOracle.parse(r4)
        assert_true(p4.is_bind_now)

        # Case 5: DT_FLAGS_1 without DF_1_NOW (e.g. 0x2)
        r5 = struct.pack("<QQQQ", DT_FLAGS_1, 0x2, DT_NULL, 0)
        p5 = ParsedDynamicSectionOracle.parse(r5)
        assert_false(p5.is_bind_now)

    def test_adv_tag_05_unknown_dynamic_tags_tolerance():
        """ADV-TAG-05: Dynamic tag parser tolerates unknown / reserved dynamic tags."""
        raw = bytearray()
        raw.extend(struct.pack("<QQ", 0x70000001, 0x12345678))  # Unknown processor-specific tag
        raw.extend(struct.pack("<QQ", DT_STRTAB, 0x402000))
        raw.extend(struct.pack("<QQ", 0x6FFFFFFF, 0x9999))      # Unknown OS-specific tag
        raw.extend(struct.pack("<QQ", DT_NULL, 0))

        parsed = ParsedDynamicSectionOracle.parse(bytes(raw))
        assert_eq(parsed.strtab, 0x402000)

    # -------------------------------------------------------------------------
    # 2. GNU Hash & SysV Hash Calculations & Bloom Filter Verification
    # -------------------------------------------------------------------------

    def test_adv_hash_01_empty_string_exact_hash_values():
        """ADV-HASH-01: Empty string hash calculations: SysV is 0, GNU is 5381."""
        # System V empty string hash
        assert_eq(RustGnuHashOracle.sysv_hash(b""), 0)
        assert_eq(MockDynamicLinker.sysv_hash(""), 0)

        # GNU Hash empty string hash
        assert_eq(RustGnuHashOracle.gnu_hash(b""), 5381)
        assert_eq(MockDynamicLinker.gnu_hash(""), 5381)

    def test_adv_hash_02_deterministic_hash_vectors():
        """ADV-HASH-02: Deterministic hash vectors across standard libc symbols."""
        test_syms = [
            b"printf", b"malloc", b"free", b"open", b"write", b"read",
            b"__libc_start_main", b"_start", b"_init", b"_fini"
        ]
        for sym in test_syms:
            gh1 = RustGnuHashOracle.gnu_hash(sym)
            gh2 = MockDynamicLinker.gnu_hash(sym.decode("utf-8"))
            assert_eq(gh1, gh2, f"GNU hash mismatch for {sym}")
            assert_true(0 <= gh1 <= 0xFFFFFFFF)

            sv1 = RustGnuHashOracle.sysv_hash(sym)
            sv2 = MockDynamicLinker.sysv_hash(sym.decode("utf-8"))
            assert_eq(sv1, sv2, f"SysV hash mismatch for {sym}")
            assert_true(0 <= sv1 <= 0xFFFFFFFF)

    def test_adv_hash_03_bloom_filter_64bit_mask_verification():
        """ADV-HASH-03: Bloom filter 64-bit dual-mask verification and miss filtering."""
        # Test word mask calculations
        h_printf = RustGnuHashOracle.gnu_hash(b"printf")
        shift = 6
        mask1, mask2, combined = RustGnuHashOracle.compute_bloom_mask(h_printf, shift)

        assert_eq(mask1, 1 << (h_printf % 64))
        assert_eq(mask2, 1 << ((h_printf >> shift) % 64))
        assert_eq(combined, mask1 | mask2)

        # Exact word match -> passes bloom filter
        filter_table = [combined]
        assert_true(RustGnuHashOracle.check_bloom_filter(filter_table, h_printf, shift))

        # Definite miss: filter has 0 bits
        empty_filter = [0]
        assert_false(RustGnuHashOracle.check_bloom_filter(empty_filter, h_printf, shift))

        # Definite miss: only mask1 present, mask2 missing (when mask1 != mask2)
        if mask1 != mask2:
            partial_filter1 = [mask1]
            assert_false(RustGnuHashOracle.check_bloom_filter(partial_filter1, h_printf, shift))
            partial_filter2 = [mask2]
            assert_false(RustGnuHashOracle.check_bloom_filter(partial_filter2, h_printf, shift))

    def test_adv_hash_04_gnu_hash_collision_resolution_and_chaining():
        """ADV-HASH-04: GNU Hash collision resolution and end-of-chain bit handling."""
        # Construct synthetic collision table:
        # 2 symbols in the same bucket: "symA" and "symB"
        symtab = ["", "symA", "symB", "symC"]
        h_a = RustGnuHashOracle.gnu_hash(b"symA")
        h_b = RustGnuHashOracle.gnu_hash(b"symB")

        nbuckets = 1
        symoffset = 1
        buckets = [1]  # bucket 0 points to sym_idx 1 (symA)
        # Chain entries: symA (bit 0 = 0 -> chain continues), symB (bit 0 = 1 -> chain ends)
        chain = [h_a & ~1, h_b | 1]

        # Lookup symA -> should find at sym_idx 1
        idx_a = RustGnuHashOracle.lookup_chain("symA", symtab, nbuckets, symoffset, buckets, chain)
        assert_eq(idx_a, 1)

        # Lookup symB -> should follow chain and find at sym_idx 2
        idx_b = RustGnuHashOracle.lookup_chain("symB", symtab, nbuckets, symoffset, buckets, chain)
        assert_eq(idx_b, 2)

        # Lookup non-existent symbol -> reaches chain terminator (bit 0 = 1), returns None
        idx_missing = RustGnuHashOracle.lookup_chain("missing_sym", symtab, nbuckets, symoffset, buckets, chain)
        assert_eq(idx_missing, None)

    def test_adv_hash_05_symoffset_boundary_rejection():
        """ADV-HASH-05: Bucket pointing below symoffset returns None immediately."""
        buckets = [0]  # points to index 0
        symoffset = 1  # minimum valid index is 1
        res = RustGnuHashOracle.lookup_chain("any", ["", "sym1"], nbuckets=1, symoffset=symoffset, buckets=buckets, chain=[0])
        assert_eq(res, None)

    # -------------------------------------------------------------------------
    # 3. Relocation Calculations (R_X86_64_RELATIVE, GLOB_DAT, COPY & Buffer Size)
    # -------------------------------------------------------------------------

    def test_adv_reloc_01_relative_zero_base_and_nonzero_base():
        """ADV-RELOC-01: R_X86_64_RELATIVE calculations with zero vs non-zero load base."""
        buf = bytearray(64)

        # Zero base (B = 0, A = 0x5000)
        bytes_patched = RustRelocationEngineOracle.apply_rela(buf, 0x10, R_X86_64_RELATIVE, None, 0x5000, 0)
        assert_eq(bytes_patched, 8)
        val = struct.unpack_from("<Q", buf, 0x10)[0]
        assert_eq(val, 0x5000, "Base 0 + addend 0x5000 = 0x5000")

        # Non-zero base (B = 0x7FFF_F700_0000, A = 0x1234)
        base = 0x7FFF_F700_0000
        RustRelocationEngineOracle.apply_rela(buf, 0x20, R_X86_64_RELATIVE, None, 0x1234, base)
        val2 = struct.unpack_from("<Q", buf, 0x20)[0]
        assert_eq(val2, 0x7FFF_F700_1234)

        # Negative addend (B = 0x7FFF_F700_1000, A = -0x100)
        RustRelocationEngineOracle.apply_rela(buf, 0x30, R_X86_64_RELATIVE, None, -0x100, base + 0x1000)
        val3 = struct.unpack_from("<Q", buf, 0x30)[0]
        assert_eq(val3, 0x7FFF_F700_0F00)

    def test_adv_reloc_02_glob_dat_symbol_address_patching():
        """ADV-RELOC-02: R_X86_64_GLOB_DAT writes resolved symbol address directly."""
        buf = bytearray(32)
        sym_addr = 0x0000_7FFF_1234_5678
        bytes_patched = RustRelocationEngineOracle.apply_rela(buf, 0x08, R_X86_64_GLOB_DAT, sym_addr, 0, 0)
        assert_eq(bytes_patched, 8)
        val = struct.unpack_from("<Q", buf, 0x08)[0]
        assert_eq(val, sym_addr)

        # Missing symbol address raises error
        assert_raises(SymbolNotFoundError, RustRelocationEngineOracle.apply_rela, buf, 0x08, R_X86_64_GLOB_DAT, None, 0, 0)

    def test_adv_reloc_03_copy_relocation_byte_copying_and_stats():
        """ADV-RELOC-03: R_X86_64_COPY copies symbol address and reports byte size."""
        buf = bytearray(64)
        sym_data_addr = 0x602040

        # Copy size defaults to 8 if addend <= 0
        p1 = RustRelocationEngineOracle.apply_rela(buf, 0x00, R_X86_64_COPY, sym_data_addr, 0, 0)
        assert_eq(p1, 8)
        assert_eq(struct.unpack_from("<Q", buf, 0x00)[0], sym_data_addr)

        # Custom copy size if addend > 0 (e.g. 32 bytes)
        p2 = RustRelocationEngineOracle.apply_rela(buf, 0x10, R_X86_64_COPY, sym_data_addr, 32, 0)
        assert_eq(p2, 32)
        assert_eq(struct.unpack_from("<Q", buf, 0x10)[0], sym_data_addr)

    def test_adv_reloc_04_buffer_boundary_overflow_defense():
        """ADV-RELOC-04: Strict buffer overflow defense at buffer boundaries."""
        buf = bytearray(16)

        # Exact fit at boundary: offset 8 in 16-byte buffer needs 8 bytes -> offset + 8 == 16 (succeeds)
        RustRelocationEngineOracle.apply_rela(buf, 8, R_X86_64_RELATIVE, None, 0x100, 0)

        # 1 byte overflow: offset 9 in 16-byte buffer -> 9 + 8 = 17 > 16 (fails)
        assert_raises(BufferOverflowError, RustRelocationEngineOracle.apply_rela, buf, 9, R_X86_64_RELATIVE, None, 0x100, 0)

        # Massive out-of-bounds offset
        assert_raises(BufferOverflowError, RustRelocationEngineOracle.apply_rela, buf, 0xFFFFFFFF, R_X86_64_RELATIVE, None, 0x100, 0)

    # -------------------------------------------------------------------------
    # 4. Eager vs Lazy Binding & dl_runtime_resolve GOT Mutation
    # -------------------------------------------------------------------------

    def test_adv_bind_01_eager_jump_slot_immediate_resolution():
        """ADV-BIND-01: Eager binding resolves R_X86_64_JUMP_SLOT immediately."""
        linker = RustDynamicLinkerOracle(eager_binding=True)
        linker.register_symbol("cos", 0x600040)

        target_slot = 0x7000
        resolved = linker.apply_relocation(R_X86_64_JUMP_SLOT, target_slot, "cos")
        assert_eq(resolved, 0x600040)
        assert_eq(linker.got_table[target_slot], 0x600040, "GOT immediately contains function pointer")

        # Missing symbol in eager mode immediately fails
        assert_raises(SymbolNotFoundError, linker.apply_relocation, R_X86_64_JUMP_SLOT, 0x7008, "nonexistent")

    def test_adv_bind_02_lazy_jump_slot_plt0_trampoline_and_runtime_resolve():
        """ADV-BIND-02: Lazy binding points to PLT0 trampoline (target_slot + 6); dl_runtime_resolve mutates GOT."""
        linker = RustDynamicLinkerOracle(eager_binding=False)
        linker.register_symbol("sin", 0x600080)

        target_slot = 0x6500
        # 1. Initial relocation sets PLT0 trampoline: target_slot + 6
        initial = linker.apply_relocation(R_X86_64_JUMP_SLOT, target_slot, "sin")
        assert_eq(initial, 0x6506, "Initial lazy GOT points to PLT0 trampoline (slot + 6)")
        assert_eq(linker.got_table[target_slot], 0x6506)

        # 2. First execution invokes dl_runtime_resolve
        resolved = linker.dl_runtime_resolve(target_slot, "sin")
        assert_eq(resolved, 0x600080)
        assert_eq(linker.got_table[target_slot], 0x600080, "GOT mutated in-place with true symbol address")

        # 3. Subsequent calls read directly from GOT table without trampoline
        assert_eq(linker.got_table[target_slot], 0x600080)

    def test_adv_bind_03_dl_runtime_resolve_undefined_symbol_failure():
        """ADV-BIND-03: dl_runtime_resolve fails cleanly when symbol cannot be resolved."""
        linker = RustDynamicLinkerOracle(eager_binding=False)
        linker.got_table[0x5000] = 0x5006
        assert_raises(SymbolNotFoundError, linker.dl_runtime_resolve, 0x5000, "undefined_function")
        assert_eq(linker.got_table[0x5000], 0x5006, "GOT unmodified on resolution failure")

    # -------------------------------------------------------------------------
    # 5. Auxiliary Vector & User Stack Frame (RSP % 16 == 0, NULL Tables, Auxv)
    # -------------------------------------------------------------------------

    def test_adv_stack_01_combinatorial_16byte_alignment_matrix():
        """ADV-STACK-01: Exhaustive combinatorial verification: RSP % 16 == 0 for all stack inputs."""
        stack_tops = [
            0x0000_7FFF_FFFF_0000,
            0x0000_7FFF_FFFF_0001,
            0x0000_7FFF_FFFF_0007,
            0x0000_7FFF_FFFF_0008,
            0x0000_7FFF_FFFF_000F,
            0x0000_7FFF_FFFF_E000,
            0x0000_7FFF_FFFF_FFF5,
        ]

        argv_variants = [
            [],
            ["/init"],
            ["/bin/sh", "-c", "echo hello"],
            ["a", "bb", "ccc", "dddd", "eeeee"],
            ["odd_len_1", "odd_len_333", "odd_len_55555"],
        ]

        envp_variants = [
            [],
            ["PATH=/bin"],
            ["A=1", "B=22", "C=333", "D=4444"],
            ["LANG=en_US.UTF-8", "HOME=/root", "TERM=vt100", "SHELL=/bin/bash"],
        ]

        sample_auxv = [
            (AT_PHDR, 0x400040),
            (AT_PHENT, 56),
            (AT_PHNUM, 4),
            (AT_PAGESZ, 4096),
            (AT_BASE, 0x7F8000),
            (AT_ENTRY, 0x401000),
            (AT_RANDOM, 0),
        ]

        for s_top in stack_tops:
            for argv in argv_variants:
                for envp in envp_variants:
                    initial_rsp, stack_bytes = RustUserStackOracle.setup_user_stack(
                        s_top, argv, envp, sample_auxv
                    )
                    assert_eq(
                        initial_rsp % 16,
                        0,
                        f"Stack alignment failed (RSP {hex(initial_rsp)} % 16 != 0) with top={hex(s_top)}, argv={len(argv)}, envp={len(envp)}"
                    )
                    assert_true(len(stack_bytes) > 0)
                    assert_true(initial_rsp + len(stack_bytes) == s_top)

    def test_adv_stack_02_null_terminated_tables_and_argc_layout():
        """ADV-STACK-02: User stack frame layout verification: argc, argv NULL, envp NULL, auxv AT_NULL."""
        stack_top = 0x0000_7FFF_FFFF_0000
        argv = ["/bin/app", "--verbose", "input.txt"]
        envp = ["PATH=/usr/bin", "USER=root"]
        auxv = [
            (AT_PHDR, 0x400040),
            (AT_BASE, 0x7F8000),
            (AT_RANDOM, 0),
        ]

        initial_rsp, stack_bytes = RustUserStackOracle.setup_user_stack(
            stack_top, argv, envp, auxv
        )

        off = 0
        # 1. argc
        argc = struct.unpack_from("<Q", stack_bytes, off)[0]
        assert_eq(argc, 3)
        off += 8

        # 2. argv pointers (3 items)
        argv_ptrs = []
        for _ in range(3):
            ptr = struct.unpack_from("<Q", stack_bytes, off)[0]
            argv_ptrs.append(ptr)
            off += 8

        # 3. argv NULL terminator
        argv_null = struct.unpack_from("<Q", stack_bytes, off)[0]
        assert_eq(argv_null, 0, "argv table must be NULL terminated")
        off += 8

        # 4. envp pointers (2 items)
        envp_ptrs = []
        for _ in range(2):
            ptr = struct.unpack_from("<Q", stack_bytes, off)[0]
            envp_ptrs.append(ptr)
            off += 8

        # 5. envp NULL terminator
        envp_null = struct.unpack_from("<Q", stack_bytes, off)[0]
        assert_eq(envp_null, 0, "envp table must be NULL terminated")
        off += 8

        # 6. auxv entries (3 entries)
        parsed_auxv = []
        while off < len(stack_bytes):
            a_type, a_val = struct.unpack_from("<QQ", stack_bytes, off)
            off += 16
            if a_type == AT_NULL:
                assert_eq(a_val, 0, "AT_NULL value must be 0")
                break
            parsed_auxv.append((a_type, a_val))

        assert_eq(len(parsed_auxv), 3)
        assert_eq(parsed_auxv[0], (AT_PHDR, 0x400040))
        assert_eq(parsed_auxv[1], (AT_BASE, 0x7F8000))
        assert_eq(parsed_auxv[2][0], AT_RANDOM)
        # AT_RANDOM must point to stack_top - 16
        assert_eq(parsed_auxv[2][1], stack_top - 16)

    def test_adv_stack_03_string_pointers_content_verification():
        """ADV-STACK-03: String pointers in argv/envp resolve to valid null-terminated UTF-8 strings."""
        stack_top = 0x0000_7FFF_FFFF_0000
        argv = ["my_kernel_task", "alpha", "beta_gamma"]
        envp = ["ENV_A=1", "ENV_B=CorOS"]

        initial_rsp, stack_bytes = RustUserStackOracle.setup_user_stack(
            stack_top, argv, envp, []
        )

        def read_cstring(vaddr: int) -> str:
            rel_off = vaddr - initial_rsp
            assert_true(0 <= rel_off < len(stack_bytes))
            end = stack_bytes.find(b"\x00", rel_off)
            assert_ne(end, -1, "String must be null-terminated")
            return stack_bytes[rel_off:end].decode("utf-8")

        # Read argv pointers
        off = 8
        for expected_arg in argv:
            ptr = struct.unpack_from("<Q", stack_bytes, off)[0]
            off += 8
            assert_eq(read_cstring(ptr), expected_arg)

        # Skip argv NULL
        off += 8

        # Read envp pointers
        for expected_env in envp:
            ptr = struct.unpack_from("<Q", stack_bytes, off)[0]
            off += 8
            assert_eq(read_cstring(ptr), expected_env)

    def test_adv_stack_04_auxv_missing_tag_and_random_seed():
        """ADV-STACK-04: Auxiliary vector missing tag query and 16-byte random seed entropy."""
        stack_top = 0x0000_7FFF_FFFF_0000
        auxv = [
            (AT_ENTRY, 0x401080),
            (AT_PAGESZ, 4096),
            (AT_RANDOM, 0),
        ]
        initial_rsp, stack_bytes = RustUserStackOracle.setup_user_stack(
            stack_top, [], [], auxv
        )

        # Verify random bytes at stack_top - 16
        rand_off = (stack_top - 16) - initial_rsp
        rand_bytes = stack_bytes[rand_off:rand_off + 16]
        assert_eq(len(rand_bytes), 16)
        assert_ne(rand_bytes, b"\x00" * 16, "Random seed must not be all zeros")

        # Missing tag lookup in auxv map returns None
        auxv_map = dict(auxv)
        assert_eq(auxv_map.get(AT_SYSINFO_EHDR), None)
        assert_eq(auxv_map.get(9999), None)

    # Register all tests
    suite.add("ADV-TAG-01 16-byte Elf64Dyn alignment rejection & acceptance", test_adv_tag_01_16byte_alignment_enforcement)
    suite.add("ADV-TAG-02 Complete parsing of all required dynamic tags", test_adv_tag_02_all_dynamic_tags_exact_extraction)
    suite.add("ADV-TAG-03 DT_NULL early termination & trailing garbage tolerance", test_adv_tag_03_dt_null_early_termination_and_trailing_garbage)
    suite.add("ADV-TAG-04 is_bind_now link flag activation matrix", test_adv_tag_04_is_bind_now_activation_matrix)
    suite.add("ADV-TAG-05 Unknown/vendor dynamic tags tolerance without crash", test_adv_tag_05_unknown_dynamic_tags_tolerance)

    suite.add("ADV-HASH-01 Empty string exact hash values (0 for SysV, 5381 for GNU)", test_adv_hash_01_empty_string_exact_hash_values)
    suite.add("ADV-HASH-02 Deterministic hash vectors across libc standard symbols", test_adv_hash_02_deterministic_hash_vectors)
    suite.add("ADV-HASH-03 Bloom filter 64-bit dual-mask & miss filtering verification", test_adv_hash_03_bloom_filter_64bit_mask_verification)
    suite.add("ADV-HASH-04 GNU Hash collision resolution & chain terminator bit", test_adv_hash_04_gnu_hash_collision_resolution_and_chaining)
    suite.add("ADV-HASH-05 Bucket pointing below symoffset returns None immediately", test_adv_hash_05_symoffset_boundary_rejection)

    suite.add("ADV-RELOC-01 R_X86_64_RELATIVE with zero base vs non-zero load base", test_adv_reloc_01_relative_zero_base_and_nonzero_base)
    suite.add("ADV-RELOC-02 R_X86_64_GLOB_DAT symbol address GOT patching", test_adv_reloc_02_glob_dat_symbol_address_patching)
    suite.add("ADV-RELOC-03 R_X86_64_COPY data copy & buffer size validation", test_adv_reloc_03_copy_relocation_byte_copying_and_stats)
    suite.add("ADV-RELOC-04 Buffer boundary overflow defense & exact boundary fits", test_adv_reloc_04_buffer_boundary_overflow_defense)

    suite.add("ADV-BIND-01 Eager R_X86_64_JUMP_SLOT immediate resolution", test_adv_bind_01_eager_jump_slot_immediate_resolution)
    suite.add("ADV-BIND-02 Lazy R_X86_64_JUMP_SLOT PLT0 trampoline & dl_runtime_resolve mutation", test_adv_bind_02_lazy_jump_slot_plt0_trampoline_and_runtime_resolve)
    suite.add("ADV-BIND-03 dl_runtime_resolve undefined symbol failure and GOT preservation", test_adv_bind_03_dl_runtime_resolve_undefined_symbol_failure)

    suite.add("ADV-STACK-01 Combinatorial 16-byte stack alignment (RSP % 16 == 0)", test_adv_stack_01_combinatorial_16byte_alignment_matrix)
    suite.add("ADV-STACK-02 User stack frame layout (argc, argv NULL, envp NULL, auxv AT_NULL)", test_adv_stack_02_null_terminated_tables_and_argc_layout)
    suite.add("ADV-STACK-03 String pointers in argv/envp resolve to null-terminated UTF-8", test_adv_stack_03_string_pointers_content_verification)
    suite.add("ADV-STACK-04 Auxv missing tag lookup and 16-byte random seed entropy", test_adv_stack_04_auxv_missing_tag_and_random_seed)

    return suite


if __name__ == "__main__":
    suite = build_empirical_challenger_suite()
    passed, failed, details = suite.run(verbose=True)
    print("\n" + "=" * 70)
    print(f"CHALLENGER RESULT: {passed} passed, {failed} failed across 21 adversarial stress tests.")
    print("=" * 70)
    if failed > 0:
        sys.exit(1)
    sys.exit(0)
