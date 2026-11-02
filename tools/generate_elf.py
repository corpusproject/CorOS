import os
import struct

def build_elf64_binary(output_path, message_str):
    """
    Constructs a 100% valid, standalone 64-bit ELF executable for x86_64.
    Zero external libraries, statically executable in Ring 3 User Space.
    Payload:
      1. SYS_WRITE (rax=2, rdi=msg_ptr, rsi=msg_len, syscall)
      2. SYS_GETPID (rax=22, syscall)
      3. SYS_EXIT (rax=60, rdi=0, syscall)
    """
    msg_bytes = message_str.encode('utf-8')
    msg_len = len(msg_bytes)
    
    # Virtual load base address
    vaddr_base = 0x00400000
    entry_offset = 0x78 # 64 bytes ELF Header + 56 bytes Program Header = 120 (0x78)
    entry_point = vaddr_base + entry_offset

    # x86_64 Machine Code instructions:
    # ---------------------------------
    # mov rax, 2 (SYS_WRITE)       -> 48 c7 c0 02 00 00 00
    # lea rdi, [rip + msg_disp]    -> 48 8d 3d xx xx xx xx
    # mov rsi, msg_len             -> 48 c7 c6 <len:4>
    # syscall                      -> 0f 05
    # mov rax, 22 (SYS_GETPID)     -> 48 c7 c0 16 00 00 00
    # syscall                      -> 0f 05
    # mov rax, 60 (SYS_EXIT)       -> 48 c7 c0 3c 00 00 00
    # xor rdi, rdi                 -> 48 31 ff
    # syscall                      -> 0f 05
    # ret                          -> c3
    code = bytearray()
    
    # mov rax, 2
    code += b"\x48\xc7\xc0\x02\x00\x00\x00"
    
    # lea rdi, [rip + disp]
    # We will patch disp after knowing code length
    lea_rip_offset = len(code) + 7
    code += b"\x48\x8d\x3d\x00\x00\x00\x00"
    
    # mov rsi, msg_len
    code += b"\x48\xc7\xc6" + struct.pack("<I", msg_len)
    
    # syscall
    code += b"\x0f\x05"
    
    # mov rax, 22 (SYS_GETPID)
    code += b"\x48\xc7\xc0\x16\x00\x00\x00"
    code += b"\x0f\x05"
    
    # mov rax, 60 (SYS_EXIT)
    code += b"\x48\xc7\xc0\x3c\x00\x00\x00"
    # xor rdi, rdi
    code += b"\x48\x31\xff"
    # syscall
    code += b"\x0f\x05"
    # ret
    code += b"\xc3"
    
    # Now patch the displacement to message
    msg_offset_in_code = len(code)
    disp = msg_offset_in_code - lea_rip_offset
    struct.pack_into("<i", code, 10, disp)
    
    # Append message string
    payload = bytes(code) + msg_bytes
    
    file_size = entry_offset + len(payload)
    
    # 1. ELF Header (64 bytes)
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2       # 64-bit
    ehdr[5] = 1       # Little-endian
    ehdr[6] = 1       # Current ELF version
    ehdr[7] = 0       # System V ABI
    ehdr[8] = 0       # ABI version
    # bytes 9..15 padding
    struct.pack_into("<H", ehdr, 16, 2)            # e_type: ET_EXEC
    struct.pack_into("<H", ehdr, 18, 62)           # e_machine: x86_64
    struct.pack_into("<I", ehdr, 20, 1)            # e_version: 1
    struct.pack_into("<Q", ehdr, 24, entry_point)  # e_entry
    struct.pack_into("<Q", ehdr, 32, 64)           # e_phoff: 64
    struct.pack_into("<Q", ehdr, 40, 0)            # e_shoff: 0
    struct.pack_into("<I", ehdr, 48, 0)            # e_flags
    struct.pack_into("<H", ehdr, 52, 64)           # e_ehsize: 64
    struct.pack_into("<H", ehdr, 54, 56)           # e_phentsize: 56
    struct.pack_into("<H", ehdr, 56, 1)            # e_phnum: 1
    struct.pack_into("<H", ehdr, 58, 0)            # e_shentsize
    struct.pack_into("<H", ehdr, 60, 0)            # e_shnum
    struct.pack_into("<H", ehdr, 62, 0)            # e_shstrndx
    
    # 2. Program Header (56 bytes)
    phdr = bytearray(56)
    struct.pack_into("<I", phdr, 0, 1)             # p_type: PT_LOAD
    struct.pack_into("<I", phdr, 4, 7)             # p_flags: PF_R | PF_W | PF_X
    struct.pack_into("<Q", phdr, 8, entry_offset)  # p_offset
    struct.pack_into("<Q", phdr, 16, entry_point)  # p_vaddr
    struct.pack_into("<Q", phdr, 24, entry_point)  # p_paddr
    struct.pack_into("<Q", phdr, 32, len(payload)) # p_filesz
    struct.pack_into("<Q", phdr, 40, len(payload)) # p_memsz
    struct.pack_into("<Q", phdr, 48, 0x1000)       # p_align: 4KB
    
    elf_file = bytes(ehdr) + bytes(phdr) + payload
    
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(elf_file)
    print(f"Generated ELF64 binary: {output_path} ({len(elf_file)} bytes, Entry: 0x{entry_point:X})")

if __name__ == '__main__':
    hesap_msg = "[HESAP.ELF] Ring 3 User-Space Matris ve Bilimsel Hesaplayici Aktif! (DPL 3)\r\n"
    app_msg = "[APP.ELF] Merhaba Dunya! CorOS x86_64 Bagimsiz ELF64 Programi Calisiyor!\r\n"
    
    build_elf64_binary("dist/esp/EFI/COROS/HESAP.ELF", hesap_msg)
    build_elf64_binary("dist/esp/EFI/COROS/APP.ELF", app_msg)
