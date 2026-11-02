# CorOS boot design and current implementation

All steps below are implemented in source and remain UNVERIFIED by compilation or firmware execution.

1. UEFI firmware starts CorBoot through its x86_64 UEFI `efi_main` entry. **IMPLEMENTED / UNVERIFIED**
2. CorBoot discovers its loaded-image protocol and boot volume. **IMPLEMENTED / UNVERIFIED**
3. CorBoot asks UEFI `LoadImage` to load `\\EFI\\COROS\\CORKERNEL.EFI`; UEFI loads and relocates it. **IMPLEMENTED / UNVERIFIED**
4. CorBoot collects BootInfo, optional ACPI/GOP data, and loaded-image ranges. **IMPLEMENTED / UNVERIFIED**
5. CorBoot probes map size, allocates LoaderData with descriptor slack, and resizes if the map grows. **IMPLEMENTED / UNVERIFIED**
6. CorBoot gets a fresh final map key and calls `ExitBootServices`; stale keys receive bounded retries. **IMPLEMENTED / UNVERIFIED**
7. CorBoot calls the loaded kernel entry using `efiapi`, without calling firmware after successful exit. **IMPLEMENTED / UNVERIFIED**
8. CorKernel validates BootInfo. **IMPLEMENTED / UNVERIFIED**
9. The kernel assembly entry disables interrupts, switches to a private 64 KiB stack, then CorKernel loads its GDT/TSS and IDT. **IMPLEMENTED / UNVERIFIED**
10. CorKernel parses the conventional-memory map into a bitmap, but keeps live frame allocation disabled because firmware page-table descendants are unknown; diagnostics use COM1 and framebuffer writes remain off. It detects TSC/APIC capabilities without enabling interrupt routing. **IMPLEMENTED BUT UNVERIFIED**
11. CorKernel halts with interrupts disabled. **IMPLEMENTED / UNVERIFIED**

## BootInfo field contract

BootInfo is 152 bytes, 8-byte aligned, `repr(C)`, version 1. Its layout is unchanged. All integer widths below are exact ABI widths; all lengths are bytes unless stated.

| Field(s) | Representation and units | Meaning, owner, and post-exit access |
| --- | --- | --- |
| `magic` | `u64` signature | Validated scalar in the static CorBoot BootInfo object. |
| `version` | `u32` ABI version | Must equal version 1. |
| `size` | `u32`, bytes | Struct size; must be at least the v1 size. |
| `architecture` | `u32` code | Must identify x86_64. |
| `flags` | `u32` bitmask | Indicates optional ACPI/framebuffer metadata; not an address. |
| `bootloader_version` | `u32` version | CorBoot version scalar. |
| `_reserved0` | `u32` reserved | Must be zero in v1. |
| `bootloader_image_address` | `u64` containing EFI Loaded Image `ImageBase` pointer value | It is not proven to be a physical address. The image is an EFI application with LoaderCode/LoaderData types, checked by CorBoot; the final descriptor map keeps those types out of usable RAM. |
| `bootloader_image_size` | `u64`, bytes | Loaded Image `ImageSize`; paired with the opaque pointer value above. Not used as a physical reservation. |
| `memory_map_address` | `u64` containing the pointer returned by `AllocatePool` | CorBoot-owned LoaderData buffer, retained after exit and read by CorKernel through the inherited address space. Pointer validity after handoff is source-required but runtime-unverified. |
| `memory_map_size` | `u64`, bytes | Final `GetMemoryMap` byte count. |
| `memory_descriptor_size` | `u64`, bytes per descriptor/stride | Used to step the final map, including descriptor extensions. |
| `memory_descriptor_version` | `u32` version | Parser accepts only descriptor version 1. |
| `firmware_revision` | `u32` revision | Scalar copied from the EFI system-table header. |
| `acpi_rsdp_address` | `u64` containing the EFI configuration-table `VendorTable` pointer value | Opaque table pointer; kernel does not dereference it in this milestone, and the allocator does not treat it as physical. ACPI descriptor types remain unavailable. |
| `framebuffer_address` | `u64` physical address | GOP `FrameBufferBase`; explicitly reserved by the allocator. Kernel framebuffer writes are disabled, so no inherited virtual mapping is assumed. |
| `framebuffer_size` | `u64`, bytes | GOP framebuffer byte extent; checked for overflow and minimum pixel storage. |
| `framebuffer_width`, `framebuffer_height` | `u32`, pixels | GOP dimensions. |
| `framebuffer_stride` | `u32`, pixels per scan line | GOP `PixelsPerScanLine`, not bytes. |
| `framebuffer_format` | `u32` enum | GOP pixel format code. |
| `red_mask`, `green_mask`, `blue_mask`, `reserved_mask` | four `u32` bitmasks | Used only for bitmask pixel format; validated for contiguous, non-overlapping masks. |
| `kernel_image_address` | `u64` containing EFI Loaded Image `ImageBase` pointer value | CorBoot uses the pointer to inspect the already-loaded PE image and call its entry in the inherited EFI address space. It is not proven to be a physical address and is not used as a physical reservation. |
| `kernel_image_size` | `u64`, bytes | Loaded Image `ImageSize`; bounds CorBoot's PE inspection. |

CorBoot's BootInfo object is static data inside the CorBoot image; CorKernel reads it through the entry argument and does not free it. The kernel image entry and BootInfo pointer are usable only as inherited EFI pointers; no CR3 change occurs. The memory-map pointer is a pool pointer, not a physical frame number. The final UEFI memory map is the allocator's range authority: UEFI application code/data use LoaderCode/LoaderData memory types, which CorOS never promotes to usable RAM. CorBoot checks both images' `ImageCodeType` and `ImageDataType` before proceeding. This follows the [UEFI Loaded Image protocol](https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html) and [UEFI image memory-type table](https://uefi.org/specs/UEFI/2.10/02_Overview.html); actual firmware map contents and inherited mapping remain runtime-unverified.

UEFI's Loaded Image protocol does not expose an entry-point member. CorBoot therefore reads bounded PE32+ headers from the image already loaded and relocated by UEFI to find the entry RVA, requiring AMD64, EFI application subsystem, and an executable section. CorBoot does not load or relocate PE images itself.

## Failure behavior

Before ExitBootServices, CorBoot reports required boot failures using firmware text output. ACPI and framebuffer are optional. CorBoot retries a stale map key with a fresh map, up to a bounded number of attempts; after other exit failures it avoids further firmware calls and halts. CorKernel probes the COM1 scratch register before configuring the UART; if the probe fails, serial output remains disabled. This check is source-level only and does not establish that hardware or VM routing is present. Panic/exception diagnostics are allocation-free and do not use firmware or framebuffer services. The kernel halts without recovery. Framebuffer writes remain disabled because no mapped alias is established.

## Limits and staging

The custom PE entry handoff, dynamic map sizing, and all firmware interactions remain uncompiled and unverified. CorBoot collects framebuffer metadata through GOP before exit; the kernel never calls GOP. CorKernel installs a GDT/TSS/IDT, parses a bounded conventional-memory bitmap with allocation disabled, and retains UEFI paging. The active CR3 root is reserved, but descendant page-table frames are not enumerated because no safe physical-table access provider has been established. The CR3 transition is **NOT IMPLEMENTED** and **BLOCKED ON RUNTIME VERIFICATION**.

## Memory handoff limits

The kernel and CorBoot image bounds come from UEFI Loaded Image information. The private bootstrap stack, double-fault stack, GDT/TSS/IDT, and allocator bitmap storage are static CorKernel data and therefore lie within the reserved kernel image. BootInfo lies within the reserved CorBoot image. The map buffer has no dedicated BootInfo reservation field; it remains a LoaderData descriptor and is never reclaimed. ACPI table extents beyond the RSDP are not parsed; ACPI reclaimable/NVS descriptors remain unavailable. Current firmware page-table descendants, runtime state, and exact active stack pointer are not enumerated. See [MEMORY.md](MEMORY.md) for the consolidated inventory and proposed read-only inspection contract.

After successful exit, CorKernel still relies on its image, its private stack and static descriptors, BootInfo, the final map buffer, and the firmware address space that maps those objects. CorBoot does not call firmware again; its entry stack and temporary protocol pointers are abandoned. ACPI and framebuffer are metadata/referenced physical ranges only; framebuffer access is disabled. The exact firmware mappings and runtime-owned structures are not established without a real boot.

`tools/build.ps1 -StageEfiFiles` stages the UEFI removable-media fallback at `dist/esp/EFI/BOOT/BOOTX64.EFI` (CorBoot) and the kernel at `dist/esp/EFI/COROS/CORKERNEL.EFI`. This is not a disk image. The project has no Linux, browser, or simulated boot dependency.

The Windows PowerShell prerequisites, existing Cargo aliases, build output
paths, test scope, failure handling, and staging workflow are documented in
[`docs/TOOLCHAIN.md`](TOOLCHAIN.md). Compilation and firmware behavior remain
unverified; staging does not demonstrate a bootable medium.

The sequencing follows the official [UEFI Boot Services specification](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html). `cargo build-milestone0`, `cargo test-boot-info`, and `cargo test-kernel-foundation` are configured but have not been executed.


