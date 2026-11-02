# CorOS memory ownership and handoff (Milestone 1.5)

This is a source audit. No compiler, test, firmware, or emulator verification was run. Status labels are deliberately distinct: **IMPLEMENTED** means the source path exists; **IMPLEMENTED BUT UNVERIFIED** means it has not been compiled or exercised; **NOT IMPLEMENTED** means no active path exists; **BLOCKED ON RUNTIME VERIFICATION** means hardware/firmware evidence is needed before activation.

## Boot-time ownership inventory

The ranges below are derived from CorBoot/CorKernel source and UEFI descriptor policy. No physical address or size is inferred beyond what BootInfo or source constants provide.

| Range or object | Source evidence and lifetime | Allocator treatment / gap |
| --- | --- | --- |
| CorBoot image, including static `BOOT_INFO` | Loaded Image `ImageBase` is a protocol pointer value; the code/data memory types are checked as EFI LoaderCode/LoaderData | ImageBase is not interpreted as physical. Every LoaderCode/LoaderData descriptor is excluded; exact physical image range is not cross-matched. BootInfo lives in the image's data. |
| CorKernel image and sections | Loaded Image `ImageBase` pointer and `ImageSize`; image code/data types checked as LoaderCode/LoaderData. Linker section bounds are not handed off. | No physical reservation is derived from the pointer. All LoaderCode/LoaderData descriptors are excluded. Fine-grained section/W^X bounds are **NOT IMPLEMENTED** |
| Bootstrap stack | 64 KiB BSS array in CorKernel image, selected by assembly entry before Rust | Covered by whole kernel image reservation; exact runtime RSP not recorded |
| Double-fault stack, GDT, TSS, IDT | Static kernel objects in CorKernel image; IDT has 256 entries | Covered by whole kernel image reservation; no separate fields required while image remains resident |
| BootInfo | Static CorBoot object; pointer passed to CorKernel, read-only for kernel lifetime | Covered by CorBoot image reservation; **IMPLEMENTED BUT UNVERIFIED** |
| UEFI memory-map buffer | `AllocatePool(EFI_LOADER_DATA)`; final pointer/size/descriptor stride in BootInfo | Loader descriptor is classified non-usable and never reclaimed. There is no separate explicit range field; exact ownership relies on the final UEFI map |
| Current CR3 root | Read from CR3 and root frame reserved during allocator initialization | Root explicitly excluded. **IMPLEMENTED BUT UNVERIFIED** |
| Active page-table descendants | CR3 root is known, but no proven physical-table access exists and descendants are not enumerated | Ownership/reservations unknown. This is a blocking gap for a new CR3 |
| Newly allocated inactive page tables | Mapper owns frames in its supplied `owned` list | Allocator marks them allocated; mapper can release them only under its inactive-root safety contract. No active mapper is installed |
| Frame allocator bitmaps | Static arrays in CorKernel image | Covered by whole kernel image reservation |
| Framebuffer | GOP physical base/size in BootInfo when validated | Explicitly reserved; kernel does not dereference it until a verified virtual mapping exists |
| ACPI RSDP and tables | RSDP is an EFI configuration-table pointer value in BootInfo; other table extents are not parsed by this milestone | Pointer is not converted to a physical reservation. ACPI reclaimable/NVS descriptors remain non-usable. No ACPI table is reclaimed |
| Firmware runtime memory | `EFI_MEMORY_RUNTIME` attribute overrides nominal type | Always classified reserved |
| MMIO / port-space descriptors | UEFI memory types | Classified non-usable; no persistent mapping/allocator path |
| Other boot data | `EFI_LOADER_*` and `EFI_BOOT_SERVICES_*` descriptors | Kept non-usable; no reclaim based only on descriptor class |

## UEFI descriptor audit

`MemoryMap` uses the firmware descriptor stride, rejects strides smaller than the known prefix or above 4096 bytes, requires exact buffer divisibility, and reads the prefix unaligned. BootInfo validation bounds the byte length and checks pointer-plus-length overflow. Each descriptor requires page-aligned start, nonzero page count, checked `pages * 4096`, and checked end address. Runtime-attributed descriptors are reserved regardless of memory type. Conventional memory alone becomes usable; loader/boot-services, ACPI reclaimable, ACPI NVS, bad, MMIO, port-space, and unknown types remain unavailable. No reclaim operation exists.

The allocator first admits usable descriptors, then reapplies every non-usable descriptor so overlap cannot make a reserved frame available. EFI image pointer fields and ACPI pointer fields are not fed to physical reservation arithmetic. GOP's physical framebuffer range and the physical active CR3 root are explicitly reserved. Explicit reservations round outward to every intersecting 4 KiB frame; if a reservation overflows, the remaining tracked range is conservatively reserved. Physical-address width is required from CPUID and must be 32–52 bits; unavailable/invalid width fails allocator initialization. Frame/page index conversions return `None` on multiplication overflow. Free rejects untracked and already-free frames; reserved frames have their managed bit cleared. Production `FrameAllocator` instances are created with allocation disabled, and the global API is independently fail-closed. Only the `cfg(test)` constructor enables the bitmap logic for deterministic source tests. These checks are **IMPLEMENTED BUT UNVERIFIED**.

Limitation: overlapping usable descriptors may be visited more than once but only set bits; malformed overlapping descriptors that are individually arithmetically valid are handled by non-usable precedence. Descriptor ranges are arithmetically checked, while frames above detected physical-width/bitmap capacity are clipped out of the managed set rather than reported as a malformed-map error. Descriptor ordering and UEFI map integrity still require actual firmware observation. Bitmap storage covers 4 GiB in the current static boot path; larger caller-provided arrays can describe higher frames, but no such larger storage is supplied.

## Page-table inspection and physical access

The source can capture CR0.PG, CR4.PAE/LA57/PKE, EFER.LMA/NXE, CPUID physical-address width, and 1 GiB-page support. The snapshot classifies four-level, five-level, or unknown mode; missing physical width remains `None`. No handoff-time snapshot is stored, and firmware state has not been observed. The builder uses four 512-entry levels and 64-bit entries. The read-only path inspector requires a supplied four-level snapshot, rejects unknown width/mode, NX without NXE, protection-key bits without PKE/leaf status, out-of-width table addresses, invalid large-page levels/alignment, and unsupported 1 GiB pages. It stops at non-present entries and does not dereference those addresses.

`inspect_path` is bounded to four entries for one canonical virtual address. Its unsafe API requires an explicitly supplied `PageTableReadAccess` provider whose contract promises validated, stable readable RAM frames; no physical-identity provider is supplied. A missing/unvalidated frame returns `AccessUnavailable`. It checks modeled reserved cases: page-size bit at invalid levels, large-page alignment, address bits above the reported width, NX without NXE, and protection-key bits without PKE/leaf semantics. Feature-dependent entry bits not represented in `PagingSnapshot` remain a limitation. **No implementation is established for firmware physical addresses.** Therefore it is not called against live CR3 and does not claim the current tree has been enumerated. Whole-tree traversal is not implemented.

Writable mapper access remains isolated behind a separate unsafe `PageTableAccess` contract. No concrete provider is supplied; the former identity-map adapter was removed so physical frame numbers cannot be cast directly into virtual pointers. Do not construct/activate CorOS page tables until a validated access provider exists.

## Future CR3 transition protocol (not implemented)

The source gate remains **BLOCKED** until each prerequisite is supported by evidence:

| Prerequisite | Current state |
| --- | --- |
| Four-/five-level mode and CR0.PG/CR4.PAE/LA57/EFER.LMA/NXE/PKE snapshot | Read-only snapshot code exists; no real boot capture or validation |
| Physical-address width and supported page sizes | CPUID parsing exists; unknown width fails closed; real CPU state unobserved |
| Validated access to root and every active child table | **MISSING**; no live physical reader/provider |
| Complete bounded enumeration and ownership of active table frames | **MISSING**; tree has not been walked |
| Physical extents and inherited virtual mappings for image, BootInfo, map, stack, GDT/TSS/IDT/IST, diagnostics | **MISSING**; only pointers/descriptors and source static bounds are known |
| Required framebuffer/MMIO mappings and cache attributes | Framebuffer output disabled; MMIO routing/mappings not established |
| New-root translation/permission validation for all transition code/data | **MISSING** |
| Real transition and recovery test | **MISSING**; no CR3 write API exists |

The code-level gate is closed and has a source test; it is not inferred open from these interfaces existing.

1. Capture/validate the current CR3, physical width, paging mode, and required control-register state; establish a safe read-only provider and enumerate the live tree with a strict page/entry budget.
2. Build an owned root and record every table frame. Preserve all live mappings needed by transition code: CorKernel code/data, current stack, double-fault stack, GDT/TSS/IDT, BootInfo, memory-map bytes, page tables, diagnostics, and any used framebuffer/MMIO. Preserve permissions and cache attributes where required.
3. Reserve all source-derived ranges and every page-table frame; ensure no new table aliases firmware-owned memory. Validate translations for every required code/data/stack/descriptor/diagnostic range, physical-width limits, canonicality, alignment, permissions, and absence of unintended large-page traversal.
4. Enter a minimal assembly transition with interrupts disabled, switch CR3, and immediately touch only mappings proven present in the new root. Verify execution through CorOS-owned serial diagnostics before enabling any interrupts.

Rollback is not generally safe after switching CR3: the old root might be inaccessible, firmware mappings may be lost, or the transition stack/instructions may not be mapped. A source-level preflight cannot prove successful execution. The CPU module contains no CR3 write API, and the architecture gate reports closed; no transition is implemented or attempted. **CR3 Transition Readiness: FAIL.**

## Heap gate

| State | Status |
| --- | --- |
| Allocator implementation | **IMPLEMENTED BUT UNVERIFIED** (`KernelHeap`) |
| Page provider implementation | **NOT IMPLEMENTED** for live CorOS mappings |
| Provider validation | **NOT IMPLEMENTED** |
| Heap initialized | **NOT IMPLEMENTED** |
| Global allocator registered | **NOT IMPLEMENTED** |

The heap remains unavailable. A future provider must supply exclusively owned frames and a verified virtual range in the active address space; no unsafe global allocator is registered.

## Source-level tests

Tests are written but **UNRUN**. Existing/new pure-logic coverage includes descriptor stride/arithmetic and ABI validation, classification including runtime attributes, overlap precedence, explicit unaligned reservations, reservation overflow, frame allocation/free state, address alignment, page-table entry classification/large-page detection, and mapper behavior using mock backing. BootInfo version/signature/flags/range tests are present. Test existence is not evidence of compilation or correctness.
