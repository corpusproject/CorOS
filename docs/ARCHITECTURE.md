# CorOS architecture status

This document reflects source only. All boot code is uncompiled and unverified.

## Current source architecture

```text
UEFI firmware -> CorBoot -> UEFI LoadImage(CORKERNEL.EFI)
  -> collect BootInfo/GOP/ACPI -> dynamically size final memory map
  -> ExitBootServices -> direct CorKernel entry with BootInfo
  -> validate -> own 64 KiB stack -> native diagnostics -> halt
```

No Linux, browser, or simulated boot is part of the build. Cargo targets `x86_64-unknown-uefi` and uses the UEFI `efiapi` ABI.

## Components

| Component | Status | Scope |
| --- | --- | --- |
| CorBoot | Partial, unverified | UEFI entry, file loading, optional GOP/ACPI, dynamic map storage, exit/retry, direct entry |
| BootInfo | Implemented in source, unverified | Version 1, 152-byte `repr(C)`, 8-byte alignment, validated fixed-width ABI |
| CorKernel | Implemented in source, unverified | entry trampoline, validation, early diagnostics, halt |
| Memory foundation | Partial, unverified | 64-bit regions, configurable-capacity bitmap with live allocation fail-closed, bounded read-only page-walk interface without a proven provider, inactive page-table builder, MMIO types, provider-based heap; no safe CR3 activation or wired heap provider |
| x86_64 layer | Partial, unverified | CPU accessors, GDT/TSS/IDT, split exception/IRQ dispatch, static IRQ registry, masked PIC; firmware paging retained |
| Diagnostics/time/APIC | Partial, unverified | COM1 logger, raw TSC, opt-in PIT ticks, APIC discovery and mapped-MMIO wrapper; no active APIC/IOAPIC routing |
| Later OS subsystems | Not implemented | No scheduler, processes, VFS, drivers, networking, graphics system, or UI |

## Handoff ABI and ownership

BootInfo is 152 bytes, aligned to 8, version 1, and explicitly `repr(C)`. Its fields are ordered as magic; version/size/architecture/flags/bootloader version/reserved; CorBoot image range; map address/size/descriptor size; descriptor version/firmware revision; ACPI address; framebuffer base/size/dimensions/stride/format/masks; kernel image range. Addresses use `u64`; there are no references, slices, trait objects, or Rust containers. Reserved fields must be zero for version 1. CorBoot owns its static structure and LoaderData map allocation; CorKernel borrows both for its lifetime and does not free them. BootInfo ABI remains unchanged in Milestone 1.5.

The loaded-image protocol does not provide an entry pointer. UEFI `LoadImage` performs image loading and relocation; CorBoot only bounds-checks the loaded PE32+ headers, AMD64 machine, EFI application subsystem, and executable entry section to locate the function for its direct post-exit call. It passes `const BootInfo*` in argument 1 and null in argument 2 using `efiapi`; the entry must not return. This custom ABI is not yet compiler- or firmware-verified.

## CPU and interrupt state

The assembly entry retains the incoming BootInfo argument, disables maskable interrupts, sets RSP to the top of a 64 KiB BSS stack aligned down to 16 bytes, reserves 32 bytes of x64 shadow space, clears RBP, and calls Rust. UEFI target compilation explicitly disables the red zone. CorKernel installs a flat ring-0 GDT, a TSS with double-fault IST1, and distinct normalized stubs for all 256 IDT vectors. Interrupt entry saves GPR and FXSAVE x87/SSE state, not AVX/extended state; unsaved state is prohibited in interrupt-reachable code. It retains firmware paging/CR3; the new page-table builder is not activated. The current boot does not enable maskable interrupts. These assembly and ABI paths remain uncompiled and unverified.

Interrupt routing is source-owned: CPU exceptions take the fatal path without
EOI; only explicitly registered PIC vectors can reach PIC handlers; PIC
spurious IRQ7/IRQ15 are filtered before handler execution; unknown vectors halt
without guessed EOI. Local APIC timer/error and IOAPIC routes would require a
Local APIC EOI, but registration and live APIC dispatch are not implemented.
The PIC unmask API refuses a line without a registered PIC handler. No
additional route is enabled by boot code.

## Memory and framebuffer

Raw UEFI descriptors are classified separately from CorOS memory regions, including runtime attributes. Descriptor version 1, stride, alignment, and range arithmetic are checked. Bitmap capacity is configurable and uses 64-bit physical addresses; current static storage still covers 4 GiB. Frame/page index conversions reject multiplication overflow. Loader/ACPI ranges are never reclaimed. ImageBase and ACPI config-table values remain opaque EFI pointers; only GOP framebuffer and the current CR3 root are passed as explicit physical reservations. The production allocator instance and global frame API stay fail-closed. A bounded page-walk parser requires a paging snapshot and explicit unsafe read-provider; no live firmware provider is established. The CPU module exposes no CR3 write API. The provider-based heap is not connected to an active mapper, and no global heap allocator exists. Framebuffer physical writes are disabled until a verified virtual alias is supplied. PIT IRQ/APIC MMIO interfaces exist but are not started/routed by boot code.

The memory ownership inventory, descriptor arithmetic/classification policy, bounded read-only page-walk design, and future CR3 protocol are documented in [MEMORY.md](MEMORY.md). The current source can snapshot CR0.PG, CR4.PAE/LA57/PKE, EFER.LMA/NXE, physical width, and 1 GiB-page support, but has not used this snapshot to inspect live tables. No physical-table reader is established; global frame allocation/free remains fail-closed. The CR3 write API is absent and the gate is closed. **CR3 Transition Readiness: FAIL.**

## Build and image boundary

`cargo build-milestone0` builds both UEFI executables. `cargo test-boot-info` and `cargo test-kernel-foundation` are configured for the Windows host target. None has been run. `tools/build.ps1 -StageEfiFiles` places CorBoot at `EFI/BOOT/BOOTX64.EFI` and CorKernel at `EFI/COROS/CORKERNEL.EFI`; this is a staged directory, not a disk image.

## Kernel subsystem boundaries (proposed contracts)

These boundaries describe dependencies for future implementation; they do
not claim the later subsystems exist.

| Boundary | Owns | May depend on | Must not assume |
| --- | --- | --- | --- |
| x86_64 CPU/ABI | Privileged instructions, register/control-state access, entry/exit assembly, GDT/TSS/IDT mechanics | Typed requests from kernel subsystems | That firmware paging, SIMD state, APIC mode, or UEFI ABI behavior has been runtime-verified |
| Memory | Address/frame/page types, descriptor policy, reservation ownership, page-table interfaces, heap providers | CPU paging observations and explicit mapping providers | That EFI pointers are physical, that firmware table frames are safely readable, or that allocation gates may open |
| Synchronization | Atomics, spinlocks, IRQ-save guard | CPU local interrupt controls | Fairness, sleeping, preemption, or SMP readiness |
| Interrupts/timers | Entry-frame decoding, vector ownership, source-specific routing/EOI, monotonic event sources | CPU entry ABI, IDT, registered bounded handlers | That PIC and APIC routing can be mixed or that a timer is calibrated |
| Scheduler (future) | Runnable tasks, run queues, saved task context, scheduling policy | Verified CPU context switch, memory mappings, timer/IPI source, synchronization | That an interrupt handler may schedule before context and stack contracts are defined |
| Syscalls (future) | User entry/exit ABI, privilege transition, argument validation and dispatch | Scheduler/process state, CPU entry mechanism, memory isolation | That current ring-0-only IDT/GDT supports user execution |
| Drivers (future) | Device state, I/O protocol, resource lifecycle | Memory-mapped/port-I/O capabilities and interrupt routing | That physical MMIO is directly dereferenceable or device interrupts are routed |
| Diagnostics | Bounded early output, panic reporting, counters/trace interfaces | Only initialized serial or explicitly mapped output | Heap, scheduler, interrupts, firmware calls after ExitBootServices, or valid BootInfo unless checked |

Dependency direction should remain explicit: architecture provides mechanisms;
memory and synchronization use those mechanisms; interrupt dispatch invokes
bounded registered handlers; future scheduling and syscalls build above those
contracts; drivers and diagnostics consume narrow resource/output interfaces.
No scheduler, user mode, syscall entry, operational allocator, or SMP support
is implemented.

## Performance evidence policy

No performance result exists. Benchmarking starts only after the relevant path
is correct, repeatable, and enabled through its safety gates. Use a pinned
workload, warm-up, many samples, median and tail percentiles, and record CPU,
firmware/VM, compiler flags, clock source, power policy, and build identity.
Use a VM for functional development only; host scheduling and emulated devices
make it unsuitable as the sole source of hardware latency or power claims.
Compare kernels only with the same hardware, workload, configuration, and
measurement method; make no cross-kernel superiority claim without that data.
