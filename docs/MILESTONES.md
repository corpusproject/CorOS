# CorOS milestone tracking

## Milestone 0 — first native kernel handoff

**Status: CODE-FIRST HARDENING COMPLETE — runtime incomplete.** The source pass
is complete, but the host toolchain is unavailable, so no part is marked
compiled, booted, or runtime verified.

| Requirement | Status |
| --- | --- |
| Separated CorBoot, CorKernel, and shared ABI crates | Implemented but unverified |
| UEFI kernel-file loading path | Implemented but unverified |
| Stable BootInfo and memory descriptor parser | Implemented but unverified; source-level tests written |
| GOP and ACPI discovery | Implemented but unverified |
| ExitBootServices and stale-key retry | Implemented but unverified |
| Native kernel PE entry and private stack | Implemented but unverified |
| Early framebuffer diagnostics | Implemented but unverified |
| Reproducible Cargo workspace configuration | Implemented but unverified |
| EFI removable-media file staging | Implemented but unverified; not a disk image |
| Bootable image generation | Not implemented |
| VirtualBox UEFI boot | Not verified |

Milestone 0 passes only after the workspace builds, an actual UEFI bootable
image is generated, and VirtualBox demonstrates the CorBoot -> ExitBootServices
-> CorKernel path with kernel-owned diagnostics.

## Milestone 1 — kernel foundation

**Status: CODE-FIRST FOUNDATION PASS — source-only and unverified; critical activation/integration work remains.**

| Requirement | Source status |
| --- | --- |
| CPU accessors and privileged instruction boundary | Implemented, unverified |
| CorOS GDT and TSS with double-fault IST stack | Implemented, unverified |
| IDT, normalized exception stubs, fatal handlers | Implemented, unverified |
| Separate IRQ dispatcher and duplicate-safe registry | Implemented in source, unverified; vectors 32–47 only |
| Legacy PIC remap/mask/EOI path | Implemented in source, not started by boot |
| Page-fault decoding and CR2 diagnostics | Implemented, unverified |
| Physical memory classification and bitmap allocator | Parsing/reservation logic implemented; live allocation is fail-closed because firmware page-table descendants and image physical interpretation remain unverified; static bitmap covers 4 GiB |
| CorOS virtual layout and inactive four-level page-table builder | Implemented in source; no CR3 activation |
| MMIO types and framebuffer/APIC persistent mappings | MMIO validation implemented; persistent mappings partial |
| Provider-backed kernel heap | Allocator implemented; no active page provider or GlobalAlloc |
| Spinlock and IRQ-save guard | Implemented, unverified |
| TSC, opt-in PIT ticks, APIC mapped-MMIO wrapper, serial/logging | Partial, unverified; timer/APIC not started by boot |
| Scheduler and later OS subsystems | Not started |

Runtime verification is unavailable. Do not start scheduler work until the
workspace and source tests run and actual UEFI memory-map and exception behavior
has been checked.

## Milestone 1.5 — memory handoff and boot safety

**Status: PARTIAL SOURCE AUDIT — CR3 readiness FAIL; compilation and runtime remain unverified.**

| Requirement | Status |
| --- | --- |
| Boot contract and post-ExitBootServices live objects traced from source | Implemented but unverified; firmware behavior not established |
| Consolidated memory ownership inventory | Implemented in `docs/MEMORY.md`; active page-table descendants unknown |
| UEFI descriptor stride, bounds, overflow, alignment, runtime attributes, and classification audited | Implemented in source; unverified |
| Non-usable overlap precedence and explicit reservations | Implemented in source; unverified |
| Read-only bounded page-walk parser and entry classification | Implemented as interface/parser only; no trusted live-table provider; four-level mode itself is not proven |
| Safe physical access to active UEFI tables | Not implemented / blocked |
| CR3 transition protocol | Documented only; transition not implemented; readiness FAIL |
| Heap provider, heap initialization, and global allocator | Not implemented; heap activation remains gated |
| Pure-logic source tests | Written, not run |
| Compilation and actual UEFI/VirtualBox verification | Not run / unavailable |

Do not begin scheduler work until a Windows toolchain can compile the workspace,
source tests execute, and a real UEFI boot validates the handoff, map ownership,
interrupt stacks, safe table access, and a controlled CR3 transition.

## Milestone 1.6 — boot contract proof and memory safety

**Status: PARTIAL — source safeguards improved; active firmware paging and memory ownership remain unverified.** Compilation and runtime verification remain unavailable and were not attempted.

| Requirement | Status |
| --- | --- |
| BootInfo field representation, units, ownership, and access conditions | Documented; ABI remains version 1 and unchanged |
| EFI image-base and ACPI pointer values kept out of physical reservation arithmetic | Implemented; images are validated as LoaderCode/LoaderData; map extents are not cross-matched |
| UEFI descriptor version/stride/range validation | Implemented for descriptor version 1; unverified against firmware |
| Current CR0/CR4/EFER/CPUID paging snapshot | Implemented as read-only source API; not captured during boot verification |
| Four-/five-level and entry/PAT/large-page interpretation | Parser rejects unsupported/unknown configurations and unsupported 1 GiB pages |
| Physical page-table access | No validated implementation; inspection fails with `AccessUnavailable` |
| Frame allocation before complete reservations | Both production `FrameAllocator` instances and global allocation/free gate remain closed; no production enable path |
| CR3 activation | No CR3 write API; gate is hard-coded closed; readiness FAIL |
| COM1 diagnostics | Scratch-register probe gates output; hardware presence remains unverified |
| Pure source tests | Added/written; not run |

## Milestone 1.7 — build readiness and verification preparation

**Status: PARTIAL — Windows-native verification workflow documented; build prerequisites and all build/runtime results remain unverified.** No installation, download, compile, test, staging, or emulator command was run for this milestone.

| Requirement | Status |
| --- | --- |
| Workspace, target, aliases, manifests, and staging script inspected | Source-reviewed; no custom build script, linker script, or target JSON exists |
| Existing Windows build and test commands documented | Documented in `docs/TOOLCHAIN.md`; aliases were verified in `.cargo/config.toml` |
| Host test target prerequisites | MSVC compiler/linker and Windows host target required; availability and assembly compatibility not established here |
| Artifact names and staging layout | Taken from `tools/build.ps1`; staging creates an EFI directory tree, not a disk image |
| Source build blockers | No definitive compile defect fixed without compiler evidence; target-specific kernel assembly on Windows-host tests remains a risk to resolve from compiler output |
| Tests | Existing shared ABI and kernel test aliases prepared; NOT RUN |
| UEFI/VirtualBox runtime | NOT RUN; no repository command creates the disk image or full VM configuration |
| Frame allocation, heap, CR3 | Existing fail-closed gates preserved |

Do not treat build instructions as a successful build. Establish the missing
Windows-native prerequisites, then run the documented build and host tests and
collect actual UEFI runtime evidence before changing any safety gate.

## Milestone 1.8 — kernel architecture audit and performance foundation

**Status: PARTIAL — source audit and benchmark design recorded; compilation and runtime remain NOT VERIFIED.** No scheduler or benchmark implementation was added. Frame allocation, heap activation, and CR3 transition remain gated.

| Requirement | Status |
| --- | --- |
| CPU/ABI, memory, synchronization, interrupt/timer, and diagnostics audit | Reviewed from source; ABI/assembly/runtime assumptions remain unverified |
| Confirmed failure-path correction | PIT initializer checks PIC software active state before consuming IRQ0 registration; hardware route remains unverified |
| Unexpected interrupt vector identity | Unresolved at 1.8; corrected in 1.9 with distinct vector stubs 0–255 |
| Interrupt-source EOI contract | Partial at 1.8; 1.9 tags PIC registrations and rejects unknown/APIC dispatch without a provider |
| Architecture boundaries | Documented as proposed contracts in `docs/ARCHITECTURE.md` |
| Performance strategy | Future benchmark plan documented in `docs/KERNEL.md`; no executable benchmarks or results |
| Tests, compilation, UEFI runtime | NOT RUN / NOT VERIFIED |

Resolve build and boot evidence before activating interrupt sources or moving
on to a scheduler. Do not use this source audit as hardware validation.

## Milestone 1.9 — interrupt correctness and CPU state policy

**Status: PARTIAL — source changes and deterministic tests written; compilation, tests, boot, and hardware behavior NOT VERIFIED.** No routes or timers were enabled.

| Requirement | Status |
| --- | --- |
| Actual vector preservation | Distinct stubs for vectors 0–255 push their actual vector; source-only, uncompiled |
| Hardware error-code normalization | Error-code exception list retained; other vectors push a zero slot; pure classification test written, NOT RUN |
| EOI/source policy | Source enum maps PIC and APIC/IOAPIC requirements; only registered PIC path is executable; exceptions/unknown/spurious-LAPIC do not receive EOI |
| PIC spurious IRQ7/IRQ15 | Filtered before calling handler; spurious 7 gets no EOI, spurious 15 only master cascade EOI; pure policy test written, hardware behavior NOT VERIFIED |
| Registration/masking | PIC active and handler ownership required before unmask; timer checks active PIC before registration; policy unit test written, NOT RUN |
| FPU/SIMD | FXSAVE/FXRSTOR documented as x87/SSE only; AVX/extended state prohibited until XSAVE policy prerequisites exist |
| Allocator, heap, timer, APIC, CR3 | Remain disabled/not started; no CR3 writer |

## Milestone 2.0 preparation — first verified kernel

**Status: SOURCE AUDIT AND VERIFICATION PLAN PREPARED — NOT VERIFIED.** The
current source, ABI boundaries, and repository commands were re-inspected. No
build, test, staging, or firmware execution was performed.

| Requirement | Status |
| --- | --- |
| CorBoot loaded-image, BootInfo, final-map, and ExitBootServices path | Source-reviewed; firmware handoff NOT VERIFIED |
| CorKernel entry, private stack, GDT/TSS/IDT and interrupt ABI | Source-reviewed; assembly/link behavior NOT VERIFIED |
| PIC policy, exception diagnostics, and memory gates | Source-reviewed; hardware behavior NOT VERIFIED |
| Windows-native host test, UEFI build, and EFI staging commands | Existing aliases/script confirmed and documented in `docs/TOOLCHAIN.md`; NOT RUN |
| VirtualBox and serial-log commands/configuration | Not present in repository; exact invocation and log path remain undefined |
| Confirmed source defects fixed | None established from source inspection alone |
| Build and host test output | NOT AVAILABLE; NOT RUN |
| First UEFI boot evidence | NOT AVAILABLE; NOT RUN |

Physical frame allocation, heap activation, CR3 writes/transitions, timer
startup, additional interrupt routes, scheduler, and user-mode execution remain
closed. Do not advance to scheduler work until the documented Windows build and
host tests succeed and an actual UEFI boot produces retained evidence. Source
inspection and staged files do not satisfy that gate.

Compiler validation is required for the generated stub table and x86 assembly;
firmware/hardware validation is required for entry frames and controller EOI.

## Later milestones

No later kernel or desktop milestone has started. Scheduler, processes, syscalls,
VFS, drivers, graphics stack, compositor, desktop, and applications remain
planned and are not represented by stubs.
