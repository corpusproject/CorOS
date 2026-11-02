# CorOS kernel foundation (Milestone 1)

**Implemented but unverified:** CPU/GDT/TSS/IDT foundations, frame-map parser/allocator logic, inactive mapper API, interrupt registry, PIC/PIT interfaces, MMIO ranges, and heap allocator source. Live global frame allocation is fail-closed while active firmware page-table descendants remain unknown. **Partial:** safe CR3 transition, active mapping access, heap provider/global allocator, APIC/IOAPIC routing, and runtime timer setup. **Planned:** scheduler and later subsystems. No compilation or runtime test has been performed. CorKernel remains `no_std` for its UEFI build.

Status vocabulary: **IMPLEMENTED** means source logic exists; **IMPLEMENTED BUT UNVERIFIED** means not compiled or exercised; **NOT IMPLEMENTED** means no source implementation; **BLOCKED ON RUNTIME VERIFICATION** means source work depends on real boot/hardware evidence before it can be enabled.

## CPU and interrupt foundation

The x86_64 layer provides CPU control-register/MSR/port operations, flat ring-0 GDT, TSS with double-fault IST1, and a 256-entry IDT with a distinct stub per vector. Each stub pushes its actual vector; processor error codes are retained and no-error vectors add a zero placeholder. The common stub clears DF, aligns its call stack, saves GPRs and FXSAVE x87/SSE state, invokes dispatch, restores state, and returns with `iretq` for handled IRQs. These ABI/assembly details are **implemented in source, not compiled or runtime verified**. The common interrupt frame does not preserve AVX or other extended state. Such use is prohibited in interrupt-reachable code until a complete XSAVE policy exists. A fixed atomic registry rejects duplicate vector ownership. Interrupt handlers must be bounded and nonblocking: no allocation, logging locks, filesystem, sleeping, or scheduler work.

The legacy 8259 PIC path can remap and mask all lines, then unmask a selected IRQ after its PIC-owned handler exists. The current boot path does not initialize it. Dispatch distinguishes CPU exceptions (no EOI), registered PIC IRQs (PIC EOI), PIC spurious IRQ7/IRQ15 (filter before handler; no EOI for 7, master-only EOI for 15), and unknown vectors (halt without EOI). APIC timer/error and IOAPIC routes require Local APIC EOI, but source registration and live controller wiring are absent and rejected by current dispatch. Local APIC spurious policy is no EOI. Local APIC discovery and a mapped-MMIO wrapper exist, but no APIC route is enabled. See `docs/INTERRUPTS.md` for the full contract.

## Virtual and physical memory

The current kernel keeps UEFI CR3. The documented future four-level layout reserves high-half ranges for kernel (`ffff8000…`), heap (`ffff9000…`), MMIO (`ffffc000…`), and framebuffer (`ffffd000…`), with low canonical addresses reserved for future user mappings and unmapped gaps between regions. These are reservations, not active mappings. The bootstrap physical strategy remains firmware mappings until all live kernel, stack, BootInfo, framebuffer, and allocator structures can be preserved. Source establishes the CR3 root but not paging-control state, the active tree, or safe physical access to table frames; current CR3 transition readiness remains **FAIL**.

The page-table builder allocates and tracks each intermediate/root table frame, supports 4 KiB map/unmap/protect/translate, rejects accidental replacement, and can allocate a leaf frame from the physical allocator. A `PageTableAccess` implementation must explicitly supply writable access to table pages; no identity-map adapter is provided. A separate unsafe read-only provider contract and bounded four-level `inspect_path` parser exist, but no provider is established for the active firmware tree; it has not been enumerated. The new root is not activated by boot code. `release_inactive` is unsafe and valid only before activation. Huge-page creation and active-root mutation are not implemented.

UEFI region parsing accepts only descriptor version 1, uses the supplied descriptor stride, validates page alignment/count/range arithmetic, and reserves `EFI_MEMORY_RUNTIME` regardless of nominal type. Unknown types remain reserved. Only conventional memory enters the bitmap; non-usable descriptors are applied afterward so overlap cannot expose reserved frames. CorBoot validates both loaded images' LoaderCode/LoaderData classifications. Their `ImageBase` values and the ACPI configuration-table value are opaque EFI pointer values, not physical reservations. GOP's physical framebuffer range and the physical CR3 root are explicitly reserved. Frame/Page index conversion reports overflow; physical-width unknown is an initialization error. Active CR3 descendants cannot be enumerated without a validated provider. Production allocator instances and global frame allocation/free remain gated off. No memory is reclaimed. See `docs/MEMORY.md` for the ownership inventory and transition protocol.

MMIO address/range types validate page rounding and overflow and keep device ranges distinct from allocator RAM. Kernel framebuffer writes are disabled until a caller supplies a proven mapped virtual alias; the former physical-address dereference was removed. No persistent CorOS virtual mapping is installed.

## Heap, timer, and synchronization

`KernelHeap` is a first-fit allocator with alignment, page-provider growth, deallocation/reuse, and explicit OOM/errors. Its provider contract requires exclusively owned mapped frames and range exclusion. No provider currently connects it to the active address space, and no global allocator is registered. Consequently, runtime heap backing is partial.

TSC reads remain raw, uncalibrated cycles. An opt-in PIT IRQ initializer checks PIC active state before registering IRQ0, programs a nominal 100 Hz divisor, and unmasks it only after registration. The handler only increments an atomic monotonic tick counter; nanosecond conversion uses the nominal PIT rate and is not a wall clock or calibrated measurement. The boot path keeps IF clear and does not start this timer. APIC timer calibration/routing is not verified.

Spinlocks use acquire/release ordering and offer an IRQ-save guard. Locks used by handlers must never be held across unbounded interrupt-disabled work. If multiple locks are introduced, acquire them in a documented global order; interrupt handlers should not acquire ordinary-context locks. The IRQ-save guard prevents local re-entry but does not provide SMP safety. No sleeping mutex or lock hierarchy enforcement exists.

## Diagnostics and verification

COM1 output is enabled only after a scratch-register round-trip probe, but UART presence/routing is unverified. Panic/exception diagnostics allocate no memory and do not depend on the heap, scheduler, interrupts, or firmware services. Source tests exist for paging classification and mode, descriptor/reservation logic, allocation gates, and earlier foundation logic; none have run. No Rust compiler, Cargo, boot, or VirtualBox verification was performed. Scheduler work must wait until Windows compilation/tests, actual UEFI boot, map/stack validation, safe table access, controlled CR3 testing, working heap provider, and IRQ/timer tests are complete.

The configured Windows-host test commands and their MSVC prerequisites are
listed in [`docs/TOOLCHAIN.md`](TOOLCHAIN.md). Kernel tests include source with
UEFI calling-convention declarations and x86_64 assembly; Windows target
compiler/linker compatibility is not claimed until those commands provide
compiler output.

### CPU state policy

Current interrupt entry uses FXSAVE/FXRSTOR on a 16-byte-aligned 512-byte
area, with separate stack space for x64 shadow space. CPU initialization clears
CR0.EM and CR0.TS, sets CR0.MP/NE, and sets CR4.OSFXSR/OSXMMEXCPT. This policy
preserves x87, MXCSR, and legacy XMM state only. It does **not** claim complete
CPU state preservation. Interrupt-reachable code must not use AVX/YMM, AVX-512,
AMX, or other extended state unsupported by that save area.

Future XSAVE support requires all of the following before enabling any such
code: CPUID validation for XSAVE and each requested feature; deliberate
CR4.OSXSAVE configuration; validated XCR0 feature dependencies and per-CPU
`XGETBV`/`XSETBV` setup; CPUID-reported XSAVE area size and alignment for the
selected mask; aligned, correctly sized state buffers; and explicit per-thread
ownership, initialization, interrupt nesting, context-switch save/restore,
and migration rules. None is implemented. Do not enable OSXSAVE/AVX or infer
these conditions from firmware state.

## Milestone 1.8 architecture audit

This is a source audit only. No performance optimization, scheduler, user
execution, or new benchmark implementation was added.

### Audit results

| Subsystem | Source-level result | Unresolved evidence/risk |
| --- | --- | --- |
| CPU and ABI | UEFI `efiapi` is used at entry and dispatch boundaries. The kernel entry reserves Windows x64 shadow space and aligns its private stack. Interrupt entry saves GPRs and FXSAVE state, aligns the call stack, and restores before `iretq`. GDT/TSS/IDT have static layouts and a double-fault IST. | None of these assembly/ABI paths has compiler or firmware verification. FXSAVE covers x87/SSE, not AVX/extended state; AVX must remain absent from interrupt-reachable code until XSAVE policy exists. Per-vector stubs now preserve vectors 48–255 in source; this correction is uncompiled. |
| Memory | Physical/virtual wrappers and checked frame-index arithmetic exist; unknown descriptors remain reserved; production frame allocation and heap activation remain disabled; no identity physical-table reader or CR3 writer exists. | Address wrappers do not alone validate hardware-width/range ownership. Active firmware page-table descendants and inherited mappings remain unknown. Heap free-list metadata and provider assumptions have only deterministic source tests, not execution evidence. |
| Synchronization | Spinlock uses acquire on acquisition and release on unlock; IRQ-save disables local maskable interrupts before taking the lock and restores IF after releasing it. | No fairness, owner/deadlock detection, preemption control, lock-order checker, or SMP proof exists. Plain `lock()` is unsafe for data shared with an interrupt handler that could preempt its holder. No scheduler uses these primitives. |
| Interrupts/timers | Static registry rejects duplicate vectors; PIC registration is source-tagged; PIC unmask requires a registered handler; PIC spurious IRQ7/IRQ15 are filtered before handler invocation. Handler pointers are static and never unregistered. Boot does not initialize PIC or PIT. | APIC routes have no registration/EOI implementation. Dispatch halts without EOI for APIC and unknown sources. PIC/APIC transition is absent; PIT nominal frequency is not calibrated. NMI nesting is not separately handled. |
| Diagnostics/failure | Early logger and panic output allocate no memory and do not call firmware; serial output is gated by a scratch-register probe; framebuffer writes remain disabled. | A scratch-register response does not prove UART routing or hardware identity. Panic reporting itself has not been exercised; output may be absent if serial is unavailable. |

The timer initializer had a recoverability defect: it registered IRQ0 before
checking whether PIC routing was active, so a failed call could leave the
one-shot vector registration occupied. It now checks PIC active state before
registration. This is a source-level ordering correction only; timer/PIC
hardware behavior remains unverified.

### Measurable performance plan — future work only

Every benchmark requires functional correctness and a stable baseline first.
Use invariant TSC only after verifying support and frequency/ordering behavior;
otherwise use a calibrated platform clock. Report sample count, median, p95,
p99, variance, warm-up policy, build identity, CPU model, firmware/VM settings,
and measurement overhead. Avoid comparing unlike VM and bare-metal results.

| Benchmark | Metric | Prerequisites | Method | Main noise | Establishes if reproducible |
| --- | --- | --- | --- | --- | --- |
| Syscall latency | cycles/ns per empty syscall; median and p99 | User mode, syscall ABI/entry, process address spaces, validation and return path | Pin caller, warm instruction/data paths, batch calls, subtract calibrated timer overhead; compare empty path with a fixed work control | TSC ordering, branch/cache state, mitigation settings, host/VM scheduling | Cost of the implemented entry/exit path for that machine and configuration |
| Interrupt latency | trigger-to-handler-entry cycles/ns and trigger-to-EOI/return | Verified IDT, one routed source, calibrated trigger, stable timer; no competing IRQs | Toggle/observe a hardware source or use a calibrated local timer; timestamp at source and first handler instruction, repeat with controlled load | Device/VM injection latency, interrupt masking, cache state, firmware routing, TSC skew | End-to-end and in-kernel interrupt path latency for that source |
| Context-switch latency | cycles/ns per voluntary and timer-driven switch | Scheduler, two pinned runnable contexts, saved CPU/SIMD state, valid stacks/mappings, timer | Ping-pong two tasks; separately measure voluntary yield and preemption; report distributions and switch count | Cache/TLB misses, timer jitter, migration, FPU state size, virtualization | Cost of the specific switch path, not application responsiveness generally |
| Physical page allocation/free | ns or cycles/op; throughput and tail latency | Verified ownership map, safe mapping access, allocator enabled, no overlapping allocator metadata | Pre-touch a fixed pool; benchmark allocate/free sizes and fragmentation patterns, first single-threaded then contended after SMP safety | Cache-line contention, bitmap locality, NUMA, page zeroing policy, pool size | Cost/capacity tradeoffs of the allocator under the tested workload |
| Heap allocation/free | ns/op by size/alignment, throughput, fragmentation and OOM rate | Verified frame/page provider, active mapped heap, heap gate intentionally enabled | Replay deterministic allocation traces; include frees, alignments, lifetimes, and exhaustion; compare warm/cold pages | First-fit scan length, fragmentation, provider growth, cache/zeroing | Heap behavior for the recorded trace; not general allocator superiority |
| IPC latency/throughput | round-trip ns/message, messages/s, bytes/s, p99 | Processes/threads, IPC primitive, synchronization and memory isolation | Ping-pong fixed and varied payloads; batch throughput separately from single-message latency | Scheduler wakeups, cache-line bouncing, payload copies, VM scheduling | Cost of the chosen IPC mechanism and payload path |
| Filesystem/storage throughput | MB/s, IOPS, operation latency distribution | Storage driver, filesystem, cache/flush semantics, repeatable medium/workload | Sequential and random reads/writes with working set larger than relevant caches; separate cached from durable writes | Device cache, flash wear leveling, filesystem journal, host page cache, thermal state | Throughput/latency under a stated durability and cache policy |
| Multicore scaling | throughput speedup and p95/p99 latency versus active core count | AP startup, per-core stacks/IDTs, TLB/memory model, SMP-safe allocator/locks, pinned workloads | Run the same fixed workload on 1..N pinned CPUs; report speedup, efficiency and contention counters | Turbo/power limits, core migration, NUMA, shared locks, VM vCPU scheduling | Scaling and contention of that workload over tested core counts |
| Idle CPU/power | idle residency or utilization, wakeups/s, joules/s or watts | Scheduler idle loop, safe halt state, timer policy, power telemetry or external meter | Measure fixed-duration idle windows with and without periodic tick; use platform telemetry and preferably an external power meter | Firmware, background OS/VM work, thermal/power policy, telemetry precision | Idle behavior on the measured platform; not universal battery/runtime claims |

No benchmark can run against the present kernel as a meaningful kernel
performance test: the boot path halts, interrupts/timers are not started, the
allocator and heap are gated, and scheduler/syscall/IPC/filesystem/multicore
paths do not exist. Do not fabricate numbers or use host-side microbenchmarks
as a substitute for these kernel paths.

## Recommendation for the next milestone

First obtain Windows-native compiler output and fix only confirmed build
failures. Then verify real UEFI boot, exception/stack behavior, descriptor
ownership, and diagnostic failure paths while keeping frame allocation,
heap, and CR3 closed. Resolve the default-vector identity and source-specific
EOI contracts before enabling new interrupt routes. Select one narrow subsystem
for implementation only after those foundations have evidence; do not start a
scheduler or performance tuning from source-only assumptions.
