# CorOS interrupt foundation

Status is source-only and unverified.

**IMPLEMENTED IN SOURCE, NOT COMPILED:** per-vector entry stubs for vectors 0–255, normalized vector/error-code slots, PIC-owned IRQ registration, and PIC spurious IRQ filtering. **SOURCE TESTS WRITTEN, NOT RUN:** pure controller-to-EOI policy, PIC spurious-IRQ policy, and exception error-code classification. **NOT IMPLEMENTED:** active APIC/IOAPIC routing or boot-time timer enable. **NOT VERIFIED:** compilation, boot, controller behavior, hardware routing, and EOI behavior.

## Dispatch

GDT/TSS/IDT setup retains the double-fault IST. Each vector 0–255 has an entry stub that pushes its actual vector. Vectors without a processor-pushed error code push a zero placeholder; error-code exceptions include #DF, #TS, #NP, #SS, #GP, #PF, #AC, #CP, #VC, and #SX. The shared frame therefore has a consistent vector/error-code prefix. CPU exceptions below 32 are fatal and never receive controller EOI. Vectors 32–47 dispatch only after a legacy PIC source was registered; unknown sources halt without EOI. Vector frame layout and assembly remain uncompiled and unverified. No user-mode interrupt entry is present.

The common entry clears DF, aligns the call stack, saves/restores GPRs and FXSAVE x87/SSE state, and reserves x64 ABI shadow space. The 512-byte FXSAVE area starts at a 16-byte-aligned address; CR0.EM/TS are cleared and CR4.OSFXSR/OSXMMEXCPT are set during CPU initialization. This preserves legacy x87/SSE state only; it is not complete CPU extended-state preservation. AVX and any other unsaved extended state are prohibited in interrupt-reachable code. Context-switch state ownership is not implemented.

Handlers run with maskable interrupts disabled by the interrupt gate. They may perform bounded atomic/accounting work. They must not block, sleep, allocate, take locks that ordinary code can hold across interrupt entry, perform filesystem/I/O waits, call userspace, or invoke scheduling. NMI is not masked by IF and has no separate nested-state policy; interrupt code must not assume NMI cannot interrupt it. Handler function pointers are static code addresses with kernel lifetime; there is no unregister or replacement operation, and duplicate registration fails. The PIC EOI occurs after a registered handler when its source is confirmed as legacy PIC.

## Routing and timer

The 8259 PIC has an explicit remap-and-mask path; lines are unmasked individually only after IDT/handler setup. The current boot path does not initialize or unmask it. `register_pic_irq` rejects registration before the PIC's software active state. PIT initialization checks this condition before consuming the one-shot IRQ0 registration, programs the nominal ~100 Hz channel-0 rate, then unmasks IRQ0. Its handler only increments an atomic tick counter. Timer startup is not called at boot, and the PIT rate and interrupt path are unverified.

EOI/source contract:

- CPU exceptions: no controller EOI; fatal diagnostic path.
- Registered legacy PIC IRQs: handler runs, then PIC EOI. Spurious IRQ7 is discarded without EOI; spurious IRQ15 is discarded with master cascade EOI only.
- Local APIC timer/error and IOAPIC-routed interrupts: require Local APIC EOI, but no source registration/dispatch path or live mapped controller exists yet. They cannot be enabled.
- Spurious Local APIC vector: no EOI and no handler, by policy; APIC route is not implemented.
- Unknown/unregistered source: fatal path, no guessed EOI.

Pure policy mapping is source-tested but tests are NOT RUN. The PIC spurious ISR reads and actual EOI writes are hardware behavior and remain unverified. PIC and APIC routes must not be mixed or simultaneously unmasked.

The PIT initializer checks the PIC active flag before registering IRQ0,
avoiding a consumed registration when PIC routing is known unavailable. The
check reflects software initialization state only; it does not validate
hardware routing.

Local APIC discovery reads CPUID and IA32_APIC_BASE. A wrapper can access ID/EOI/spurious-vector and masked timer registers once the caller supplies a valid uncacheable MMIO mapping. Mapping, enabling, timer calibration, APIC EOI integration, IOAPIC and MADT routing, and PIC-to-APIC transition are not implemented in the boot path. The two routing modes must never both be unmasked when that transition is added.

Current IRQ dispatch routes EOI through the legacy PIC helper only for vectors
registered as PIC-owned. The former shared fallback for vectors 48–255 was
replaced in Milestone 1.9 by distinct vector stubs. APIC routing still needs
source-specific dispatch/EOI before any APIC interrupt is unmasked.

No scheduler, process/thread switching, syscall gate, or interrupt-context scheduling is implemented. Compilation, firmware boot, and hardware/VirtualBox interrupt verification remain outstanding.
