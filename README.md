# CorOS v1.0

*Corpus Studio tarafından geliştirilen modern işletim sistemi.*

CorOS is an independent x86_64 **UEFI** operating-system project written in pure
`#![no_std]` Rust with **zero external crate dependencies**. It boots through its own
UEFI loader (CorBoot), hands off to a native kernel (CorKernel), and provides a
framebuffer desktop environment with PS/2 keyboard/mouse input.

> **Status: v1.0 – research / hobby OS.** It boots in VirtualBox (UEFI). It is not a
> Linux replacement and has not been validated on real hardware. See
> [Known limitations](#known-limitations) before relying on any claim below.

## Features

- **CorBoot** – UEFI loader: kernel/initrd loading, memory-map handling, BootInfo handoff.
- **CorKernel** – GDT/IDT/TSS, frame allocator, heap, PIC + Local APIC, PIT/TSC timing,
  serial logger, 361-vector Linux-style syscall table (`SYSCALL`/`SYSRET`).
- **Input** – lock-free PS/2 keyboard ring buffer (extended scancodes, arrows, Delete,
  Super), self-resynchronising PS/2 mouse state machine with acceleration.
- **Desktop / window manager** – file explorer, terminal, notepad, calculator, paint,
  code editor, settings, device manager, disk manager, lock screen, and more.
- **Task Manager** – per-core CPU history graphs, memory breakdown, process table.
- **CorAudio player** – playlist, volume/scrub, equalizer visualiser, AC'97 trigger.
- **CorShark & Firewall** – packet-capture style table with hex inspector, firewall rule toggles.
- **Subsystem crates** (`subsystems/`) – 22 independent `no_std` crates, e.g. `corsyscall`,
  `corvfs`, `cornet`, `cormm`, `corsched`, `corsec`, `coripc`, `cortoolchain`
  (ELF dynamic linker / relocations), `corvirt`, `cordrm`, `corblock`, `corwifi`, …
- **Linux-feature work (Milestones 1–3)** – namespaces/chroot, cgroups v2, POSIX signals,
  futex/sync primitives, swap/LRU paging, `AF_UNIX` + `SCM_RIGHTS`, FIFOs, POSIX message
  queues, `ld.so`-style loader with AMD64 relocations, and Btrfs / ZFS / F2FS / XFS /
  ISO9660 (Rock Ridge + Joliet) on-disk parsers.

## Repository layout

| Path | Purpose |
|------|---------|
| `boot/corboot` | UEFI loader |
| `shared/corboot-info` | Versioned boot ABI shared by loader and kernel |
| `kernel/corkernel` | Kernel, drivers, window manager, filesystems (`src/fs`) |
| `subsystems/*` | Independent `no_std` subsystem crates |
| `tests/e2e` | Python E2E model test suite (590 tests) |
| `tests/*.py` | Adversarial/empirical challenger scripts |
| `tests/empirical_harness` | Stand-alone UEFI test app (own Cargo project) |
| `tools/` | Build, ISO (`make-iso.py`), VirtualBox helpers |
| `docs/` | Early design notes (boot, memory, interrupts, toolchain) |
| `assets/` | Icons, fonts, wallpapers |

## Building

Requirements: Rust (stable, see `rust-toolchain.toml`), the `x86_64-unknown-uefi`
target (`rustup target add x86_64-unknown-uefi`), Windows PowerShell, Python 3.

```powershell
# Type-check everything
cargo check --workspace --target x86_64-unknown-uefi

# Release build + stage the EFI System Partition tree under dist/esp
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -StageEfiFiles

# Additionally produce the hybrid UEFI live ISO (dist/coros.iso, ~2.2 GB)
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -StageEfiFiles -MakeIso
```

## Running (VirtualBox)

```powershell
powershell -ExecutionPolicy Bypass -File tools/run-vbox.ps1 -Iso
```

Click inside the VM window to capture the mouse; press **Right Ctrl** (Host Key) to release it.
Serial output is written to `outputs/serial.log`.

## Testing

```powershell
py -3 tests/e2e/run_e2e_tests.py       # 590 E2E model tests
py -3 tools/scale_coros_50m.py         # uniqueness audit (no synthetic numbered templates)
```

## Known limitations

- **Scale:** the source is roughly 150k lines of Rust (≈620 files). Earlier goals of tens of
  millions of lines were not met and are not claimed.
- **ISO size:** `dist/coros.iso` is ~2.2 GB because `tools/make-iso.py` writes large
  *placeholder* payloads (`/LIVE/ROOTFS.IMG`, `/POOL/PACKAGES.DAT`, …). Only the embedded
  64 MB ESP image is actually booted; the rest is not a working package set or root filesystem.
- **E2E tests** in `tests/e2e` are Python models/specifications of the intended behaviour;
  they do not execute the kernel. Real boot verification is done manually in VirtualBox.
- **Hardware support:** device/chipset databases are data tables; broad real-hardware driver
  support (all CPUs/GPUs/NICs/storage) is **not** implemented.
- **Web browser:** the in-tree `CorBrowse` window is a minimal mock-up; a separate browser
  project is planned to replace it.
- **Milestone 3 review:** a reviewer requested six follow-up fixes in the Btrfs/ZFS parsers
  (dual Btrfs magic, uberblock TXG offsets, `parse_znode_bonus` bounds, Micro-ZAP endianness,
  interior-node key comparison, multi-level directory resolution). Their completion was
  interrupted and is **not verified**.
- **Not started:** xHCI/EHCI USB stack, Netfilter/conntrack/NAT, and KVM/VMX/SVM
  hypervisor support (planned Milestone 4).

## License

MIT – see [LICENSE](LICENSE).

---

## Türkçe Özet

CorOS v1.0; saf `no_std` Rust ile yazılmış, harici bağımlılığı olmayan, UEFI ile açılan
x86_64 deneysel bir işletim sistemidir. Masaüstü arayüzü, PS/2 klavye/fare, Görev Yöneticisi,
ses çalar, ağ paketi analiz aracı ve 22 alt sistem crate'i içerir. Yukarıdaki *Known
limitations* bölümü projenin sınırlarını açıkça belirtir (ISO içeriği büyük ölçüde yer
tutucudur, testler model tabanlıdır, gerçek donanım doğrulanmamıştır).
