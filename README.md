# CorOS v1.0

[![License](https://img.shields.io/github/license/corpusproject/CorOS?label=license)](LICENSE)
[![Language](https://img.shields.io/badge/language-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-x86__64%20UEFI-blue)](#)
[![Status](https://img.shields.io/badge/status-research%20%2F%20hobby-lightgrey)](#known-limitations)

*An experimental operating-system project by Corpus Studio.*

**English** · [Türkçe](README.tr.md)

![CorOS wallpaper preview — not a screenshot of a running desktop](assets/wallpapers/wallpaper.png)

CorOS is an independent x86_64 **UEFI** operating-system project written in pure
`#![no_std]` Rust, with **zero external crate dependencies**. Its own UEFI loader
(**CorBoot**) loads the native kernel (**CorKernel**), which provides a framebuffer
desktop and PS/2 keyboard/mouse input.

> **Status: v1.0 — research / hobby OS.** CorOS boots in VirtualBox with UEFI. It is
> not a Linux replacement and has not been validated on real hardware. Read
> [Known limitations](#known-limitations) before relying on the feature descriptions below.

## Quick start

On Windows, install Rust stable and Python 3, then run these commands in PowerShell
(the UEFI target may need to be installed once with `rustup target add x86_64-unknown-uefi`):

```powershell
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -StageEfiFiles
powershell -ExecutionPolicy Bypass -File tools/run-vbox.ps1 -Iso
```

To create the optional hybrid ISO, add `-MakeIso` to the build command. The ISO is
approximately 2.2 GB; most of its non-ESP contents are placeholders (see limitations).

## Features

| Area | Included in the project |
|------|-------------------------|
| **Boot and kernel** | CorBoot UEFI loader, kernel/initrd loading, memory-map handling, BootInfo handoff; CorKernel GDT/IDT/TSS, frame allocator, heap, PIC + Local APIC, PIT/TSC timing, serial logger, and a 361-vector Linux-style syscall table (`SYSCALL`/`SYSRET`). |
| **Input** | Lock-free PS/2 keyboard ring buffer (extended scancodes, arrows, Delete, Super) and self-resynchronising PS/2 mouse state machine with acceleration. |
| **Desktop** | Window manager, file explorer, terminal, notepad, calculator, paint, code editor, settings, device manager, disk manager, lock screen, and more. |
| **System tools** | Task Manager with per-core CPU history graphs, memory breakdown, and process table; CorAudio player with playlist, volume/scrub, equalizer visualiser, and AC'97 trigger. |
| **Networking UI** | CorShark packet-capture-style table with hex inspector and firewall rule toggles. |
| **Subsystem crates** | 22 independent `no_std` crates under `subsystems/`, including `corsyscall`, `corvfs`, `cornet`, `cormm`, `corsched`, `corsec`, `coripc`, `cortoolchain` (ELF dynamic linker / relocations), `corvirt`, `cordrm`, `corblock`, and `corwifi`. |
| **Linux-feature work (Milestones 1–3)** | Namespaces/chroot, cgroups v2, POSIX signals, futex/sync primitives, swap/LRU paging, `AF_UNIX` + `SCM_RIGHTS`, FIFOs, POSIX message queues, an `ld.so`-style loader with AMD64 relocations, and Btrfs / ZFS / F2FS / XFS / ISO9660 (Rock Ridge + Joliet) on-disk parsers. See [Known limitations](#known-limitations) for unverified parser follow-ups. |

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
| `tools/` | Build, ISO (`make-iso.py`), and VirtualBox helpers |
| `docs/` | Early design notes (boot, memory, interrupts, toolchain) |
| `assets/` | Icons, fonts, and wallpapers |

## Build and test

Requirements: Rust stable (see `rust-toolchain.toml`), the `x86_64-unknown-uefi`
target, Windows PowerShell, and Python 3.

```powershell
# Type-check the workspace
cargo check --workspace --target x86_64-unknown-uefi

# Build and stage the EFI System Partition files
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -StageEfiFiles

# Run the E2E model tests (they do not execute the kernel)
py -3 tests/e2e/run_e2e_tests.py
```

For VirtualBox, run `powershell -ExecutionPolicy Bypass -File tools/run-vbox.ps1 -Iso`.
Click inside the VM to capture the mouse; press **Right Ctrl** (Host Key) to release it.
Serial output is written to `outputs/serial.log`.

## Known limitations

- **Scale:** The source is roughly 150k lines of Rust (≈620 files). Earlier goals of tens of millions of lines were not met and are not claimed.
- **ISO contents:** `dist/coros.iso` is approximately 2.2 GB because `tools/make-iso.py` writes large *placeholder* payloads (`/LIVE/ROOTFS.IMG`, `/POOL/PACKAGES.DAT`, …). Only the embedded 64 MB ESP image is actually booted; the rest is not a working package set or root filesystem.
- **Testing:** `tests/e2e` contains Python models/specifications of intended behaviour, not tests that execute the kernel. Real boot verification is performed manually in VirtualBox.
- **Hardware support:** Device/chipset databases are data tables. Broad real-hardware driver support (all CPUs/GPUs/NICs/storage) is **not** implemented.
- **Web browser:** The in-tree `CorBrowse` window is a minimal mock-up; a separate browser project is planned to replace it.
- **Milestone 3 review:** A reviewer requested six follow-up fixes in the Btrfs/ZFS parsers (dual Btrfs magic, uberblock TXG offsets, `parse_znode_bonus` bounds, Micro-ZAP endianness, interior-node key comparison, and multi-level directory resolution). Work was interrupted and completion is **not verified**.
- **Not started:** xHCI/EHCI USB stack, Netfilter/conntrack/NAT, and KVM/VMX/SVM hypervisor support (planned Milestone 4).

## License

MIT — see [LICENSE](LICENSE).
