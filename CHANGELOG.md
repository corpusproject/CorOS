# Changelog

## [1.0.0] - 2026-11-02

First tagged release.

### Added
- UEFI boot chain (CorBoot → CorKernel) with BootInfo ABI.
- Window-manager desktop, Task Manager, CorAudio player, CorShark & Firewall.
- Lock-free PS/2 keyboard and self-healing PS/2 mouse drivers; dual PIC/APIC EOI.
- 22 `no_std` subsystem crates and a 361-vector syscall table.
- Namespaces/chroot, cgroups v2, POSIX signals, futex, swap/LRU paging.
- `AF_UNIX` + `SCM_RIGHTS`, FIFOs, POSIX MQ vectors, ELF dynamic linker/relocations.
- Btrfs, ZFS, F2FS, XFS, ISO9660 (Rock Ridge/Joliet) parsers.
- Hybrid UEFI live-ISO generator (`tools/make-iso.py`) and VirtualBox helpers.
- 590-test E2E model suite and adversarial challenger scripts.

### Changed
- Workspace version bumped to 1.0.0; license set to MIT.
- Removed all `corboot` compiler warnings.

### Known issues
See *Known limitations* in `README.md`.
