# Windows build and first-boot verification plan

This is a source-reviewed PowerShell plan. No command below was run for this
milestone. It performs no installation or download. CorOS artifacts target
native x86_64 UEFI; Windows-host commands are only for deterministic unit
tests. Stop if any required toolchain component or target is missing; do not
allow a command to fetch it automatically.

## Configuration inspected

| File | Confirmed configuration |
| --- | --- |
| `Cargo.toml` | Workspace members are CorBoot, CorKernel, and `corboot-info`; edition 2021; dev and release panic strategy is abort. |
| `rust-toolchain.toml` | Stable, minimal profile; requests `x86_64-unknown-uefi`. |
| `.cargo/config.toml` | Default target is `x86_64-unknown-uefi`; `-C no-redzone=yes`; aliases `build-milestone0`, `test-boot-info`, and `test-kernel-foundation`. The tests explicitly select `x86_64-pc-windows-msvc`. |
| Crate manifests | CorBoot binary tests are disabled; CorKernel binary tests are enabled; shared ABI is a library. No external Cargo dependencies or Cargo features are declared. |
| Build configuration | No `build.rs`, custom linker script, or target JSON is present in the repository. Cargo.lock uses format version 4. |
| `tools/build.ps1` | Builds release workspace for UEFI; optional `-StageEfiFiles` copies both EFI binaries into `dist\esp`. It does not create a disk image. |

## Prerequisites — inspect only

From PowerShell in the repository root:

```powershell
rustc --version
cargo --version
rustup show active-toolchain
rustup target list --installed
where.exe link.exe
where.exe cl.exe
```

The expected Rust host is `x86_64-pc-windows-msvc`; installed targets must
include `x86_64-unknown-uefi` and `x86_64-pc-windows-msvc`. MSVC host tests
also need `cl.exe`, `link.exe`, and Windows SDK libraries available in the
current Developer PowerShell. These inspection commands install nothing. If a
prerequisite is missing, stop and resolve it in a separately authorized setup
step before running Cargo.

## Future execution checklist

Run in order from the repository root. Keep the output and check each result
before continuing.

### 1. Host test compilation and execution

Both aliases are defined in `.cargo/config.toml`:

```powershell
cargo test-boot-info
if ($LASTEXITCODE -ne 0) { throw "cargo test-boot-info failed: $LASTEXITCODE" }

cargo test-kernel-foundation
if ($LASTEXITCODE -ne 0) { throw "cargo test-kernel-foundation failed: $LASTEXITCODE" }
```

They compile and run shared ABI and kernel host tests. CorBoot has no test
command because its binary manifest sets `test = false`. The kernel test target
includes x86 inline/global assembly and UEFI ABI declarations; Windows MSVC
compatibility remains unknown until compiler and linker output is available.
Passing tests do not exercise firmware or privileged hardware behavior.

### 2. UEFI target compilation

`build-milestone0` is defined as `build --release --workspace`; Cargo
configuration supplies the UEFI target:

```powershell
cargo build-milestone0
if ($LASTEXITCODE -ne 0) { throw "cargo build-milestone0 failed: $LASTEXITCODE" }
```

Expected outputs from the target and release configuration:

```text
target\x86_64-unknown-uefi\release\corboot.efi
target\x86_64-unknown-uefi\release\corkernel.efi
```

Success proves target compilation and linking only. It does not prove firmware
ABI correctness, the memory handoff, or boot behavior.

### 3. EFI artifact inspection and staging

After a successful build, inspect the configured artifacts:

```powershell
Get-Item .\target\x86_64-unknown-uefi\release\corboot.efi, .\target\x86_64-unknown-uefi\release\corkernel.efi
```

The existing script builds again, then stages the files:

```powershell
.\tools\build.ps1 -StageEfiFiles
if (-not $?) { throw 'tools/build.ps1 staging failed; inspect the first PowerShell error.' }
Get-Item .\dist\esp\EFI\BOOT\BOOTX64.EFI, .\dist\esp\EFI\COROS\CORKERNEL.EFI
```

The script checks Cargo's exit code before copying. Success proves the files
were copied to the configured EFI directory tree. It does not inspect the PE
images, create boot media, or prove they boot.

### 4. VirtualBox UEFI boot

The repository contains no VM configuration, disk-image creation script, or
VirtualBox launch command. Therefore there is no repository-defined exact
command to give or run. A future boot pass must establish and record a real EFI
boot medium and UEFI VM configuration before launching VirtualBox.

### 5. Serial-log review

CorKernel writes diagnostics to COM1 only after a source-level scratch-register
probe. The repository configures neither a VirtualBox serial port nor a log
path, so it has no serial-log command. When a VM configuration defines the
output file, retain the raw log and inspect that configured file in PowerShell.
A missing log by itself cannot distinguish a failed boot from unavailable
serial routing.

### 6. Evidence-based pass/fail

- Host tests pass only when both aliases exit zero and Cargo reports every
  executed test `ok`. This proves host test results only.
- Target build passes only when the build alias exits zero and both configured
  EFI outputs exist. This proves compilation and linking only.
- Staging passes only when the script succeeds and both staged files exist.
  This proves copying only.
- First boot passes when retained evidence shows CorBoot loaded CorKernel,
  `ExitBootServices` succeeded, and CorKernel emitted its online and safe-halt
  diagnostics. Keep the VM configuration and raw serial log with that result.
  This proves behavior only for the recorded configuration; it does not prove
  memory allocation, heap, CR3 transition, or interrupt-route readiness.
- A nonzero command, missing artifact, firmware error, missing required
  handoff diagnostic, or panic fails its corresponding stage.

## Status

Toolchain availability was not checked in this milestone. Host tests, UEFI
compilation, EFI staging, and VirtualBox runtime verification are **NOT RUN**.
Windows MSVC assembly/link compatibility and actual firmware behavior need
compiler output and a real boot. Frame allocation, heap activation, CR3
transition, timer startup, and additional interrupt routes remain gated; see
[`MEMORY.md`](MEMORY.md), [`BOOT.md`](BOOT.md), and
[`MILESTONES.md`](MILESTONES.md).
