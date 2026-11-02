[CmdletBinding()]
param(
    [switch] $StageEfiFiles,
    [switch] $MakeIso
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) { $env:PATH = "$cargoBin;$env:PATH" }
$target = 'x86_64-unknown-uefi'
$releaseDir = Join-Path $repoRoot "target\$target\release"

Push-Location $repoRoot
try {
    cargo build --release --workspace --target $target
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo build failed with exit code $LASTEXITCODE."
    }

    if ($StageEfiFiles) {
        $espRoot = Join-Path $repoRoot 'dist\esp'
        $bootDir = Join-Path $espRoot 'EFI\BOOT'
        $corosDir = Join-Path $espRoot 'EFI\COROS'
        New-Item -ItemType Directory -Force -Path $bootDir, $corosDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $releaseDir 'corboot.efi') `
            -Destination (Join-Path $bootDir 'BOOTX64.EFI') -Force
        Copy-Item -LiteralPath (Join-Path $releaseDir 'corkernel.efi') `
            -Destination (Join-Path $corosDir 'CORKERNEL.EFI') -Force
        Copy-Item -LiteralPath (Join-Path $releaseDir 'corkernel.efi') `
            -Destination (Join-Path $corosDir 'CORKERNEL_BACKUP.EFI') -Force
        [System.IO.File]::WriteAllBytes((Join-Path $corosDir 'INITRD.IMG'), [System.Text.Encoding]::ASCII.GetBytes("COROS_INITRD_V1_ASSET_BUNDLE_WALLPAPERS_AND_ICONS"))
        [System.IO.File]::WriteAllBytes((Join-Path $corosDir 'HIBER.DAT'), [System.Text.Encoding]::ASCII.GetBytes("COROS_HIBER_FAST_STARTUP_SNAPSHOT_V2"))
        py -3 (Join-Path $PSScriptRoot 'generate_elf.py')
        Write-Output "UEFI files staged under $espRoot."
        if ($MakeIso) {
            Write-Output "Generating bootable UEFI ISO image..."
            py -3 (Join-Path $PSScriptRoot 'make-iso.py')
        }
    }
    elseif ($MakeIso) {
        Write-Output "Generating bootable UEFI ISO image from existing staging..."
        py -3 (Join-Path $PSScriptRoot 'make-iso.py')
    }
}
finally {
    Pop-Location
}
