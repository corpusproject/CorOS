[CmdletBinding()]
param(
    [string] $VMName = "COROS",
    [switch] $Rebuild,
    [switch] $Headless,
    [switch] $TailSerial,
    [switch] $Iso
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) { $env:PATH = "$cargoBin;$env:PATH" }

# 1. VirtualBox kontrolü
$vboxPaths = @(
    "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    (Get-Command VBoxManage -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
)
$vboxExe = $vboxPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $vboxExe) {
    throw "HATA: VirtualBox (VBoxManage.exe) bulunamadı! Lütfen Oracle VM VirtualBox'ın kurulu olduğundan emin olun."
}

Write-Host "==> VirtualBox tespit edildi: $vboxExe" -ForegroundColor Cyan

# 2. Rust/Cargo kontrolü ve derleme
$hasCargo = (Get-Command cargo -ErrorAction SilentlyContinue)
if (-not $hasCargo) {
    Write-Host "`n[UYARI] Sistemde 'cargo' / 'rustc' tespit edilemedi!" -ForegroundColor Yellow
    Write-Host "CorOS ikili dosyalarını (corboot.efi ve corkernel.efi) derlemek için Rust kurulu olmalıdır." -ForegroundColor Yellow
    Write-Host "Kurulum için: winget install Rustlang.Rustup ve ardından:" -ForegroundColor Gray
    Write-Host "rustup target add x86_64-unknown-uefi`n" -ForegroundColor Gray
}

$buildScript = Join-Path $PSScriptRoot "build.ps1"
$distDir = Join-Path $repoRoot "dist"
$espDir = Join-Path $distDir "esp"
$bootEfi = Join-Path $espDir "EFI\BOOT\BOOTX64.EFI"
$kernelEfi = Join-Path $espDir "EFI\COROS\CORKERNEL.EFI"

if ($Rebuild -or (-not (Test-Path $bootEfi)) -or (-not (Test-Path $kernelEfi))) {
    if (-not $hasCargo) {
        throw "EFI dosyaları mevcut değil ve Cargo kurulu olmadığı için derlenemiyor."
    }
    Write-Host "==> CorOS derleniyor ve EFI dosyaları hazırlanıyor..." -ForegroundColor Cyan
    & $buildScript -StageEfiFiles
    if ($LASTEXITCODE -ne 0) {
        throw "Derleme başarısız oldu!"
    }
}

# 3. Çalışan VM varsa durdur ve diski ayır
$distDir = Join-Path $repoRoot "dist"
$vdiFile = Join-Path $distDir "coros.vdi"
try {
    & $vboxExe controlvm $VMName poweroff 2>$null
    Start-Sleep -Milliseconds 500
} catch {}
try {
    & $vboxExe storageattach $VMName --storagectl "SATA" --port 0 --device 0 --type hdd --medium none 2>$null
    & $vboxExe closemedium disk $vdiFile 2>$null
} catch {}

# 4. FAT32 ve VDI Disk İmajı Oluşturma
Write-Host "==> FAT32 ve VDI disk imajı oluşturuluyor..." -ForegroundColor Cyan
$makeDiskScript = Join-Path $PSScriptRoot "make-vbox-disk.py"
$imgFile = Join-Path $distDir "coros.img"

& py $makeDiskScript $espDir $imgFile
if (-not (Test-Path $vdiFile)) {
    throw "VDI disk imajı oluşturulamadı: $vdiFile"
}

# 4. Çıktı ve Log dizini
$outputDir = Join-Path $repoRoot "outputs"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
$serialLog = Join-Path $outputDir "serial.log"
# Eski logu temizle veya sıfırla
Set-Content -Path $serialLog -Value "" -Force

# 5. VirtualBox Sanal Makine Yapılandırması
$existingVMs = & $vboxExe list vms
$vmExists = $existingVMs -match """$VMName"""

if (-not $vmExists) {
    Write-Host "==> '$VMName' sanal makinesi oluşturuluyor..." -ForegroundColor Cyan
    & $vboxExe createvm --name $VMName --ostype "Other_64" --register
}

Write-Host "==> '$VMName' sanal makinesi UEFI ve COM1 için yapılandırılıyor..." -ForegroundColor Cyan
# UEFI 64-bit modunu aktif et
& $vboxExe modifyvm $VMName --firmware efi64
& $vboxExe modifyvm $VMName --memory 2048
& $vboxExe modifyvm $VMName --cpus 4
& $vboxExe modifyvm $VMName --graphicscontroller vmsvga
& $vboxExe modifyvm $VMName --mouse ps2
& $vboxExe modifyvm $VMName --keyboard ps2

# COM1 Seri Portunu dosya yönlendirmesiyle aktifleştir (CorKernel logları için)
& $vboxExe modifyvm $VMName --uart1 0x3F8 4
& $vboxExe modifyvm $VMName --uart-type1 16550A
& $vboxExe modifyvm $VMName --uart-mode1 file $serialLog

# Depolama denetleyicisi ve VDI diski bağlama
$vmInfo = & $vboxExe showvminfo $VMName --machinereadable
$hasSata = $vmInfo -match 'storagecontrollername\d+="SATA"'
if (-not $hasSata) {
    & $vboxExe storagectl $VMName --name "SATA" --add sata --controller IntelAhci --portcount 2
}

# VDI diskini güncellemeden önce varsa eski bağlantıyı ayır
try {
    & $vboxExe storageattach $VMName --storagectl "SATA" --port 0 --device 0 --type hdd --medium none 2>$null
} catch {}

# VirtualBox ortam kayıt defterindeki eski VDI UUID'sini temizle
try {
    & $vboxExe closemedium disk $vdiFile 2>$null
} catch {}

# Yeni VDI'ı SATA Port 0'a bağla
& $vboxExe storageattach $VMName --storagectl "SATA" --port 0 --device 0 --type hdd --medium $vdiFile

$isoFile = Join-Path $distDir "coros.iso"
if ($Iso) {
    if ($Rebuild -or (-not (Test-Path $isoFile))) {
        Write-Host "==> CorOS Bootable ISO oluşturuluyor..." -ForegroundColor Cyan
        & py (Join-Path $PSScriptRoot "make-iso.py") $espDir $isoFile
    }
    Write-Host "==> ISO imajı DVD sürücüsüne takılıyor: $isoFile" -ForegroundColor Cyan
    try {
        & $vboxExe storageattach $VMName --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium none 2>$null
    } catch {}
    & $vboxExe storageattach $VMName --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium $isoFile
    & $vboxExe modifyvm $VMName --boot1 dvd --boot2 disk
}

Write-Host "==> Sanal makine hazır: $VMName" -ForegroundColor Green
Write-Host "    - Firmware: UEFI x86_64" -ForegroundColor Gray
Write-Host "    - Disk: $vdiFile" -ForegroundColor Gray
if ($Iso) {
    Write-Host "    - DVD (ISO): $isoFile" -ForegroundColor Gray
}
Write-Host "    - Seri Port (COM1): $serialLog" -ForegroundColor Gray

# 6. Sanal Makineyi Başlat
$vmType = if ($Headless) { "headless" } else { "gui" }
Write-Host "`n==> VirtualBox başlatılıyor ($vmType modu)..." -ForegroundColor Cyan
Write-Host " [İPUCU] Fare ve klavyeyi kullanmak için VM penceresinin içine tıklayın (Mouse Capture)." -ForegroundColor Yellow
Write-Host " [İPUCU] Fare imlecini sanal makineden kurtarmak için Sağ Ctrl (Host Key) tuşuna basın.`n" -ForegroundColor Yellow
& $vboxExe startvm $VMName --type $vmType

if ($TailSerial) {
    Write-Host "==> COM1 Seri Port çıktısı dinleniyor (Çıkış için Ctrl+C)..." -ForegroundColor Yellow
    Get-Content -Path $serialLog -Wait
}
