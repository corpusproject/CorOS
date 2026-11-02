# CorOS İkon İşleme ve BMP Dönüştürücü (128x128 Şeffaf Squircle)
# Gemini / internetten indirdiğiniz PNG veya JPG dosyalarını otomatik olarak:
# 1. 128x128 çözünürlüğe ölçekler
# 2. Arka plandaki siyah/koyu kenarları temizler (Apple squircle maskesi uygular)
# 3. CorOS uyumlu 32-bit şeffaf BMP formatına dönüştürür.

Add-Type -AssemblyName System.Drawing

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$iconsDir = Join-Path $repoRoot "assets\icons"

if (-not (Test-Path $iconsDir)) {
    New-Item -ItemType Directory -Path $iconsDir -Force | Out-Null
}

function Convert-ToCleanBmp {
    param(
        [string]$inputPath,
        [string]$outputPath
    )

    Write-Host "==> İşleniyor: $([System.IO.Path]::GetFileName($inputPath)) -> $([System.IO.Path]::GetFileName($outputPath))" -ForegroundColor Cyan
    
    $origBmp = [System.Drawing.Bitmap]::FromFile($inputPath)
    $targetSize = 128
    $destBmp = [System.Drawing.Bitmap]::new($targetSize, $targetSize, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    
    $g = [System.Drawing.Graphics]::FromImage($destBmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    # Squircle Kavisli Köşe Yolu (Apple Maskesi)
    $radius = 28
    $diameter = $radius * 2
    $rect = [System.Drawing.Rectangle]::new(0, 0, $targetSize, $targetSize)
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    
    $path.AddArc($rect.X, $rect.Y, $diameter, $diameter, 180, 90)
    $path.AddArc($rect.Right - $diameter, $rect.Y, $diameter, $diameter, 270, 90)
    $path.AddArc($rect.Right - $diameter, $rect.Bottom - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()

    # Maskeyi sınır olarak uygula (Dıştaki siyah arka planı kırpar)
    $g.SetClip($path)
    $g.DrawImage($origBmp, 0, 0, $targetSize, $targetSize)
    $g.ResetClip()

    # İnce parlak kenarlık ekle
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(40, 255, 255, 255), 1.5)
    $g.DrawPath($pen, $path)

    $g.Dispose()
    $origBmp.Dispose()

    # BMP olarak kaydet
    $destBmp.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
    $destBmp.Dispose()
    Write-Host "    [OK] 128x128 Şeffaf Squircle BMP başarıyla oluşturuldu!" -ForegroundColor Green
}

# Klasördeki PNG/JPG dosyalarını tara ve eşleşen isimlere göre dönüştür
$files = Get-ChildItem -Path "$iconsDir\*" -Include *.png, *.jpg, *.jpeg, *.webp -File
if ($files.Count -eq 0) {
    Write-Host "`n[BİLGİ] 'assets\icons' klasöründe dönüştürülecek .png / .jpg görsel bulunamadı." -ForegroundColor Yellow
    Write-Host "Gemini'den indirdiğiniz görselleri (örn: finder.png, terminal.png) bu klasöre atıp tekrar çalıştırın.`n" -ForegroundColor Gray
} else {
    foreach ($file in $files) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $bmpPath128 = Join-Path $iconsDir "$baseName.bmp"
        $bmpPath40 = Join-Path $iconsDir "${baseName}_40.bmp"
        
        # 128x128
        Convert-ToCleanBmp -inputPath $file.FullName -outputPath $bmpPath128
        
        # 40x40 (Dock için ultra keskin piksel uyumu)
        $origBmp = [System.Drawing.Bitmap]::FromFile($bmpPath128)
        $destBmp40 = [System.Drawing.Bitmap]::new(40, 40, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g40 = [System.Drawing.Graphics]::FromImage($destBmp40)
        $g40.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g40.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g40.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g40.DrawImage($origBmp, 0, 0, 40, 40)
        $g40.Dispose()
        $origBmp.Dispose()
        $destBmp40.Save($bmpPath40, [System.Drawing.Imaging.ImageFormat]::Bmp)
        $destBmp40.Dispose()
        Write-Host "    [OK] 40x40 Dock BMP oluşturuldu: ${baseName}_40.bmp" -ForegroundColor Green
    }
}
