Add-Type -AssemblyName System.Drawing

$fontName = "Segoe UI"
$fontSize = 12.0
$font = New-Object System.Drawing.Font($fontName, [float]$fontSize, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$sf = New-Object System.Drawing.StringFormat([System.Drawing.StringFormat]::GenericTypographic)
$sf.FormatFlags = $sf.FormatFlags -bor [System.Drawing.StringFormatFlags]::MeasureTrailingSpaces

$bmp = New-Object System.Drawing.Bitmap 64, 32
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAlias

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("//! Ultra-Modern Anti-Aliased Segoe UI Font for CorOS")
[void]$sb.AppendLine("//! Zero-dependency bare-metal font table with subpixel alpha blending.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("#[derive(Clone, Copy)]")
[void]$sb.AppendLine("pub struct Glyph {")
[void]$sb.AppendLine("    pub width: u8,")
[void]$sb.AppendLine("    pub height: u8,")
[void]$sb.AppendLine("    pub x_offset: i8,")
[void]$sb.AppendLine("    pub y_offset: i8,")
[void]$sb.AppendLine("    pub advance: u8,")
[void]$sb.AppendLine("    pub data: &'static [u8],")
[void]$sb.AppendLine("}")
[void]$sb.AppendLine("")

function Rasterize-Char($c, $varName) {
    $g.Clear([System.Drawing.Color]::Black)
    $g.DrawString($c.ToString(), $font, [System.Drawing.Brushes]::White, 0, 0, $sf)
    $sz = $g.MeasureString($c.ToString(), $font, 100, $sf)
    
    $charMinX = 999; $charMaxX = -1; $charMinY = 999; $charMaxY = -1
    for ($y = 0; $y -lt 32; $y++) {
        for ($x = 0; $x -lt 64; $x++) {
            $lum = $bmp.GetPixel($x, $y).R
            if ($lum -gt 20) {
                if ($x -lt $charMinX) { $charMinX = $x }
                if ($x -gt $charMaxX) { $charMaxX = $x }
                if ($y -lt $charMinY) { $charMinY = $y }
                if ($y -gt $charMaxY) { $charMaxY = $y }
            }
        }
    }
    
    if ($charMaxX -lt 0 -or $c -eq ' ') {
        # Space or empty glyph
        $adv = [int][Math]::Max(3, [Math]::Round($sz.Width))
        [void]$sb.AppendLine("pub static ${varName}: Glyph = Glyph { width: 0, height: 0, x_offset: 0, y_offset: 0, advance: $adv, data: &[] };")
        return
    }
    
    $w = $charMaxX - $charMinX + 1
    $h = $charMaxY - $charMinY + 1
    $xOff = $charMinX
    $yOff = $charMinY - 2
    $adv = [int][Math]::Max($w + 1, [Math]::Round($sz.Width))
    
    # Collect bytes
    $bytes = @()
    for ($y = $charMinY; $y -le $charMaxY; $y++) {
        for ($x = $charMinX; $x -le $charMaxX; $x++) {
            $lum = $bmp.GetPixel($x, $y).R
            $bytes += $lum
        }
    }
    
    $dataStr = [string]::Join(", ", $bytes)
    [void]$sb.AppendLine("pub static ${varName}_DATA: [u8; $($bytes.Count)] = [$dataStr];")
    [void]$sb.AppendLine("pub static ${varName}: Glyph = Glyph { width: $w, height: $h, x_offset: $xOff, y_offset: $yOff, advance: $adv, data: &${varName}_DATA };")
}

# 1. ASCII 32 to 126
for ($code = 32; $code -le 126; $code++) {
    $c = [char]$code
    $varName = "GLYPH_$code"
    Rasterize-Char $c $varName
}

# 2. ASCII Glyphs array
[void]$sb.AppendLine("")
[void]$sb.AppendLine("pub static ASCII_GLYPHS: [Glyph; 95] = [")
for ($code = 32; $code -le 126; $code++) {
    [void]$sb.AppendLine("    GLYPH_$code,")
}
[void]$sb.AppendLine("];")
[void]$sb.AppendLine("")

# 3. Turkish Glyphs
$turkish = @(
    @{ Name = "GLYPH_TR_LOWER_C"; Char = [char]0x00E7 },
    @{ Name = "GLYPH_TR_UPPER_C"; Char = [char]0x00C7 },
    @{ Name = "GLYPH_TR_LOWER_G"; Char = [char]0x011F },
    @{ Name = "GLYPH_TR_UPPER_G"; Char = [char]0x011E },
    @{ Name = "GLYPH_TR_LOWER_I"; Char = [char]0x0131 },
    @{ Name = "GLYPH_TR_UPPER_I"; Char = [char]0x0130 },
    @{ Name = "GLYPH_TR_LOWER_O"; Char = [char]0x00F6 },
    @{ Name = "GLYPH_TR_UPPER_O"; Char = [char]0x00D6 },
    @{ Name = "GLYPH_TR_LOWER_S"; Char = [char]0x015F },
    @{ Name = "GLYPH_TR_UPPER_S"; Char = [char]0x015E },
    @{ Name = "GLYPH_TR_LOWER_U"; Char = [char]0x00FC },
    @{ Name = "GLYPH_TR_UPPER_U"; Char = [char]0x00DC }
)

foreach ($item in $turkish) {
    Rasterize-Char $item.Char $item.Name
}

# 4. Lookup and width functions
$helperCode = @'

pub fn get_glyph(c: char) -> Option<&'static Glyph> {
    match c {
        ' '..='~' => ASCII_GLYPHS.get((c as usize).saturating_sub(32)),
        '\u{00E7}' => Some(&GLYPH_TR_LOWER_C), // ç
        '\u{00C7}' => Some(&GLYPH_TR_UPPER_C), // Ç
        '\u{011F}' => Some(&GLYPH_TR_LOWER_G), // ğ
        '\u{011E}' => Some(&GLYPH_TR_UPPER_G), // Ğ
        '\u{0131}' => Some(&GLYPH_TR_LOWER_I), // ı
        '\u{0130}' => Some(&GLYPH_TR_UPPER_I), // İ
        '\u{00F6}' => Some(&GLYPH_TR_LOWER_O), // ö
        '\u{00D6}' => Some(&GLYPH_TR_UPPER_O), // Ö
        '\u{015F}' => Some(&GLYPH_TR_LOWER_S), // ş
        '\u{015E}' => Some(&GLYPH_TR_UPPER_S), // Ş
        '\u{00FC}' => Some(&GLYPH_TR_LOWER_U), // ü
        '\u{00DC}' => Some(&GLYPH_TR_UPPER_U), // Ü
        '\u{2014}' => ASCII_GLYPHS.get(('-' as usize).saturating_sub(32)), // —
        _ => ASCII_GLYPHS.get(('?' as usize).saturating_sub(32)),
    }
}

pub fn string_width(s: &str) -> usize {
    let mut w = 0;
    for c in s.chars() {
        if let Some(g) = get_glyph(c) {
            w += g.advance as usize;
        } else {
            w += 6;
        }
    }
    w
}
'@

[void]$sb.AppendLine($helperCode)

$outPath = Join-Path $PSScriptRoot "..\kernel\corkernel\src\font.rs"
[System.IO.File]::WriteAllText($outPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
Write-Host "Generated font.rs successfully at $outPath"

$g.Dispose()
$bmp.Dispose()
