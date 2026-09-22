param(
    [string]$CsvPath
)

Add-Type -AssemblyName System.Drawing

function Render-Curve([string]$path) {
    if (-not (Test-Path $path)) {
        Write-Warning "Archivo no encontrado: $path"
        return
    }

    $lines = Get-Content $path
    $p = $null; $a = $null; $b = $null; $count = $null
    $points = @()

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed.Split(',')
        if ($parts[0] -eq '' -and $parts.Length -ge 3) {
            switch ($parts[1]) {
                'p' { $p = [int]$parts[2] }
                'a' { $a = [int]$parts[2] }
                'b' { $b = [int]$parts[2] }
                'count' { $count = [int]$parts[2] }
            }
        }
        elseif ($parts[0] -ne 'x' -and $parts.Length -ge 3) {
            $x = [int]$parts[0]
            $y = [int]$parts[1]
            $z = [int]$parts[2]
            if ($z -ne 0) {
                $points += ,@($x, $y)
            }
        }
    }

    $width = 900
    $height = 900
    $margin = 90

    $bmp = [System.Drawing.Bitmap]::new($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::White)

    $plotW = $width - 2 * $margin
    $plotH = $height - 2 * $margin

    $penAxis = [System.Drawing.Pen]::new([System.Drawing.Color]::Black, [float]2.0)
    $penGrid = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(235, 235, 235), [float]1.0)
    $brushPoint = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(31, 119, 180))
    $penPointBorder = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(15, 60, 90), [float]1.0)

    $fontTitle = [System.Drawing.Font]::new("Segoe UI", [float]14.0, [System.Drawing.FontStyle]::Bold)
    $fontSubtitle = [System.Drawing.Font]::new("Segoe UI", [float]10.0, [System.Drawing.FontStyle]::Regular)
    $fontTick = [System.Drawing.Font]::new("Segoe UI", [float]8.0, [System.Drawing.FontStyle]::Regular)
    $fontAxisLabel = [System.Drawing.Font]::new("Segoe UI", [float]10.0, [System.Drawing.FontStyle]::Bold)
    $brushText = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::Black)

    # Titulo
    $title = "Curva Eliptica E(Fp): y^2 = x^3 + ${a}x + ${b} (mod $p)"
    $subTitle = "Total puntos racionales: $count (incluyendo O=(0,1,0)) | Puntos afines graficados: $($points.Count)"
    $g.DrawString($title, $fontTitle, $brushText, [float]$margin, [float]25.0)
    $g.DrawString($subTitle, $fontSubtitle, $brushText, [float]$margin, [float]55.0)

    # Marco
    $g.DrawRectangle($penAxis, $margin, $margin, $plotW, $plotH)

    $step = if ($p -le 40) { 5 } elseif ($p -le 100) { 10 } elseif ($p -le 300) { 25 } else { 50 }
    for ($val = 0; $val -lt $p; $val += $step) {
        $px = $margin + ($val / ($p - 1)) * $plotW
        $py = $margin + $plotH - ($val / ($p - 1)) * $plotH
        # Lineas verticales
        $g.DrawLine($penGrid, [float]$px, [float]$margin, [float]$px, [float]($margin + $plotH))
        # Lineas horizontales
        $g.DrawLine($penGrid, [float]$margin, [float]$py, [float]($margin + $plotW), [float]$py)

        # Ticks texto X
        $g.DrawString("$val", $fontTick, $brushText, [float]($px - 8.0), [float]($margin + $plotH + 5.0))
        # Ticks texto Y
        $g.DrawString("$val", $fontTick, $brushText, [float]($margin - 30.0), [float]($py - 6.0))
    }

    # Etiquetas de ejes
    $g.DrawString("Coordenada x", $fontAxisLabel, $brushText, [float]($width / 2 - 40), [float]($height - 35))
    $g.DrawString("y", $fontAxisLabel, $brushText, [float]25.0, [float]($height / 2 - 10))

    # Graficar puntos
    $ptRadius = if ($p -le 40) { 5.0 } elseif ($p -le 100) { 4.0 } else { 3.0 }
    foreach ($pt in $points) {
        $xVal = $pt[0]
        $yVal = $pt[1]
        $cx = $margin + ($xVal / ($p - 1)) * $plotW
        $cy = $margin + $plotH - ($yVal / ($p - 1)) * $plotH

        $g.FillEllipse($brushPoint, [float]($cx - $ptRadius), [float]($cy - $ptRadius), [float]($ptRadius * 2.0), [float]($ptRadius * 2.0))
        $g.DrawEllipse($penPointBorder, [float]($cx - $ptRadius), [float]($cy - $ptRadius), [float]($ptRadius * 2.0), [float]($ptRadius * 2.0))
    }

    $outName = "grafica_" + [System.IO.Path]::GetFileNameWithoutExtension($path) + ".png"
    $bmp.Save($outName, [System.Drawing.Imaging.ImageFormat]::Png)

    $g.Dispose()
    $bmp.Dispose()
    Write-Host "[+] Grafica generada exitosamente: $outName ($($points.Count) puntos afines)"
}

if ($CsvPath) {
    Render-Curve $CsvPath
} else {
    Get-ChildItem -Filter "curva*.csv" | ForEach-Object { Render-Curve $_.FullName }
    if (Test-Path "puntos_mod31_a11_b5.csv") {
        Render-Curve "puntos_mod31_a11_b5.csv"
    }
}
