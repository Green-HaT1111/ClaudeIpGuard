# Draws the app icon (indigo shield with a globe-check mark) and writes a multi-size .ico.
param([string]$Out = "$PSScriptRoot\..\src\ClaudeIpGuard\Assets\app.ico")

Add-Type -AssemblyName System.Drawing

function New-ShieldPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 32.0

    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddLine(16*$s, 1*$s, 29*$s, 6*$s)
    $path.AddLine(29*$s, 6*$s, 29*$s, 15*$s)
    $path.AddBezier(29*$s, 15*$s, 29*$s, 23*$s, 23*$s, 28*$s, 16*$s, 31*$s)
    $path.AddBezier(16*$s, 31*$s, 9*$s, 28*$s, 3*$s, 23*$s, 3*$s, 15*$s)
    $path.AddLine(3*$s, 15*$s, 3*$s, 6*$s)
    $path.CloseFigure()

    $rect = New-Object System.Drawing.RectangleF 0, 0, $size, $size
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect,
        ([System.Drawing.Color]::FromArgb(99, 102, 241)), ([System.Drawing.Color]::FromArgb(67, 56, 202)), 60
    $g.FillPath($brush, $path)

    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([Math]::Max(1.5, 3.2*$s))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $pts = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF (10*$s), (16*$s)),
        (New-Object System.Drawing.PointF (14.5*$s), (20.5*$s)),
        (New-Object System.Drawing.PointF (22*$s), (11*$s)))
    $g.DrawLines($pen, $pts)
    $g.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = foreach ($sz in $sizes) { ,(New-ShieldPng $sz) }

New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
$fs = [System.IO.File]::Create($Out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]; $data = $images[$i]
    $dim = if ($sz -ge 256) { 0 } else { $sz }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$data.Length); $bw.Write([uint32]$offset)
    $offset += $data.Length
}
foreach ($data in $images) { $bw.Write($data) }
$bw.Close()
Write-Host "Icon written to $Out"
