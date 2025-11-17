# tests/run_cli_roundtrip.ps1
# Round-trip test that parses the "Wrote: <path>.pdf" line (no JP literals in script)

param(
  [string]$Python = "py"  # 例: -Python python
)

$ErrorActionPreference = "Stop"

# --- Paths ---
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir  = Split-Path -Path $scriptPath -Parent
$root       = (Resolve-Path -Path (Join-Path -Path $scriptDir -ChildPath "..")).Path
$demos      = Join-Path -Path $root -ChildPath "demos\google"

Write-Host "root : $root"
Write-Host "demos: $demos"

# --- 1) Make sample PDF ---
Write-Host "== 1) make sample PDF =="
$makePdf = Join-Path -Path $demos -ChildPath "make_sample_pdf.ps1"

# 出力をキャプチャして "Wrote: <...>.pdf" を抜く
$outLines = & powershell -NoProfile -ExecutionPolicy Bypass -File $makePdf 2>&1
$outLines | Out-Host

$match = $outLines | Select-String -Pattern '^Wrote:\s+(.+\.pdf)$'
if (-not $match) {
  # フォールバック：ディレクトリから最新 *.pdf を拾う
  $srcPdfItem = Get-ChildItem -Path $demos -Filter *.pdf -File |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $srcPdfItem) { throw "No PDF found under $demos" }
  $srcPdf = $srcPdfItem.FullName
} else {
  $srcPdf = $match.Matches[0].Groups[1].Value
}

if (-not (Test-Path -LiteralPath $srcPdf)) { throw "Source PDF not found: $srcPdf" }
Write-Host "srcPdf: $srcPdf"

# --- 2) Encrypt to .bmsc6 (ctx/aad embedded) ---
Write-Host "== 2) encrypt (.bmsc6 v2) =="
Push-Location $root
& $Python (Join-Path -Path $demos -ChildPath "drive_encrypt.py") | Out-Host
Pop-Location

# 直近の .bmsc6 を取得
$encItem = Get-ChildItem -Path $demos -Filter *.bmsc6 -File |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $encItem) { throw "No .bmsc6 found under $demos" }
$encFile = $encItem.FullName
Write-Host "encFile: $encFile"

# --- 3) Decrypt (ctx/aad are embedded) ---
Write-Host "== 3) decrypt-file =="
$keyFile = Join-Path -Path $demos -ChildPath "key_drive.bin"
$outPdf  = Join-Path -Path $demos -ChildPath "decoded.pdf"

& $Python -m apps.cli.bmsc_prod decrypt-file `
  --key-file $keyFile `
  --in-enc-file $encFile `
  --out $outPdf | Out-Host

if (-not (Test-Path -LiteralPath $outPdf)) { throw "Decrypted PDF not found: $outPdf" }
Write-Host "outPdf: $outPdf"

# --- 4) Hash compare ---
Write-Host "== 4) hash compare =="
$h1 = (Get-FileHash -Algorithm SHA256 -LiteralPath $srcPdf).Hash.ToLower()
$h2 = (Get-FileHash -Algorithm SHA256 -LiteralPath $outPdf).Hash.ToLower()
Write-Host "src: $h1"
Write-Host "out: $h2"

if ($h1 -ne $h2) { throw "❌ SHA256 mismatch" }
Write-Host "✅ Round-trip OK (SHA256 matched)"
