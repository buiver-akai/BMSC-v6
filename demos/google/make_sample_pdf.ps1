# demos\google\make_sample_pdf.ps1
$ErrorActionPreference = "Stop"

# BMSC-v6 直下に出力（この ps1 は BMSC-v6\demos\google\ にある想定）
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
# 日本語ファイル名をエンコーディング非依存で生成（"住民票_サンプル.pdf"）
# BMSC-v6\demos\google 直下に出力
$name    = ([char]0x4F4F)+([char]0x6C11)+([char]0x7968)+'_'+([char]0x30B5)+([char]0x30F3)+([char]0x30D7)+([char]0x30EB)+'.pdf'
$outPath = Join-Path $PSScriptRoot $name



# 最小構成のサンプルPDFを Base64 で埋め込み
# SHA-256: 22c4b27eabc1016aa3a74d53c3758d52e87fcea7d80e2def68b38aed9e799262
$base64 = @'
JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4K
ZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4K
ZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAg
MCAyMDAgMjAwXSAvQ29udGVudHMgNCAwIFIgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCA1
NSA+PgpzdHJlYW0KQlQgL0YxIDEyIFRmIDcyIDEyMCBUZCAoU2FtcGxlIFJlc2lkZW50IFJlY29y
ZCkgVGogRVQKZW5kc3RyZWFtCmVuZG9iagp4cmVmCjAgNQowMDAwMDAwMDAgNjU1MzUgZiAKMDAw
MDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwMDYyIDAwMDAwIG4gCjAwMDAwMDAxMTEgMDAwMDAgbiAK
MDAwMDAwMDIwNSAwMDAwMCBuIAp0cmFpbGVyCjw8IC9Sb290IDEgMCBSIC9TaXplIDUgPj4Kc3Rh
cnR4cmVmCjI5MAolJUVPRgo=
'@

[IO.File]::WriteAllBytes($outPath, [Convert]::FromBase64String(($base64 -replace '\s','')))
$hash = (Get-FileHash -Algorithm SHA256 $outPath).Hash
Write-Host "Wrote: $outPath"
Write-Host "SHA-256: $hash"
