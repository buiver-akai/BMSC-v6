# demos/google

このフォルダは Google Drive 等に置く想定の**ファイル暗号デモ**一式です。

## 1) サンプルPDFの生成

```powershell
.\make_sample_pdf.ps1
```

- `BMSC-v6\demos\google\住民票_サンプル.pdf` が生成されます。

## 2) 暗号化（bmsc6 v2 と raw の両方を作成）

```powershell
py .\drive_encrypt.py
```

生成物：

- `住民票_encrypted.bin` …… `nonce|tag|ct` の生バイナリ
- `住民票_encrypted.bmsc6` …… **自己完結フォーマット（v2）**
- `住民票_encrypted.aad.json` …… AAD(JSON, name/size/sha256)
- `住民票_encrypted.meta.json` …… 参考メタ（nonce/tag など）
- `key_drive.bin` …… 32バイト鍵（未存在なら自動生成）

## 3) 復号

### 3-a) 自己完結 `.bmsc6` から復号

```powershell
py -m apps.cli.bmsc_prod decrypt-file `
  --key-file .\key_drive.bin `
  --in-enc-file .\住民票_encrypted.bmsc6 `
  --out .\復号_住民票.pdf
```

### 3-b) raw（nonce/tag/ct を直接与える場合）

```powershell
py -m apps.cli.bmsc_prod decrypt `
  --key-file .\key_drive.bin `
  --iv "BMSCv6-IV00" `
  --nonce-b64 "NONCE_BASE64" `
  --ct-b64    "CT_BASE64" `
  --tag-b64   "TAG_BASE64" `
  --aad-file  .\住民票_encrypted.aad.json
```

## 4) ハッシュ一致確認

```powershell
Get-FileHash -Algorithm SHA256 .\住民票_サンプル.pdf
Get-FileHash -Algorithm SHA256 .\復号_住民票.pdf
# ↑ 値が一致すればOK
```

> 注意：鍵ファイルは個人権限に絞って管理してください（Windows: `icacls`, Linux: `chmod 600`）。
