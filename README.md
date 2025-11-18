# BMSC v6: Secure Natural Language Stream Cipher

World's first secure natural language stream cipher. Multilingual, nonce-protected, ChatGPT-audited. PoC welcome!  
MIT / Test vectors / CLI included.

## Quick Start (Python)

### Windows (PowerShell)

```powershell
cd BMSC-v6
py -m pip install -r requirements-prod.txt

# 動作確認
py -m apps.cli.bmsc_prod selftest
```

macOS/Linux:

```bash
cd BMSC-v6
python3 -m pip install -r requirements-prod.txt

# 動作確認
python3 -m apps.cli.bmsc_prod selftest
```

## CLI (Prod / XChaCha20-Poly1305)

※ 実運用では --key-file を推奨します（鍵を履歴に残さないため）。

```powershell
# 例: テキストを暗号化
py -m apps.cli.bmsc_prod encrypt `
  --key-file .\key_cli.bin `
  --iv "BMSCv6-IV00" `
  --text "機密データ：発注番号12345"

# 例: 復号（上の出力 NONCE/CT/TAG を貼る）
py -m apps.cli.bmsc_prod decrypt `
  --key-file .\key_cli.bin `
  --iv "BMSCv6-IV00" `
  --nonce-b64 "NONCE_BASE64" `
  --ct-b64    "CT_BASE64" `
  --tag-b64   "TAG_BASE64"
```

## CLI (Demo / HMAC-stream, educational)

```powershell
py -m apps.cli.bmsc selftest
py -m apps.cli.bmsc encrypt --text "教材デモ" --iv "20251029"
```

## Security

- Prod: AEAD (XChaCha20-Poly1305) + HKDF で鍵分離。AAD で文脈（コンテキスト）をタグにバインド。
- Demo: HMAC-stream + Encrypt-then-MAC（教材用。実運用は Prod を使用）。

## Google Demos

See demos/google/README.md.

## BMSC6 ファイル形式（v2）

- ヘッダ: `MAGIC="BMSC6\0"(6B)` + `ver(1)=2` + `flags(1)=0`
- 長さ: `ctx_len(2, BE)` + `aad_len(4, BE)`
- 本体: `ctx(ctx_len)` + `aad(aad_len)` + `nonce(24)` + `tag(16)` + `ct(可変)`

ctx は用途識別の**コンテキスト文字列**（暗号 nonce ではない）。  
aad は JSON など任意のバイト列（復号時の同一性検証に使う）。

### 使い方（自己完結 bmsc6 v2）

```powershell
# サンプルPDF生成
.\demos\google\make_sample_pdf.ps1

# 暗号化（bmsc6 v2 と raw を生成）
py .\demos\google\drive_encrypt.py

# 復号（ctx/aad は bmsc6 内に内包されているので追加引数不要）
py -m apps.cli.bmsc_prod decrypt-file `
  --key-file .\demos\google\key_drive.bin `
  --in-enc-file .\demos\google\住民票_encrypted.bmsc6 `
  --out .\demos\google\復号_住民票.pdf

# ハッシュ一致確認（同じならOK）
Get-FileHash -Algorithm SHA256 .\demos\google\住民票_サンプル.pdf
Get-FileHash -Algorithm SHA256 .\demos\google\復号_住民票.pdf
```

## Security Notes

- **SHA-256 は“ハッシュ（要約値）”であって鍵ではありません。**  
  同一の入力からは常に同じ値が出ます。不可逆変換ですが、**秘密鍵の代わりにはなりません。**

- **v2 では AEAD の AAD（追加認証データ）に、ファイル識別子やバージョン等の“文脈情報”をバインド**して取り違えを防ぎます。  
  AAD は“鍵ではない公開メタデータ”を置く場所です（機密値は置かない）。

- **鍵ファイルはランダム 32 バイトを推奨**（例：`os.urandom(32)` ）。Windows では作成直後に ACL を絞ってください。

```powershell
py - <<'PY'
import os; open('key_cli.bin','wb').write(os.urandom(32))
PY
icacls key_cli.bin /inheritance:r /grant:r "$env:USERNAME":F
```

## License

MIT © 赤井 英生
Developed by 赤井 英生 at 株式会社 BUIVER.
Commercial licensing: email akai@buiver.jp

## requirements-prod.txt（同梱推奨）

```text
PyNaCl==1.5.0
```

## BMSC-v6/LICENSE

```text
MIT License

Copyright (c) 2025 赤井 英生

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Key Management and Windows Key Protection

This section summarizes the recommended key handling policy for BMSC v6.

- For production use, prefer **`--key-file`** over `--key-hex`.  
  `--key-hex` and `--show-key` are mainly intended for local testing and debugging.
- Use **random 32‑byte binary keys** (e.g. `os.urandom(32)` in Python), and keep them out of Git or any VCS.
- On Windows, restrict the key file ACLs so that only **the current user and SYSTEM** can access it.
- See `windows_key_protection.md` (or `docs/ops/windows_key_protection.md` in this repo) for step‑by‑step commands.

Example for generating and protecting a key on Windows PowerShell:

```powershell
py - <<'PY'
import os; open('key_cli.bin','wb').write(os.urandom(32))
PY

icacls key_cli.bin /inheritance:r /grant:r "$env:USERNAME":F /grant:r "SYSTEM":F
```

Handle the key file with the same care as any other long‑term symmetric key
(no sharing over chat, no plain uploads, and avoid copying it to untrusted machines).
