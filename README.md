# BMSC v6: Secure Natural Language Stream Cipher

World's first secure natural language stream cipher. Multilingual, nonce-protected, ChatGPT-audited. PoC welcome!
MIT / Test vectors / CLI included.

## Quick Start (Python)

Windows:

```bash
cd BMSC-v6
py demo.py
```

macOS/Linux:

```bash
cd BMSC-v6
python3 demo.py
```

このプロジェクトは 標準ライブラリのみで動きます（追加インストール不要）。

## CLI (Windows)

```bat
py -m apps.cli.bmsc selftest
py -m apps.cli.bmsc encrypt --text "機密データ：発注番号12345" --iv "BMSCv6-IV00"
py -m apps.cli.bmsc decrypt --nonce-b64 "<NONCE>" --ct-b64 "<CT>" --tag-b64 "<TAG>" --iv "BMSCv6-IV00" --key-hex <KEYHEX>
```

**置き換え注意**：<NONCE>/<CT>/<TAG>/<KEYHEX> は実際の値に置換してください。
**Windows の cmd.exe では < > を打つとエラー**になります。Base64 は**ダブルクォート**で囲んでください。

## Python API

```
import os
from bmsc_v6 import bmsc_v6_encrypt, bmsc_v6_decrypt

K = os.urandom(32)
IV = b"BMSCv6-IV00"
pt = "秘密".encode("utf-8")

nonce, ct, tag = bmsc_v6_encrypt(pt, K, IV)
assert bmsc_v6_decrypt(nonce, ct, tag, K, IV) == pt
```

## Security

Standard AEAD/HKDF wrapper. No novel claims.
v5 (demo): Educational only. v6 for production.

## Test Vectors

See /test-vectors and apps/cli (selftest).

## License

MIT © 赤井 英生

Developed by 赤井 英生 at 株式会社&nbsp;BUIVER.
Commercial licensing: DM @buiver-akai.
