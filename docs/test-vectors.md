# Sample Outputs (for reference only)

> **注意**: BMSC は毎回ランダム nonce を生成するため、**CT/TAG は毎回変わります**。以下は**参考例（再現用ではない）**です。固定テストベクタが必要なら、テスト限定で nonce 指定オプションを追加してください。

## Text Example
```
Command:
py -m apps.cli.bmsc_prod encrypt `
  --key-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f `
  --iv "BMSCv6-IV00" `
  --text "テスト"

Sample output (will vary):
NONCE(Base64): kLwFiRSU9IJf9FPhsk+ig1fFMeuJUwh/
CT(Base64):     RhLApbax3O1w
TAG(Base64):    OUDUjYoxZqgkC4h9NIWtZA==
```

## PDF Example (demos/google)
```
Input: 住民票_サンプル.pdf (SHA-256: 320aa9...b87f)

Sample output (will vary):
NONCE(Base64): sTls2FpuKJt14uGBoDW3gmLPLKOn9TU4
CT(Base64):     tJ3/.../Ov8=
TAG(Base64):    H4RnLNbdYkxeI47NScyBBg==

AAD (JSON):
{"name":"住民票_サンプル.pdf","size":473,"sha256":"320aa91306698be3fc7e7d44b96999f7fa960bf05cf9d0145519834d7298b87f"}
```
