# SECURITY

## Threat Model（想定する脅威）
- 攻撃者は暗号文（nonce/tag/ct）と、場合によっては AAD を取得可能
- 秘密鍵は安全に管理される（漏えい時は鍵ローテーションで対応）
- 改ざん・リプレイ・取り違えを防ぎたい

## 設計の要点
- **AEAD:** XChaCha20-Poly1305（libsodium/PyNaCl）で暗号化＋完全性
- **HKDF:** 用途ごとに鍵を分離（`bmsc_v6_prod` 内部）
- **Context（IV文字列）:** 用途識別のラベル。暗号nonceではない
- **AAD:** ファイル名・サイズ・平文の SHA-256 などをバインド（取り違え防止）
- **BMSC6 v2:** `ctx` と `aad` をファイルに内包（自己完結フォーマット）

## 推奨運用
- 鍵は **`--key-file`** を使用（履歴やログに残さない）
- Windows は作成直後に ACL を絞る：
  ```powershell
  py - <<'PY'
  import os; open('key_cli.bin','wb').write(os.urandom(32))
  PY
  icacls key_cli.bin /inheritance:r /grant:r "$env:USERNAME":F
  ```
- AAD に平文ハッシュを入れたくない場合は、**HMAC(key, 平文)** 等に置き換え
- リプレイ耐性が必要なメッセージ用途では、`aad` に `timestamp` と `message_id` を含め、検証側で未使用ID/許容時刻範囲をチェック

## 既知の制約
- `encrypt` は毎回ランダム nonce を生成 → **CT/TAG は毎回異なる**（安全設計）
- 「固定テストベクタ」が必要な場合は、**テスト専用で nonce 指定**の実装を追加（運用での使用は非推奨）
