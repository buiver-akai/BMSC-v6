# Benchmarks

## 目的
1MiB のデータを暗号化/復号するスループットの目安を示します。

## 実行
```bash
python -m pip install -r requirements-prod.txt
python bench_aead.py
```

## 期待値（目安）
- **Prod (XChaCha20-Poly1305):**  数百 MiB/s クラス（環境依存。数 ms/1MiB）
- **Demo (HMAC-stream 教材版):** サンプル実装のため遅い（数秒/1MiB）

> 数値は CPU/メモリ/ビルドに依存します。比較の目的は「Prod が実運用速度」「Demo は内部学習用」という位置づけの可視化です。
