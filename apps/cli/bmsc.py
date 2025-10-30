# apps/cli/bmsc.py — BMSC v6 簡易CLI
# 使い方（プロジェクトのルートで実行）:
#   py -m apps.cli.bmsc selftest
#   py -m apps.cli.bmsc encrypt --text "機密データ：発注番号12345" --iv "BMSCv6-IV00"
#   py -m apps.cli.bmsc decrypt --nonce-b64 <...> --ct-b64 <...> --tag-b64 <...> --iv "BMSCv6-IV00" --key-hex <...>

import argparse, os, base64, sys
from typing import Optional
from pathlib import Path

# ルートを import パスに追加（bmsc_v6.py を見つけるため）
ROOT = Path(__file__).resolve().parents[2]  # ...\python_app
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bmsc_v6 import bmsc_v6_encrypt, bmsc_v6_decrypt  # メインコード

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def read_key(key_hex: Optional[str], key_file: Optional[str]) -> bytes:
    if key_hex:
        return bytes.fromhex(key_hex)
    if key_file:
        return Path(key_file).read_bytes()
    # 指定が無ければランダム生成して表示
    k = os.urandom(32)
    print("※ 鍵が未指定なので 32B ランダム鍵を生成しました（HEX 下に出力）")
    print("KEY(HEX):", k.hex())
    return k

def cmd_selftest(args: argparse.Namespace) -> None:
    K  = os.urandom(32)
    IV = args.iv.encode("utf-8")
    pt = "hello 🍋".encode("utf-8")

    nonce, ct, tag = bmsc_v6_encrypt(pt, K, IV)
    assert bmsc_v6_decrypt(nonce, ct, tag, K, IV) == pt

    # 改ざん検知
    bad = bytearray(ct); bad[0] ^= 1
    try:
        bmsc_v6_decrypt(nonce, bytes(bad), tag, K, IV)
        print("❌ tamper undetected")  # ここに来たらNG
    except ValueError:
        print("✅ tamper detected")

    # ノンス違いで出力が変わる
    n2, c2, t2 = bmsc_v6_encrypt(pt, K, IV)
    print("✅ different output with new nonce:", (c2 != ct) or (t2 != tag))
    print("✅ selftest OK")

def cmd_encrypt(args: argparse.Namespace) -> None:
    K  = read_key(args.key_hex, args.key_file)
    IV = args.iv.encode("utf-8")

    if args.text is not None:
        pt = args.text.encode("utf-8")
    elif args.in_file:
        pt = Path(args.in_file).read_bytes()
    else:
        print("入力がありません。--text か --in-file を指定してください。", file=sys.stderr)
        sys.exit(2)

    aad = args.aad.encode("utf-8") if args.aad else b""
    nonce, ct, tag = bmsc_v6_encrypt(pt, K, IV, aad=aad)

    print("KEY(HEX):", K.hex())
    print("IV(text):", args.iv)
    print("NONCE(Base64):", b64e(nonce))
    print("CT(Base64):", b64e(ct))
    print("TAG(Base64):", b64e(tag))

def cmd_decrypt(args: argparse.Namespace) -> None:
    K  = read_key(args.key_hex, args.key_file)
    IV = args.iv.encode("utf-8")

    try:
        nonce = b64d(args.nonce_b64)
        ct    = b64d(args.ct_b64)
        tag   = b64d(args.tag_b64)
    except Exception as e:
        print("Base64 の入力が不正です:", e, file=sys.stderr)
        sys.exit(2)

    aad = args.aad.encode("utf-8") if args.aad else b""
    try:
        pt = bmsc_v6_decrypt(nonce, ct, tag, K, IV, aad=aad)
    except ValueError:
        print("復号失敗（鍵/IV/nonce/TAG/AAD を確認）。", file=sys.stderr)
        sys.exit(1)

    # UTF-8 として表示、失敗したらHEXで
    try:
        print("PLAINTEXT(utf-8):", pt.decode("utf-8"))
    except UnicodeDecodeError:
        print("PLAINTEXT(hex):", pt.hex())

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bmsc", description="BMSC v6 CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # 共通: --iv, --aad, --key-hex/--key-file
    def add_common(sp):
        sp.add_argument("--iv", default="BMSCv6-IV00", help="IV（テキスト。用途識別子として固定可）")
        sp.add_argument("--aad", default="", help="追加認証データ（任意）")
        sp.add_argument("--key-hex", help="32B鍵のHEX")
        sp.add_argument("--key-file", help="鍵ファイル（32B）")

    sp = sub.add_parser("selftest", help="自己診断（改ざん検知/ノンス差異）")
    add_common(sp)
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("encrypt", help="暗号化")
    add_common(sp)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="平文テキスト（UTF-8）")
    g.add_argument("--in-file", help="平文バイナリのパス")
    sp.set_defaults(func=cmd_encrypt)

    sp = sub.add_parser("decrypt", help="復号")
    add_common(sp)
    sp.add_argument("--nonce-b64", required=True, help="Nonce(Base64)")
    sp.add_argument("--ct-b64",    required=True, help="Ciphertext(Base64)")
    sp.add_argument("--tag-b64",   required=True, help="Tag(Base64)")
    sp.set_defaults(func=cmd_decrypt)

    return p

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
