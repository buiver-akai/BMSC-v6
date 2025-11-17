import argparse, os, base64, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bmsc_v6 import bmsc_v6_encrypt, bmsc_v6_decrypt

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

def read_key(key_hex: str|None, key_file: str|None) -> bytes:
    if key_hex:  return bytes.fromhex(key_hex)
    if key_file: return Path(key_file).read_bytes()
    k = os.urandom(32)
    print("※ 鍵が未指定なので 32B ランダム鍵を生成しました（HEX 下に出力）")
    print("KEY(HEX):", k.hex())
    return k

def cmd_selftest(args):
    K  = os.urandom(32)
    IV = args.iv.encode("utf-8")
    pt = b"hello"
    n,c,t = bmsc_v6_encrypt(pt, K, IV)
    assert bmsc_v6_decrypt(n,c,t,K,IV) == pt
    bad = bytearray(c); bad[0] ^= 1
    try: bmsc_v6_decrypt(n,bytes(bad),t,K,IV); print("❌ tamper undetected")
    except ValueError: print("✅ tamper detected")
    print("✅ selftest OK (demo)")

def cmd_encrypt(args):
    K  = read_key(args.key_hex, args.key_file)
    IV = args.iv.encode("utf-8")
    if args.text is not None: pt = args.text.encode("utf-8")
    elif args.in_file:       pt = Path(args.in_file).read_bytes()
    else: print("入力がありません。--text か --in-file を指定してください。", file=sys.stderr); sys.exit(2)
    aad = args.aad.encode("utf-8") if args.aad else b""
    n,c,t = bmsc_v6_encrypt(pt, K, IV, aad=aad)
    print("KEY(HEX):", K.hex())
    print("IV(text):", args.iv)
    print("NONCE(Base64):", b64e(n))
    print("CT(Base64):", b64e(c))
    print("TAG(Base64):", b64e(t))

def cmd_decrypt(args):
    K  = read_key(args.key_hex, args.key_file)
    IV = args.iv.encode("utf-8")
    try:
        n = b64d(args.nonce_b64); c = b64d(args.ct_b64); t = b64d(args.tag_b64)
    except Exception as e:
        print("Base64 の入力が不正です:", e, file=sys.stderr); sys.exit(2)
    aad = args.aad.encode("utf-8") if args.aad else b""
    try:
        pt = bmsc_v6_decrypt(n, c, t, K, IV, aad=aad)
    except ValueError:
        print("復号失敗（鍵/IV/nonce/TAG/AAD を確認）。", file=sys.stderr); sys.exit(1)
    try:    print("PLAINTEXT(utf-8):", pt.decode("utf-8"))
    except UnicodeDecodeError:
            print("PLAINTEXT(hex):", pt.hex())

def build():
    p = argparse.ArgumentParser(prog="bmsc_demo", description="BMSC v6 CLI (demo/HMAC-stream)")
    sub = p.add_subparsers(dest="cmd", required=True)
    def common(sp):
        sp.add_argument("--iv",  default="20251029", help="用途識別のIV（任意文字列）")
        sp.add_argument("--aad", default="",         help="追加認証データ")
        sp.add_argument("--key-hex",  help="32B鍵のHEX")
        sp.add_argument("--key-file", help="鍵ファイル（32B）")
    s = sub.add_parser("selftest", help="自己診断"); common(s); s.set_defaults(func=cmd_selftest)
    s = sub.add_parser("encrypt",  help="暗号化");   common(s)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--text"); g.add_argument("--in-file")
    s.set_defaults(func=cmd_encrypt)
    s = sub.add_parser("decrypt",  help="復号");     common(s)
    s.add_argument("--nonce-b64", required=True); s.add_argument("--ct-b64", required=True); s.add_argument("--tag-b64", required=True)
    s.set_defaults(func=cmd_decrypt)
    return p

def main(argv=None):
    args = build().parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
