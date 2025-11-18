# apps/cli/bmsc_prod.py
import argparse, os, base64, sys, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bmsc_v6_prod import bmsc_v6_encrypt, bmsc_v6_decrypt

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

MAGIC = b"BMSC6\x00"  # 6 bytes
NONCE_LEN = 24
TAG_LEN   = 16

def read_key(key_hex: str|None, key_file: str|None):
    """戻り値: (K: bytes, source: str)"""
    if key_hex:
        return bytes.fromhex(key_hex), "hex"
    if key_file:
        return Path(key_file).read_bytes(), "file"
    k = os.urandom(32)
    return k, "random"

def load_aad(args) -> bytes:
    """--aad-file があればそれを優先。無ければ --aad（文字列）"""
    if getattr(args, "aad_file", None):
        return Path(args.aad_file).read_text(encoding="utf-8").encode("utf-8")
    return (args.aad or "").encode("utf-8")

def cmd_selftest(args):
    K, _ = read_key(None, None)
    IV = args.iv.encode("utf-8")  # 用途識別の“コンテキスト”
    pt = "hello 🍋".encode("utf-8")
    n,c,t = bmsc_v6_encrypt(pt, K, IV)
    assert bmsc_v6_decrypt(n,c,t,K,IV) == pt
    bad = bytearray(c); bad[0] ^= 1
    try:
        bmsc_v6_decrypt(n,bytes(bad),t,K,IV)
        print("❌ tamper undetected")
    except ValueError:
        print("✅ tamper detected")
    print("✅ selftest OK (prod)")

def cmd_encrypt(args):
    K, source = read_key(args.key_hex, args.key_file)
    IV = args.iv.encode("utf-8")  # ※ nonce ではありません

    if args.text is not None:
        pt = args.text.encode("utf-8")
    elif args.in_file:
        pt = Path(args.in_file).read_bytes()
    else:
        print("入力がありません。--text か --in-file を指定してください。", file=sys.stderr)
        sys.exit(2)

    aad = load_aad(args)
    n,c,t = bmsc_v6_encrypt(pt, K, IV, aad=aad)

    show_key = bool(args.show_key or source == "hex")
    if source == "random":
        if show_key:
            print("※ 鍵が未指定なので 32B ランダム鍵を生成しました（HEX 下に出力）")
        else:
            print("※ 鍵が未指定なので 32B ランダム鍵を生成しました（HEX 非表示。--show-key で表示可）")

    if show_key:
        print("KEY(HEX):", K.hex())

    print("CONTEXT:", args.iv)
    print("NONCE(Base64):", b64e(n))
    print("CT(Base64):", b64e(c))
    print("TAG(Base64):", b64e(t))

def cmd_decrypt(args):
    K, source = read_key(args.key_hex, args.key_file)
    IV = args.iv.encode("utf-8")  # ※ nonce ではありません

    try:
        n = b64d(args.nonce_b64); c = b64d(args.ct_b64); t = b64d(args.tag_b64)
    except Exception as e:
        print("Base64 の入力が不正です:", e, file=sys.stderr)
        sys.exit(2)

    aad = load_aad(args)

    try:
        pt = bmsc_v6_decrypt(n, c, t, K, IV, aad=aad)
    except ValueError:
        print("復号失敗（鍵/IV/nonce/TAG/AAD を確認）。", file=sys.stderr)
        sys.exit(1)

    show_key = bool(args.show_key or source == "hex")
    if source == "random" and not show_key:
        print("※ 鍵が未指定なので 32B ランダム鍵を生成しました（HEX 非表示。--show-key で表示可）")
    if show_key:
        print("KEY(HEX):", K.hex())

    try:
        print("PLAINTEXT(utf-8):", pt.decode("utf-8"))
    except UnicodeDecodeError:
        print("PLAINTEXT(hex):", pt.hex())

def _parse_encrypted_blob(blob: bytes):
    """
    bmsc6(v1/v2) or raw を判定して分解する。
    返り値: (nonce, tag, ct, embedded_ctx_bytes|None, embedded_aad_bytes|None, ver|0)
      ver=0 は raw、ver=1/2 は bmsc6
    """
    if len(blob) >= 8 and blob[:6] == MAGIC:
        ver   = blob[6]
        flags = blob[7]
        off = 8
        if ver == 1:
            n = blob[off:off+NONCE_LEN]; off += NONCE_LEN
            t = blob[off:off+TAG_LEN];   off += TAG_LEN
            c = blob[off:]
            return n, t, c, None, None, 1
        elif ver >= 2:
            if len(blob) < off + 2 + 4:
                raise ValueError("bmsc6 v2 header too short")
            ctx_len = struct.unpack(">H", blob[off:off+2])[0]; off += 2
            aad_len = struct.unpack(">I", blob[off:off+4])[0]; off += 4
            if len(blob) < off + ctx_len + aad_len + NONCE_LEN + TAG_LEN:
                raise ValueError("bmsc6 v2 payload too short")
            ctx = blob[off:off+ctx_len]; off += ctx_len
            aad = blob[off:off+aad_len]; off += aad_len
            n = blob[off:off+NONCE_LEN]; off += NONCE_LEN
            t = blob[off:off+TAG_LEN];   off += TAG_LEN
            c = blob[off:]
            return n, t, c, ctx, aad, ver
        else:
            raise ValueError(f"unsupported bmsc6 version: {ver}")
    # raw: nonce|tag|ct
    n = blob[:NONCE_LEN]
    t = blob[NONCE_LEN:NONCE_LEN+TAG_LEN]
    c = blob[NONCE_LEN+TAG_LEN:]
    return n, t, c, None, None, 0

def cmd_decrypt_file(args):
    K, _ = read_key(args.key_hex, args.key_file)
    blob = Path(args.in_enc_file).read_bytes()
    n, t, c, ctx_b, aad_b, ver = _parse_encrypted_blob(blob)

    # CONTEXT の決定（v2 なら内包を優先）
    if ctx_b is not None:
        IV = ctx_b
        print("CONTEXT(from file):", IV.decode("utf-8", errors="replace"))
    else:
        IV = args.iv.encode("utf-8")
        print("CONTEXT(from args):", args.iv)

    # AAD の決定（v2 なら内包を優先。引数が明示されていればそれを使う）
    arg_aad = load_aad(args)
    if aad_b is not None and not arg_aad:
        aad = aad_b
        print("AAD: embedded (used)")
    else:
        aad = arg_aad
        print("AAD: from args/file (used)" if aad else "AAD: empty")

    try:
        pt = bmsc_v6_decrypt(n, c, t, K, IV, aad=aad)
    except ValueError:
        print("復号失敗（鍵/IV/nonce/TAG/AAD を確認）。", file=sys.stderr)
        sys.exit(1)

    if args.out:
        Path(args.out).write_bytes(pt)
        print("Wrote:", args.out)
    else:
        print("PLAINTEXT(hex):", pt.hex())

def build():
    p = argparse.ArgumentParser(prog="bmsc_prod", description="BMSC v6 CLI (prod/AEAD)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--iv",  default="BMSCv6-IV00",
                        help="用途識別のコンテキスト文字列（暗号nonceではない）")
        sp.add_argument("--ctx", dest="iv",
                        help="--iv の別名（用途識別のコンテキスト。暗号nonceではない）")
        sp.add_argument("--aad", default="",
                        help="追加認証データ（文字列）")
        sp.add_argument("--aad-file",
                        help="追加認証データのファイル（--aad より優先）")
        sp.add_argument("--key-hex",
                        help="32B鍵のHEX")
        sp.add_argument("--key-file",
                        help="鍵ファイル（32B）")
        sp.add_argument("--show-key", action="store_true",
                        help="キーを表示する（検証・デバッグ用。本番運用では通常は使用しない想定）")

    s = sub.add_parser("selftest", help="自己診断")
    common(s); s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("encrypt",  help="暗号化")
    common(s)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--text",    help="平文テキスト（UTF-8）")
    g.add_argument("--in-file", help="平文バイナリのパス")
    s.set_defaults(func=cmd_encrypt)

    s = sub.add_parser("decrypt",  help="復号")
    common(s)
    s.add_argument("--nonce-b64", required=True)
    s.add_argument("--ct-b64",    required=True)
    s.add_argument("--tag-b64",   required=True)
    s.set_defaults(func=cmd_decrypt)

    s = sub.add_parser("decrypt-file", help="ファイル復号（.bmsc6 v1/v2 または raw .bin 自動判別）")
    common(s)
    s.add_argument("--in-enc-file", required=True, help="暗号ファイル（.bmsc6 / .bin）")
    s.add_argument("--out", help="復号した平文の出力パス（未指定ならhex表示）")
    s.set_defaults(func=cmd_decrypt_file)

    return p

def main(argv=None):
    args = build().parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
