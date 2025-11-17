from pathlib import Path
import base64, json, hashlib, sys

# ルートを import パスに追加
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bmsc_v6_prod import bmsc_v6_encrypt, bmsc_v6_decrypt  # AEAD

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def main():
    # ★テスト専用の固定キー（実運用では使用厳禁）
    key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    K = bytes.fromhex(key_hex)
    ctx = b"BMSCv6-IV00"
    aad = "test-aad".encode("utf-8")
    pt_text = "Test vector: 日本語🍣"

    pt = pt_text.encode("utf-8")
    nonce, ct, tag = bmsc_v6_encrypt(pt, K, ctx, aad=aad)

    vec = {
        "algorithm": "XChaCha20-Poly1305",
        "ctx": "BMSCv6-IV00",
        "aad_b64": b64e(aad),
        "key_hex": key_hex,  # ←テスト用。Prodでは鍵をファイルで渡すこと
        "nonce_b64": b64e(nonce),
        "ct_b64": b64e(ct),
        "tag_b64": b64e(tag),
        "pt_utf8": pt_text,
        "pt_sha256": hashlib.sha256(pt).hexdigest(),
    }

    outdir = ROOT / "tests" / "vectors"
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / "bmsc6_vector_1.json"
    outfile.write_text(json.dumps(vec, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Wrote:", outfile)

if __name__ == "__main__":
    main()
