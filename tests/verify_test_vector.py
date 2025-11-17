from pathlib import Path
import base64, json, sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bmsc_v6_prod import bmsc_v6_decrypt

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def main():
    if len(sys.argv) < 2:
        print("Usage: py tests/verify_test_vector.py tests/vectors/bmsc6_vector_1.json", file=sys.stderr)
        sys.exit(2)

    vecpath = Path(sys.argv[1])
    vec = json.loads(vecpath.read_text(encoding="utf-8"))

    K = bytes.fromhex(vec["key_hex"])
    ctx = vec["ctx"].encode("utf-8")
    aad = b64d(vec["aad_b64"])
    nonce = b64d(vec["nonce_b64"])
    ct = b64d(vec["ct_b64"])
    tag = b64d(vec["tag_b64"])
    pt_expected = vec["pt_utf8"].encode("utf-8")

    pt = bmsc_v6_decrypt(nonce, ct, tag, K, ctx, aad=aad)
    if pt == pt_expected:
        print("✅ verify OK")
    else:
        print("❌ verify FAIL")
        sys.exit(1)

if __name__ == "__main__":
    main()
