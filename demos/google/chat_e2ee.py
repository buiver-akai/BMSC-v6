import sys, pathlib, os, base64
ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from bmsc_v6_prod import bmsc_v6_encrypt, bmsc_v6_decrypt

HERE = pathlib.Path(__file__).resolve().parent
key_path = HERE / "key_chat.bin"
if key_path.exists():
    K = key_path.read_bytes()
else:
    K = os.urandom(32); key_path.write_bytes(K); print(f"新規鍵生成 → {key_path.name}（HEX: {K.hex()}）")

IV  = b"BMSCv6-IV00"
msg = "こんにちは！ 全角です"

nonce, ct, tag = bmsc_v6_encrypt(msg.encode("utf-8"), K, IV)
print("送信（CT先頭）:", base64.b64encode(ct[:24]).decode(), "...")
pt = bmsc_v6_decrypt(nonce, ct, tag, K, IV)
print("受信:", pt.decode("utf-8"))
