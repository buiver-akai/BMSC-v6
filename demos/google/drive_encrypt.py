# demos/google/drive_encrypt.py
import sys
import os
import base64
import hashlib, json, time, struct
from pathlib import Path

# ルート（BMSC-v6）を import パスに追加
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bmsc_v6_prod import bmsc_v6_encrypt  # AEAD本体

HERE = Path(__file__).resolve().parent

# 入力PDFの探索順（どちらかにあればOK）
SRC_CANDIDATES = [
    HERE / "住民票_サンプル.pdf",
    ROOT / "住民票_サンプル.pdf",
]
for _p in SRC_CANDIDATES:
    if _p.exists():
        SRC_PDF = _p
        break
else:
    cand_str = "\n - ".join(str(p) for p in SRC_CANDIDATES)
    print("住民票_サンプル.pdf が見つかりません。以下のいずれかに置いてください:\n - " + cand_str)
    raise SystemExit(1)

KEY_FILE   = HERE / "key_drive.bin"                # 32B鍵（無ければ生成）
OUT_BIN    = HERE / "住民票_encrypted.bin"         # 旧: raw (nonce|tag|ct)
OUT_BMSC6  = HERE / "住民票_encrypted.bmsc6"       # 新: ヘッダ付き（v2）
AAD_JSON   = HERE / "住民票_encrypted.aad.json"    # 参考用: AAD（書き出すが未使用でも可）
META_JSON  = HERE / "住民票_encrypted.meta.json"   # メタ情報（人間/機械可読）

# “コンテキスト”（用途ラベル。暗号nonceではない）
CTX = "BMSCv6-IV00"
CTX_BYTES = CTX.encode("utf-8")

# bmsc6 v1: MAGIC(6) + ver(1)=1 + flags(1) + nonce(24) + tag(16) + ct
# bmsc6 v2: MAGIC(6) + ver(1)=2 + flags(1)
#           + ctx_len(2 BE) + aad_len(4 BE) + ctx + aad + nonce(24) + tag(16) + ct
MAGIC = b"BMSC6\x00"
VER_V2 = 2
FLAGS  = 0
NONCE_LEN = 24
TAG_LEN   = 16

def main() -> int:
    # 鍵の用意
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(os.urandom(32))
    K = KEY_FILE.read_bytes()
    if len(K) != 32:
        print("key_drive.bin は 32 バイトである必要があります。")
        return 2

    # 平文PDFの読込
    try:
        data = SRC_PDF.read_bytes()
    except Exception as e:
        print(f"PDF 読込に失敗: {SRC_PDF} ({e})")
        return 3

    # AAD(JSON) を作成（コンパクト・バイト固定）
    sha = hashlib.sha256(data).hexdigest()
    aad_obj   = {"name": SRC_PDF.name, "size": len(data), "sha256": sha}
    aad_bytes = json.dumps(aad_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    # 暗号化（nonce|tag|ct）
    nonce, ct, tag = bmsc_v6_encrypt(data, K, CTX_BYTES, aad=aad_bytes)

    # 旧形式（互換用）
    OUT_BIN.write_bytes(nonce + tag + ct)

    # 新形式（bmsc6 v2 = ctx/aad 内包）
    ctx_len = len(CTX_BYTES)
    aad_len = len(aad_bytes)
    header  = MAGIC + bytes([VER_V2, FLAGS]) + struct.pack(">HI", ctx_len, aad_len)
    OUT_BMSC6.write_bytes(header + CTX_BYTES + aad_bytes + nonce + tag + ct)

    # サイドカー出力（参考用途。なくても復号可能）
    AAD_JSON.write_bytes(aad_bytes)
    meta = {
        "ver":  "bmsc6",
        "kid":  "local:drive",
        "ctx":  CTX,
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "tag_b64":   base64.b64encode(tag).decode("ascii"),
        "created_at": int(time.time()),
        "bmsc6_version": 2
    }
    META_JSON.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    # 情報表示
    print("入力PDF:", SRC_PDF)
    print("元PDF SHA-256:", sha)
    print("鍵ファイル:", KEY_FILE)
    print("暗号化完了(raw):", OUT_BIN.name)
    print("暗号化完了(bmsc6 v2):", OUT_BMSC6.name)
    print("CT(Base64):", base64.b64encode(ct).decode("ascii"))
    print("NONCE(Base64):", base64.b64encode(nonce).decode("ascii"))
    print("TAG(Base64):",   base64.b64encode(tag).decode("ascii"))
    print("AAD file:", AAD_JSON)
    print("META file:", META_JSON)
    print("CT size:", len(ct), "bytes")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
