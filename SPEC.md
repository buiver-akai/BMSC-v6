# BMSC6 File Format Specification (v2)

**Version:** 2  
**Status:** Stable (2025-11-17)  
**Purpose:** Self-contained container for BMSC v6 ciphertext and its associated *context* (`ctx`) and *additional authenticated data* (`aad`).

---

## 1. High-level

A `*.bmsc6` file packages:
- **Header** (magic, version, flags)
- **Lengths** for `ctx` and `aad`
- **Payload**: `ctx`, `aad`, `nonce (24B)`, `tag (16B)`, `ct (variable)`

`ctx` = a UTF-8 text label that identifies *use / domain* (e.g., `"BMSCv6-IV00"`).  
`aad` = arbitrary bytes (commonly UTF-8 JSON) that must match at decryption (binds filename/hash/etc.).  
Both `ctx` and `aad` are authenticated via the AEAD tag (tamper detection).

Encryption primitive: **XChaCha20-Poly1305**. Nonce: 24 bytes (random & unique per encryption).

---

## 2. Binary Layout (Big-Endian for lengths)

```
offset  size  description
------  ----  -----------------------------------------------
0       6     MAGIC = 42 4D 53 43 36 00   # "BMSC6\0"
6       1     ver   = 0x02                # file format version
7       1     flags = 0x00                # reserved (must be 0)

8       2     ctx_len  (uint16, BE)
10      4     aad_len  (uint32, BE)

14      Lc    ctx bytes (Lc = ctx_len)
14+Lc   La    aad bytes (La = aad_len)

14+Lc+La 24   nonce (24 bytes)
...      16   tag   (16 bytes)
...      N    ct    (ciphertext, N = remaining file size)
```

> Notes
> - `ctx` is UTF-8 text by convention (but treated as opaque bytes in the format).
> - `aad` can be any bytes. In most demos we store compact JSON like:  
>   `{"name":"住民票_サンプル.pdf","size":473,"sha256":"..."} (UTF-8)`
> - `nonce` must be unique per encryption under the same key. Random 24B from libsodium is recommended.
> - `tag` is the 16-byte Poly1305 tag returned by the AEAD.
> - `ct` is the AEAD ciphertext for the plaintext `pt`.

---

## 3. Pseudocode

### 3.1 Write (`pt` -> `.bmsc6`)

```python
from struct import pack
MAGIC = b"BMSC6\x00"
ver, flags = 2, 0

ctx_bytes = ctx.encode("utf-8")  # or raw bytes
aad_bytes = aad                  # bytes

nonce, ct, tag = aead_encrypt(pt, key, ctx_bytes, aad_bytes)  # XChaCha20-Poly1305

out = bytearray()
out += MAGIC
out += bytes([ver])
out += bytes([flags])
out += pack(">H", len(ctx_bytes))
out += pack(">I", len(aad_bytes))
out += ctx_bytes
out += aad_bytes
out += nonce
out += tag
out += ct

open("file.bmsc6","wb").write(out)
```

> `aead_encrypt` is an abstraction for a function that uses XChaCha20-Poly1305, passing `aad_bytes` as AAD. The **`ctx_bytes` should also be included inside AAD** by your higher-level API or explicitly concatenated with other fixed AAD fields to guarantee context binding. BMSC v6's reference implementation handles this binding internally.

### 3.2 Read (`.bmsc6` -> `pt`)

```python
from struct import unpack

data = open("file.bmsc6","rb").read()
assert data[:6] == b"BMSC6\x00"
ver   = data[6]
flags = data[7]
assert ver == 2 and flags == 0

ctx_len = unpack(">H", data[8:10])[0]
aad_len = unpack(">I", data[10:14])[0]

p = 14
ctx_bytes = data[p:p+ctx_len]; p += ctx_len
aad_bytes = data[p:p+aad_len]; p += aad_len
nonce = data[p:p+24];          p += 24
tag   = data[p:p+16];          p += 16
ct    = data[p:]

pt = aead_decrypt(nonce, ct, tag, key, ctx_bytes, aad_bytes)
```

---

## 4. Security Considerations

- **Nonce uniqueness**: XChaCha20 requires a 24-byte nonce unique per encryption under the same key. Use cryptographically secure randomness. Never reuse a `(key, nonce)` pair.
- **Context binding**: Treat `ctx` as a *label*. Ensure the decryptor provides/validates the same `ctx`. BMSC v6 reference code binds `ctx` via AAD so decryption fails if contexts mismatch.
- **AAD content**: Include meaningful identifiers (e.g., filename, size, SHA-256). If these should not reveal information, replace the raw hash with an **HMAC** of the hash under a separate secret.
- **Replay**: To mitigate replay in messaging, extend AAD with monotonic counters, timestamps, `message_id`, etc., and enforce freshness/uniqueness at application level.
- **Key rotation**: Track key ids (KIDs) in side metadata or wrap `*.bmsc6` inside a higher-level envelope that carries `kid`, issuer, created_at, etc.

---

## 5. Interop Checklist

- [ ] MAGIC and version check
- [ ] Big-endian parsing of lengths
- [ ] UTF-8 handling for `ctx` if treated as text
- [ ] Exact AAD bytes match between enc/dec
- [ ] 24B nonce, 16B tag sizes validated
- [ ] Fail-closed on any parse or AEAD verification error

---

## 6. Test Guidance

A simple round-trip test:
1. Build an example `pt` (e.g., a short PDF).
2. Choose `ctx = "BMSCv6-IV00"` and an `aad` JSON with name/size/sha256.
3. Encrypt → produce `.bmsc6`.
4. Decrypt with the same key and verify `sha256(pt_dec) == sha256(pt)`.

For large files, also test streaming/chunked processing in your application layer.
