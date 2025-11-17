import os, hmac, hashlib
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt as aead_encrypt,
        crypto_aead_xchacha20poly1305_ietf_decrypt as aead_decrypt,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as NPUBBYTES,
        crypto_aead_xchacha20poly1305_ietf_ABYTES as ABYTES,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES as KEYBYTES,
    )
except Exception as e:
    raise ImportError("PyNaCl が必要です。'pip install pynacl' を実行してください。") from e

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b''; okm = b''; c = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t; c += 1
    return okm[:length]

def _aad_pack(iv: bytes, aad: bytes) -> bytes:
    # AAD = len(iv)||iv||aad  （IVと文脈をタグにバインド）
    return len(iv).to_bytes(2, "big") + iv + aad

def bmsc_v6_encrypt(plaintext: bytes, K_master: bytes, IV: bytes, aad: bytes=b""):
    if not isinstance(plaintext, (bytes, bytearray)): raise TypeError("plaintext must be bytes")
    if not isinstance(K_master, (bytes, bytearray)) or len(K_master) != 32: raise ValueError("K_master must be 32 bytes")
    if not isinstance(IV, (bytes, bytearray)): raise TypeError("IV must be bytes")

    nonce = os.urandom(NPUBBYTES)  # 24 bytes
    K_enc = hkdf_sha256(K_master, nonce, b"BMSCv6-prod:"+IV, KEYBYTES)
    ad = _aad_pack(IV, aad)

    ct_full = aead_encrypt(bytes(plaintext), ad, nonce, K_enc)  # ct||tag
    ciphertext, tag = ct_full[:-ABYTES], ct_full[-ABYTES:]
    return (nonce, ciphertext, tag)

def bmsc_v6_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, K_master: bytes, IV: bytes, aad: bytes=b"") -> bytes:
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 24: raise ValueError("nonce must be 24 bytes")
    if not isinstance(K_master, (bytes, bytearray)) or len(K_master) != 32: raise ValueError("K_master must be 32 bytes")
    if not isinstance(IV, (bytes, bytearray)): raise TypeError("IV must be bytes")

    K_enc = hkdf_sha256(K_master, nonce, b"BMSCv6-prod:"+IV, KEYBYTES)
    ad = _aad_pack(IV, aad)
    ct_full = bytes(ciphertext) + bytes(tag)
    try:
        pt = aead_decrypt(ct_full, ad, nonce, K_enc)
    except Exception:
        raise ValueError("auth failed")
    return pt
