import os, hmac, hashlib

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b''; okm = b''; c = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t; c += 1
    return okm[:length]

def _coeffs(n: int):
    return [(i+1)*(n-i) for i in range(n)]

def _keystream(K_stream: bytes, IV: bytes, nonce: bytes, n: int) -> bytes:
    ks = bytearray(n); cs = _coeffs(n)
    for i, c in enumerate(cs):
        data = IV + nonce + str(n).encode() + str(i).encode() + str(c).encode()
        ks[i] = hmac.new(K_stream, data, hashlib.sha256).digest()[0]
    return bytes(ks)

def bmsc_v6_encrypt(plaintext: bytes, K_master: bytes, IV: bytes, aad: bytes=b""):
    if not isinstance(plaintext, (bytes, bytearray)): raise TypeError("plaintext must be bytes")
    if not isinstance(K_master, (bytes, bytearray)) or len(K_master) != 32: raise ValueError("K_master must be 32 bytes")
    if not isinstance(IV, (bytes, bytearray)): raise TypeError("IV must be bytes")
    n = len(plaintext)
    nonce = os.urandom(16)
    K_stream = hkdf_sha256(K_master, nonce, b"stream", 32)
    K_mac    = hkdf_sha256(K_master, nonce, b"mac", 32)
    ks = _keystream(K_stream, IV, nonce, n)
    ciphertext = bytes(p ^ s for p, s in zip(plaintext, ks))
    header = IV + nonce + n.to_bytes(4, "big") + aad
    tag = hmac.new(K_mac, header + ciphertext, hashlib.sha256).digest()[:16]
    return (nonce, ciphertext, tag)

def bmsc_v6_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, K_master: bytes, IV: bytes, aad: bytes=b"") -> bytes:
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 16: raise ValueError("nonce must be 16 bytes")
    if not isinstance(K_master, (bytes, bytearray)) or len(K_master) != 32: raise ValueError("K_master must be 32 bytes")
    if not isinstance(IV, (bytes, bytearray)): raise TypeError("IV must be bytes")
    n = len(ciphertext)
    K_stream = hkdf_sha256(K_master, nonce, b"stream", 32)
    K_mac    = hkdf_sha256(K_master, nonce, b"mac", 32)
    header = IV + nonce + n.to_bytes(4, "big") + aad
    expect = hmac.new(K_mac, header + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expect, tag):
        raise ValueError("auth failed")
    ks = _keystream(K_stream, IV, nonce, n)
    return bytes(c ^ s for c, s in zip(ciphertext, ks))
