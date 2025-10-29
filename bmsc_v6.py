import os, hmac, hashlib
from typing import Tuple

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b''; okm = b''; c = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t; c += 1
    return okm[:length]

def coeffs(n: int):
    return [(i+1)*(n-i) for i in range(n)]

def keystream(K_stream: bytes, IV: bytes, nonce: bytes, n: int):
    ks = bytearray(n)
    cs = coeffs(n)
    for i, c in enumerate(cs):
        data = IV + nonce + str(n).encode() + str(i).encode() + str(c).encode()
        ks[i] = hmac.new(K_stream, data, hashlib.sha256).digest()[0]
    return bytes(ks)

def bmsc_v6_encrypt(plaintext: bytes, K_master: bytes, IV: bytes, aad: bytes=b'') -> Tuple[bytes, bytes, bytes]:
    n = len(plaintext)
    nonce = os.urandom(16)
    K_stream = hkdf_sha256(K_master, nonce, b"stream", 32)
    K_mac = hkdf_sha256(K_master, nonce, b"mac", 32)
    
    ks = keystream(K_stream, IV, nonce, n)
    ciphertext = bytes(p ^ s for p, s in zip(plaintext, ks))
    
    header = IV + nonce + n.to_bytes(4, "big") + aad
    tag = hmac.new(K_mac, header + ciphertext, hashlib.sha256).digest()[:16]
    return nonce, ciphertext, tag

def bmsc_v6_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, K_master: bytes, IV: bytes, aad: bytes=b'') -> bytes:
    n = len(ciphertext)
    K_stream = hkdf_sha256(K_master, nonce, b"stream", 32)
    K_mac = hkdf_sha256(K_master, nonce, b"mac", 32)
    
    header = IV + nonce + n.to_bytes(4, "big") + aad
    expect = hmac.new(K_mac, header + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expect, tag):
        raise ValueError("auth failed")
    
    ks = keystream(K_stream, IV, nonce, n)
    return bytes(c ^ s for c, s in zip(ciphertext, ks))