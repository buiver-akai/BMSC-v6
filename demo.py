import os
from bmsc_v6_prod import bmsc_v6_encrypt, bmsc_v6_decrypt

K  = os.urandom(32)
IV = b"BMSCv6-IV00"
pt = b"HelloWorld2025"

nonce, ct, tag = bmsc_v6_encrypt(pt, K, IV)
print("Encrypt OK")
dec = bmsc_v6_decrypt(nonce, ct, tag, K, IV)
print("Decrypt:", dec.decode("utf-8"))
