from bmsc_v6 import bmsc_v6_encrypt, bmsc_v6_decrypt
K_master = b'masterkey12345678901234567890123456789012'
IV = b'20251029'
plain = b'HelloWorld2025'
nonce, cipher, tag = bmsc_v6_encrypt(plain, K_master, IV)
print("Encrypt OK")
decrypt = bmsc_v6_decrypt(nonce, cipher, tag, K_master, IV)
print("Decrypt:", decrypt.decode()) # HelloWorld2025