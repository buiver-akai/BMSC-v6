import argparse
import base64
from bmsc_v6 import bmsc_v6_encrypt, bmsc_v6_decrypt  # メインコードインポート

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='command')

encrypt_parser = subparsers.add_parser('encrypt')
encrypt_parser.add_argument('plaintext', type=str)
encrypt_parser.add_argument('--key', type=str, default='masterkey12345678901234567890123456789012')
encrypt_parser.add_argument('--iv', type=str, default='20251029')

decrypt_parser = subparsers.add_parser('decrypt')
decrypt_parser.add_argument('nonce_cipher_tag', type=str)  # base64(nonce + cipher + tag)
decrypt_parser.add_argument('--key', type=str, default='masterkey12345678901234567890123456789012')
decrypt_parser.add_argument('--iv', type=str, default='20251029')

args = parser.parse_args()

if args.command == 'encrypt':
    plain_bytes = args.plaintext.encode()
    IV = args.iv.encode()
    nonce, cipher, tag = bmsc_v6_encrypt(plain_bytes, args.key.encode(), IV)
    output = nonce + cipher + tag
    print(base64.b64encode(output).decode())

elif args.command == 'decrypt':
    output = base64.b64decode(args.nonce_cipher_tag)
    nonce = output[:16]
    n = len(output) - 16 - 16  # tag 16
    cipher = output[16:16+n]
    tag = output[-16:]
    IV = args.iv.encode()
    try:
        decrypted = bmsc_v6_decrypt(nonce, cipher, tag, args.key.encode(), IV)
        print(decrypted.decode())
    except ValueError as e:
        print(f"Error: {e}")