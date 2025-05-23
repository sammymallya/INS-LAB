# key_manager.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import os

def generate_aes_key():
    if not os.path.exists('keys'):
        os.makedirs('keys')
    key = get_random_bytes(32)  # AES 256-bit
    with open('keys/aes_key.bin', 'wb') as f:
        f.write(key)
    return "AES key generated."

def generate_rsa_keys(username):
    if not os.path.exists('keys'):
        os.makedirs('keys')
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f'keys/{username}_private.pem', 'wb') as f:
        f.write(private_key)
    with open(f'keys/{username}_public.pem', 'wb') as f:
        f.write(public_key)
    return "RSA key pair generated."