# signer.py
import json
import base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

messages = {}

def sign_message(username, message):
    try:
        with open(f'keys/{username}_private.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())
    except FileNotFoundError:
        return None, "Private key not found."

    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    signature_b64 = base64.b64encode(signature).decode()

    # Encrypt the message with the user's public key
    encrypted_message_b64 = encrypt_message(username, message)

    # Storing encrypted message and signature
    messages[username] = {
        "message": encrypted_message_b64,
        "signature": signature_b64
    }

    # Save messages to a file
    with open('messages.json', 'w') as f:
        json.dump(messages, f, indent=4)

    return signature_b64, "Message signed."


def verify_message(data):
    username = data.get('username')
    signature_b64 = data.get('signature')
    cert_path = f'certificates/{username}_certificate.pem'

    if not username or not signature_b64:
        return {"error": "Username, certificate, and signature are required"}

    if not os.path.exists(cert_path):
        return {"error": "Certificate not found"}

    if username not in messages:
        return {"error": "Incorrect credentials"}

    encrypted_message_b64 = messages[username]['message']
    signature = base64.b64decode(signature_b64)

    try:
        public_key = load_public_key(username)

        # Decrypt the message first
        encrypted_message = base64.b64decode(encrypted_message_b64)
        plaintext_message = decrypt_message(username, encrypted_message)

        # Verify the signature using plaintext
        h = SHA256.new(plaintext_message.encode())
        pkcs1_15.new(public_key).verify(h, signature)

        return {"message": plaintext_message}

    except (ValueError, TypeError):
        return {"error": "Incorrect credentials"}


def encrypt_message(username, message):
    try:
        with open(f'keys/{username}_public.pem', 'rb') as f:
            public_key = RSA.import_key(f.read())
    except FileNotFoundError:
        return None

    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode()

    return encrypted_message_b64


def decrypt_message(username, encrypted_message):
    try:
        with open(f'keys/{username}_private.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())
    except FileNotFoundError:
        return None

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)

    return decrypted_message.decode()


def load_public_key(username):
    with open(f'keys/{username}_public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    return public_key
