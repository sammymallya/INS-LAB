import os
import logging
from pathlib import Path
from aes_keygen import generate_aes_key, encrypt_data, decrypt_data
from rsagen import generate_rsa_keys, load_rsa_keys
from certificate_manager import (
    generate_x509_certificate,
    load_certificate,
    verify_certificate,
    get_certificate_info
)
from krl_manager import (
    revoke_key,
    remove_key_revocation,
    check_key_status,
    KRLManager
)
from authentication import (
    signed_message,
    verify_signature,
    sign_file,
    verify_file_signature
)
from key_ex import (
    generate_dh_parameters,
    generate_dh_private_key,
    get_dh_public_key,
    get_shared_secret
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
from datetime import datetime
from flask import Flask, request, jsonify
from ca_manager import ca
from authentication import auth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Admin password
ADMIN_PASSWORD = "Admin123"

# Store user sessions
user_sessions = {}

def create_directories():
    """Create necessary directories for the system."""
    directories = ["keys", "certificates"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

def print_menu():
    """Print the main menu."""
    print("\n🔐 Secure Key Management System")
    print("1. Generate AES Key")
    print("2. Generate RSA Key Pair")
    print("3. Generate X.509 Certificate")
    print("4. Revoke Key")
    print("5. Check Key Revocation Status")
    print("6. Remove Key Revocation")
    print("7. Sign Message")
    print("8. Verify Message Signature")
    print("9. Sign File")
    print("10. Verify File Signature")
    print("11. Perform Key Exchange")
    print("12. Exit")

def handle_aes_key_generation():
    """Handle AES key generation."""
    print("\nGenerating AES key...")
    key = generate_aes_key()
    if key:
        print("✅ AES key generated successfully")
        
        # Test encryption/decryption
        test_data = b"Test message"
        encrypted = encrypt_data(test_data, key)
        if encrypted:
            print("✅ Test encryption successful")
            decrypted = decrypt_data(encrypted, key)
            if decrypted == test_data:
                print("✅ Test decryption successful")
            else:
                print("❌ Test decryption failed")
    else:
        print("❌ Failed to generate AES key")

def handle_rsa_key_generation():
    """Handle RSA key pair generation."""
    print("\nGenerating RSA key pair...")
    private_key, public_key = generate_rsa_keys()
    if private_key and public_key:
        print("✅ RSA key pair generated successfully")
    else:
        print("❌ Failed to generate RSA key pair")

def handle_certificate_generation():
    """Handle X.509 certificate generation."""
    print("\nGenerating X.509 certificate...")
    if generate_x509_certificate():
        print("✅ Certificate generated successfully")
        
        # Load and verify certificate
        cert = load_certificate()
        if cert:
            info = get_certificate_info(cert)
            if info:
                print("\nCertificate Information:")
                print(f"Subject: {info['subject']}")
                print(f"Issuer: {info['issuer']}")
                print(f"Valid from: {info['not_valid_before']}")
                print(f"Valid until: {info['not_valid_after']}")
                
                if verify_certificate(cert):
                    print("✅ Certificate verification successful")
                else:
                    print("❌ Certificate verification failed")
    else:
        print("❌ Failed to generate certificate")

def handle_key_revocation():
    """Handle key revocation."""
    key_name = input("\nEnter key filename to revoke: ")
    if revoke_key(key_name):
        print(f"✅ Key {key_name} revoked successfully")
    else:
        print(f"❌ Failed to revoke key {key_name}")

def handle_key_status_check():
    """Handle key revocation status check."""
    key_name = input("\nEnter key filename to check: ")
    status = check_key_status(key_name)
    if status:
        print(f"🔒 Key {key_name} is revoked")
    else:
        print(f"✅ Key {key_name} is not revoked")

def handle_key_revocation_removal():
    """Handle key revocation removal."""
    key_name = input("\nEnter key filename to remove from revocation: ")
    if remove_key_revocation(key_name):
        print(f"✅ Key {key_name} removed from revocation")
    else:
        print(f"❌ Failed to remove key {key_name} from revocation")

def handle_message_signing():
    """Handle message signing."""
    message = input("\nEnter message to sign: ").encode()
    signature = sign_message(message)
    if signature:
        print("✅ Message signed successfully")
        if verify_signature(message, signature):
            print("✅ Signature verification successful")
        else:
            print("❌ Signature verification failed")
    else:
        print("❌ Failed to sign message")

def handle_file_signing():
    """Handle file signing."""
    file_path = input("\nEnter file path to sign: ")
    signature = sign_file(file_path)
    if signature:
        print("✅ File signed successfully")
        if verify_file_signature(file_path, signature):
            print("✅ File signature verification successful")
        else:
            print("❌ File signature verification failed")
    else:
        print("❌ Failed to sign file")

def handle_key_exchange():
    """Handle Diffie-Hellman key exchange."""
    print("\nPerforming Diffie-Hellman key exchange...")
    
    # Generate parameters
    parameters = generate_dh_parameters()
    if not parameters:
        print("❌ Failed to generate DH parameters")
        return
        
    # Generate Alice's keys
    alice_private = generate_dh_private_key(parameters)
    if not alice_private:
        print("❌ Failed to generate Alice's private key")
        return
        
    alice_public = get_dh_public_key(alice_private)
    if not alice_public:
        print("❌ Failed to generate Alice's public key")
        return
        
    # Generate Bob's keys
    bob_private = generate_dh_private_key(parameters)
    if not bob_private:
        print("❌ Failed to generate Bob's private key")
        return
        
    bob_public = get_dh_public_key(bob_private)
    if not bob_public:
        print("❌ Failed to generate Bob's public key")
        return
        
    # Generate shared secrets
    alice_secret = get_shared_secret(alice_private, bob_public)
    bob_secret = get_shared_secret(bob_private, alice_public)
    
    if alice_secret and bob_secret and alice_secret == bob_secret:
        print("✅ Key exchange successful")
        print(f"Shared secret: {alice_secret.hex()[:32]}...")
    else:
        print("❌ Key exchange failed")

def main():
    """Main application entry point."""
    try:
        # Create necessary directories
        create_directories()
        
        while True:
            print_menu()
            choice = input("\nEnter your choice: ")
            
            if choice == "1":
                handle_aes_key_generation()
            elif choice == "2":
                handle_rsa_key_generation()
            elif choice == "3":
                handle_certificate_generation()
            elif choice == "4":
                handle_key_revocation()
            elif choice == "5":
                handle_key_status_check()
            elif choice == "6":
                handle_key_revocation_removal()
            elif choice == "7":
                handle_message_signing()
            elif choice == "8":
                message = input("\nEnter message to verify: ").encode()
                signature = input("Enter signature (hex): ")
                if verify_signature(message, bytes.fromhex(signature)):
                    print("✅ Signature verification successful")
                else:
                    print("❌ Signature verification failed")
            elif choice == "9":
                handle_file_signing()
            elif choice == "10":
                file_path = input("\nEnter file path to verify: ")
                signature = input("Enter signature (hex): ")
                if verify_file_signature(file_path, bytes.fromhex(signature)):
                    print("✅ File signature verification successful")
                else:
                    print("❌ File signature verification failed")
            elif choice == "11":
                handle_key_exchange()
            elif choice == "12":
                print("\n👋 Goodbye!")
                break
            else:
                print("\n❌ Invalid choice!")
                
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        print("\n❌ An error occurred. Check the logs for details.")

@app.route('/api/generate/aes', methods=['GET'])
def api_generate_aes():
    """Generate AES key."""
    try:
        key = generate_aes_key()
        return jsonify({
            "status": "success",
            "key": base64.b64encode(key).decode('utf-8')
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/generate/rsa', methods=['GET'])
def api_generate_rsa():
    """Generate RSA key pair."""
    try:
        private_key, public_key = generate_rsa_keys()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return jsonify({
            "status": "success",
            "private_key": private_pem,
            "public_key": public_pem
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/setup/user', methods=['POST'])
def api_setup_user():
    """Setup new user with ID and private key."""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        private_key_pem = data.get('private_key')
        
        if not all([user_id, private_key_pem]):
            return jsonify({"error": "Missing required fields"}), 400
            
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Register user with CA
        if ca.register_user(user_id, private_key.public_key()):
            return jsonify({
                "status": "success",
                "message": f"User {user_id} registered successfully"
            })
        else:
            return jsonify({"error": "User registration failed"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """Login user with ID and private key."""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        private_key_pem = data.get('private_key')
        
        if not all([user_id, private_key_pem]):
            return jsonify({"error": "Missing required fields"}), 400
            
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Verify user exists and private key matches
        user_cert = ca.get_user_certificate(user_id)
        if not user_cert:
            return jsonify({"error": "User not found"}), 404
            
        if private_key.public_key().public_numbers() != user_cert.public_key().public_numbers():
            return jsonify({"error": "Invalid private key"}), 401
            
        # Store user session
        user_sessions[user_id] = {
            "private_key": private_key,
            "login_time": datetime.utcnow().isoformat()
        }
        
        return jsonify({
            "status": "success",
            "message": f"User {user_id} logged in successfully"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/revoke', methods=['POST'])
def api_revoke():
    """Revoke user certificate (admin only)."""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        admin_password = data.get('admin_password')
        
        if not all([user_id, admin_password]):
            return jsonify({"error": "Missing required fields"}), 400
            
        if admin_password != ADMIN_PASSWORD:
            return jsonify({"error": "Invalid admin password"}), 401
            
        if ca.revoke_user_certificate(user_id):
            return jsonify({
                "status": "success",
                "message": f"User {user_id} certificate revoked"
            })
        else:
            return jsonify({"error": "Certificate revocation failed"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/sign', methods=['POST'])
def api_sign():
    """Sign a message."""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        message = data.get('message')
        private_key_pem = data.get('private_key')
        
        if not all([user_id, message, private_key_pem]):
            return jsonify({"error": "Missing required fields"}), 400
            
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Sign message
        signed_message = auth.sign_message(user_id, message, private_key)
        if signed_message:
            return jsonify(signed_message)
        else:
            return jsonify({"error": "Message signing failed"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify', methods=['POST'])
def api_verify():
    """Verify a signed message."""
    try:
        data = request.get_json()
        signed_message = data.get('signed_message')
        
        if not signed_message:
            return jsonify({"error": "Signed message is required"}), 400
            
        # Verify message
        result = auth.verify_message(signed_message)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    main() 