from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import logging
from ca_manager import ca
from authentication import auth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/api/register', methods=['POST'])
def register_user():
    """Register a new user and generate key pair."""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({"error": "User ID is required"}), 400
            
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Register user with CA
        if ca.register_user(user_id, public_key):
            # Save private key
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            return jsonify({
                "status": "success",
                "user_id": user_id,
                "private_key": private_key_pem
            }), 201
        else:
            return jsonify({"error": "User registration failed"}), 400
            
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/sign', methods=['POST'])
def sign_message():
    """Sign a message with user's private key."""
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
            return jsonify(signed_message), 200
        else:
            return jsonify({"error": "Message signing failed"}), 400
            
    except Exception as e:
        logger.error(f"Error signing message: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify', methods=['POST'])
def verify_message():
    """Verify a signed message."""
    try:
        data = request.get_json()
        signed_message = data.get('signed_message')
        
        if not signed_message:
            return jsonify({"error": "Signed message is required"}), 400
            
        # Verify message
        result = auth.verify_message(signed_message)
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error verifying message: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/revoke', methods=['POST'])
def revoke_certificate():
    """Revoke a user's certificate."""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({"error": "User ID is required"}), 400
            
        # Revoke certificate
        if ca.revoke_user_certificate(user_id):
            return jsonify({"status": "success", "message": "Certificate revoked"}), 200
        else:
            return jsonify({"error": "Certificate revocation failed"}), 400
            
    except Exception as e:
        logger.error(f"Error revoking certificate: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000) 