from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json
import logging
from datetime import datetime
from ca_manager import ca

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Authentication:
    def __init__(self):
        self.signatures = {}

    def sign_message(self, user_id, message, private_key):
        """
        Sign a message with user's private key and include certificate information.
        Args:
            user_id: User identifier
            message: Message to sign
            private_key: User's private key
        Returns:
            dict: JSON formatted signed message with metadata
        """
        try:
            # Get user's certificate
            user_cert = ca.get_user_certificate(user_id)
            if not user_cert:
                logger.error(f"User {user_id} certificate not found")
                return None

            # Create signature
            signature = private_key.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Create signed message structure
            signed_message = {
                "version": "1.0",
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": user_id,
                "message": message,
                "signature": signature.hex(),
                "certificate": {
                    "serial_number": str(user_cert.serial_number),
                    "issuer": user_cert.issuer.rfc4514_string(),
                    "subject": user_cert.subject.rfc4514_string(),
                    "valid_from": user_cert.not_valid_before.isoformat(),
                    "valid_to": user_cert.not_valid_after.isoformat()
                }
            }

            # Store signature for verification
            self.signatures[user_id] = {
                "signature": signature,
                "timestamp": signed_message["timestamp"]
            }

            logger.info(f"Message signed successfully for user {user_id}")
            return signed_message

        except Exception as e:
            logger.error(f"Error signing message: {str(e)}")
            return None

    def verify_message(self, signed_message):
        """
        Verify a signed message and display JSON data.
        Args:
            signed_message: JSON formatted signed message
        Returns:
            dict: Verification result with message data if valid
        """
        try:
            # Parse signed message
            if isinstance(signed_message, str):
                signed_message = json.loads(signed_message)

            user_id = signed_message.get("user_id")
            if not user_id:
                logger.error("User ID not found in signed message")
                return {"valid": False, "error": "Invalid message format"}

            # Get user's certificate
            user_cert = ca.get_user_certificate(user_id)
            if not user_cert:
                logger.error(f"User {user_id} certificate not found")
                return {"valid": False, "error": "User certificate not found"}

            # Verify certificate
            if not ca.verify_user_certificate(user_id, user_cert):
                logger.error(f"Invalid certificate for user {user_id}")
                return {"valid": False, "error": "Invalid certificate"}

            # Verify signature
            signature = bytes.fromhex(signed_message["signature"])
            try:
                user_cert.public_key().verify(
                    signature,
                    signed_message["message"].encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                logger.error(f"Signature verification failed: {str(e)}")
                return {"valid": False, "error": "Invalid signature"}

            # Return verification result with message data
            result = {
                "valid": True,
                "message_data": {
                    "user_id": user_id,
                    "message": signed_message["message"],
                    "timestamp": signed_message["timestamp"],
                    "certificate_info": signed_message["certificate"]
                }
            }

            logger.info(f"Message verified successfully for user {user_id}")
            return result

        except Exception as e:
            logger.error(f"Error verifying message: {str(e)}")
            return {"valid": False, "error": str(e)}

    def save_signed_message(self, signed_message, filename):
        """
        Save signed message to a file.
        Args:
            signed_message: JSON formatted signed message
            filename: Output filename
        """
        try:
            with open(filename, 'w') as f:
                json.dump(signed_message, f, indent=4)
            logger.info(f"Signed message saved to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving signed message: {str(e)}")
            return False

    def load_signed_message(self, filename):
        """
        Load signed message from a file.
        Args:
            filename: Input filename
        Returns:
            dict: Loaded signed message
        """
        try:
            with open(filename, 'r') as f:
                signed_message = json.load(f)
            logger.info(f"Signed message loaded from {filename}")
            return signed_message
        except Exception as e:
            logger.error(f"Error loading signed message: {str(e)}")
            return None

# Global authentication instance
auth = Authentication()

if __name__ == "__main__":
    # Test authentication functionality
    test_user_id = "test_user"
    test_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    test_message = "Hello, World!"

    # Register test user
    ca.register_user(test_user_id, test_private_key.public_key())
    
    # Sign message
    signed_message = auth.sign_message(test_user_id, test_message, test_private_key)
    if signed_message:
        print("Message signed successfully")
        print(json.dumps(signed_message, indent=4))

        # Verify message
        verification_result = auth.verify_message(signed_message)
        print("\nVerification result:")
        print(json.dumps(verification_result, indent=4)) 