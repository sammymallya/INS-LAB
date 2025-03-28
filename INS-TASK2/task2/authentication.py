from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import logging
from pathlib import Path
from rsagen import load_rsa_keys

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sign_message(message: bytes) -> bytes:
    """
    Sign a message using the private key.
    Args:
        message: The message to sign
    Returns:
        The signature if successful, None otherwise
    """
    try:
        # Load RSA keys
        private_key, _ = load_rsa_keys()
        if not private_key:
            logger.error("Private key not found")
            return None

        # Create signature
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        logger.info("Message signed successfully")
        return signature
        
    except Exception as e:
        logger.error(f"Error signing message: {str(e)}")
        return None

def verify_signature(message: bytes, signature: bytes) -> bool:
    """
    Verify a message signature using the public key.
    Args:
        message: The original message
        signature: The signature to verify
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Load RSA keys
        _, public_key = load_rsa_keys()
        if not public_key:
            logger.error("Public key not found")
            return False

        # Verify signature
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        logger.info("Signature verified successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error verifying signature: {str(e)}")
        return False

def sign_file(file_path: str) -> bytes:
    """
    Sign a file using the private key.
    Args:
        file_path: Path to the file to sign
    Returns:
        The signature if successful, None otherwise
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"File {file_path} not found")
            return None

        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()

        # Sign the content
        return sign_message(content)
        
    except Exception as e:
        logger.error(f"Error signing file: {str(e)}")
        return None

def verify_file_signature(file_path: str, signature: bytes) -> bool:
    """
    Verify a file signature using the public key.
    Args:
        file_path: Path to the file to verify
        signature: The signature to verify
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"File {file_path} not found")
            return False

        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()

        # Verify the signature
        return verify_signature(content, signature)
        
    except Exception as e:
        logger.error(f"Error verifying file signature: {str(e)}")
        return False

def save_signature(signature: bytes, output_path: str):
    """
    Save a signature to a file.
    Args:
        signature: The signature to save
        output_path: Path to save the signature
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        output_path = Path(output_path)
        with open(output_path, 'wb') as f:
            f.write(signature)
        logger.info(f"Signature saved to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving signature: {str(e)}")
        return False

def load_signature(signature_path: str) -> bytes:
    """
    Load a signature from a file.
    Args:
        signature_path: Path to the signature file
    Returns:
        The signature if successful, None otherwise
    """
    try:
        signature_path = Path(signature_path)
        if not signature_path.exists():
            logger.error(f"Signature file {signature_path} not found")
            return None

        with open(signature_path, 'rb') as f:
            return f.read()
            
    except Exception as e:
        logger.error(f"Error loading signature: {str(e)}")
        return None

if __name__ == "__main__":
    # Test message signing and verification
    test_message = b"Hello, World!"
    
    # Sign message
    signature = sign_message(test_message)
    if signature:
        print("Message signed successfully")
        
        # Save signature
        if save_signature(signature, "test_signature.sig"):
            print("Signature saved successfully")
            
            # Load signature
            loaded_signature = load_signature("test_signature.sig")
            if loaded_signature:
                print("Signature loaded successfully")
                
                # Verify signature
                if verify_signature(test_message, loaded_signature):
                    print("Signature verified successfully")
                else:
                    print("Signature verification failed") 