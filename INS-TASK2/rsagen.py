from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_rsa_keys(key_size=2048, public_exponent=65537):
    """
    Generate RSA key pair and save them to files.
    Args:
        key_size: Size of the RSA key in bits (default: 2048)
        public_exponent: Public exponent (default: 65537)
    Returns:
        Tuple of (private_key, public_key) if successful, (None, None) otherwise
    """
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Create keys directory if it doesn't exist
        key_dir = Path("keys")
        key_dir.mkdir(exist_ok=True)
        
        # Save private key
        private_key_path = key_dir / "private_key.pem"
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        public_key_path = key_dir / "public_key.pem"
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        # Set proper file permissions (readable only by owner)
        os.chmod(private_key_path, 0o600)
        os.chmod(public_key_path, 0o644)
        
        logger.info("RSA key pair generated and saved successfully")
        return private_key, public_key
        
    except Exception as e:
        logger.error(f"Error generating RSA keys: {str(e)}")
        return None, None

def load_rsa_keys():
    """
    Load RSA key pair from files.
    Returns:
        Tuple of (private_key, public_key) if successful, (None, None) otherwise
    """
    try:
        private_key_path = Path("keys") / "private_key.pem"
        public_key_path = Path("keys") / "public_key.pem"
        
        if not private_key_path.exists() or not public_key_path.exists():
            logger.error("RSA key files not found")
            return None, None
            
        # Load private key
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
            
        # Load public key
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
            
        return private_key, public_key
        
    except Exception as e:
        logger.error(f"Error loading RSA keys: {str(e)}")
        return None, None

def get_public_key_pem(public_key):
    """
    Get the PEM format of a public key.
    Args:
        public_key: The public key object
    Returns:
        The PEM format of the public key
    """
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        logger.error(f"Error getting public key PEM: {str(e)}")
        return None

def get_private_key_pem(private_key):
    """
    Get the PEM format of a private key.
    Args:
        private_key: The private key object
    Returns:
        The PEM format of the private key
    """
    try:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception as e:
        logger.error(f"Error getting private key PEM: {str(e)}")
        return None

if __name__ == "__main__":
    # Test key generation
    private_key, public_key = generate_rsa_keys()
    if private_key and public_key:
        print("RSA key pair generated successfully")
        
        # Test loading keys
        loaded_private, loaded_public = load_rsa_keys()
        if loaded_private and loaded_public:
            print("RSA key pair loaded successfully")
            
            # Test PEM conversion
            public_pem = get_public_key_pem(loaded_public)
            private_pem = get_private_key_pem(loaded_private)
            if public_pem and private_pem:
                print("PEM conversion successful") 