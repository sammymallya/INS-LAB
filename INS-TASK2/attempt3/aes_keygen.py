from cryptography.fernet import Fernet
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_aes_key():
    """
    Generate a secure AES key and save it to a file.
    Returns the generated key if successful, None otherwise.
    """
    try:
        # Generate a new Fernet key (AES-128 in CBC mode with PKCS7 padding)
        key = Fernet.generate_key()
        
        # Create keys directory if it doesn't exist
        key_dir = Path("keys")
        key_dir.mkdir(exist_ok=True)
        
        # Save the key to a file
        key_path = key_dir / "aes_key.bin"
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        
        # Set proper file permissions (readable only by owner)
        os.chmod(key_path, 0o600)
        
        logger.info("AES key generated and saved successfully")
        return key
        
    except Exception as e:
        logger.error(f"Error generating AES key: {str(e)}")
        return None

def load_aes_key():
    """
    Load the AES key from the file.
    Returns the loaded key if successful, None otherwise.
    """
    try:
        key_path = Path("keys") / "aes_key.bin"
        
        if not key_path.exists():
            logger.error("AES key file not found")
            return None
            
        with open(key_path, "rb") as key_file:
            key = key_file.read()
            
        return key
        
    except Exception as e:
        logger.error(f"Error loading AES key: {str(e)}")
        return None

def encrypt_data(data: bytes, key: bytes = None) -> bytes:
    """
    Encrypt data using the AES key.
    Args:
        data: The data to encrypt
        key: Optional key to use (if None, will load from file)
    Returns:
        The encrypted data
    """
    try:
        if key is None:
            key = load_aes_key()
            if key is None:
                raise ValueError("No key available")
                
        f = Fernet(key)
        return f.encrypt(data)
        
    except Exception as e:
        logger.error(f"Error encrypting data: {str(e)}")
        return None

def decrypt_data(encrypted_data: bytes, key: bytes = None) -> bytes:
    """
    Decrypt data using the AES key.
    Args:
        encrypted_data: The encrypted data to decrypt
        key: Optional key to use (if None, will load from file)
    Returns:
        The decrypted data
    """
    try:
        if key is None:
            key = load_aes_key()
            if key is None:
                raise ValueError("No key available")
                
        f = Fernet(key)
        return f.decrypt(encrypted_data)
        
    except Exception as e:
        logger.error(f"Error decrypting data: {str(e)}")
        return None

if __name__ == "__main__":
    # Test key generation
    key = generate_aes_key()
    if key:
        print("AES key generated successfully")
        
        # Test encryption/decryption
        test_data = b"Hello, World!"
        encrypted = encrypt_data(test_data, key)
        if encrypted:
            print("Data encrypted successfully")
            decrypted = decrypt_data(encrypted, key)
            if decrypted == test_data:
                print("Data decrypted successfully")
            else:
                print("Decryption failed") 