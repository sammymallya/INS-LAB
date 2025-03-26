import os
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='key_management.log'
)

logger = logging.getLogger(__name__)

def generate_master_key(password: str, salt: bytes = None) -> bytes:
    """Generate a master key from a password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.decrypt(encrypted_data)

def generate_key_id() -> str:
    """Generate a unique key ID."""
    return f"key_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"

def validate_key(key: bytes) -> bool:
    """Basic validation of a key."""
    return len(key) >= 32  # Minimum key length check

def log_key_operation(operation: str, key_id: str, status: str, details: str = None):
    """Log key operations for audit trail."""
    log_message = f"Operation: {operation}, Key ID: {key_id}, Status: {status}"
    if details:
        log_message += f", Details: {details}"
    logger.info(log_message) 