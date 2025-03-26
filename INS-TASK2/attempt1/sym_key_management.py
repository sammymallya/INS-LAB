#for implementing symmetric key 
#for key generation
from cryptography.fernet import Fernet
import secrets
import os
from typing import Optional
from utils import log_key_operation

def generate_symmetric_key(key_size: int = 32) -> bytes:
    """
    Generate a cryptographically secure symmetric key.
    
    Args:
        key_size: Size of the key in bytes (default: 32 bytes = 256 bits)
    
    Returns:
        bytes: The generated key
    """
    key = secrets.token_bytes(key_size)
    log_key_operation("generate", "sym_key", "success", f"Generated {key_size}-byte key")
    return key

class SymmetricKeyManager:
    def __init__(self, key_size: int = 32):
        self.key_size = key_size
        self.key = None

    def generate_key(self) -> bytes:
        """Generate a new symmetric key."""
        self.key = generate_symmetric_key(self.key_size)
        return self.key

    def get_key(self) -> Optional[bytes]:
        """Get the current key if it exists."""
        return self.key

    def rotate_key(self) -> bytes:
        """Generate a new key and invalidate the old one."""
        old_key = self.key
        self.key = self.generate_key()
        log_key_operation("rotate", "sym_key", "success", "Key rotated")
        return self.key

    def save_key(self, filepath: str):
        """Save the key to a file."""
        if not self.key:
            raise ValueError("No key to save")
        
        with open(filepath, 'wb') as f:
            f.write(self.key)
        log_key_operation("save", "sym_key", "success", f"Saved to {filepath}")

    def load_key(self, filepath: str):
        """Load a key from a file."""
        with open(filepath, 'rb') as f:
            self.key = f.read()
        log_key_operation("load", "sym_key", "success", f"Loaded from {filepath}")

    def clear_key(self):
        """Clear the current key from memory."""
        if self.key:
            # Overwrite the key in memory with random data
            self.key = secrets.token_bytes(self.key_size)
            self.key = None
        log_key_operation("clear", "sym_key", "success", "Key cleared from memory")

def create_symmetric_key_manager(key_size: int = 32) -> SymmetricKeyManager:
    """
    Factory function to create a SymmetricKeyManager instance.
    
    Args:
        key_size: Size of the key in bytes (default: 32 bytes = 256 bits)
    
    Returns:
        SymmetricKeyManager: A new key manager instance
    """
    return SymmetricKeyManager(key_size)



