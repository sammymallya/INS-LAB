import secrets

def generate_symmetric_key(key_size: int = 32) -> bytes:
    """
    Generate a cryptographically secure symmetric key.
    
    Args:
        key_size: Size of the key in bytes (default: 32 bytes = 256 bits)
    
    Returns:
        bytes: The generated key
    """
    return secrets.token_bytes(key_size) 