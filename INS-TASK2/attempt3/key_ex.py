from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging
from pathlib import Path
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_dh_parameters():
    """
    Generate Diffie-Hellman parameters.
    Returns:
        DHParameters object if successful, None otherwise
    """
    try:
        parameters = dh.generate_parameters(
            generator=2,
            key_size=2048,
            backend=default_backend()
        )
        logger.info("DH parameters generated successfully")
        return parameters
    except Exception as e:
        logger.error(f"Error generating DH parameters: {str(e)}")
        return None

def generate_dh_private_key(parameters):
    """
    Generate a private key for Diffie-Hellman exchange.
    Args:
        parameters: DHParameters object
    Returns:
        DHPrivateKey object if successful, None otherwise
    """
    try:
        private_key = parameters.generate_private_key()
        logger.info("DH private key generated successfully")
        return private_key
    except Exception as e:
        logger.error(f"Error generating DH private key: {str(e)}")
        return None

def get_dh_public_key(private_key):
    """
    Get the public key from a private key.
    Args:
        private_key: DHPrivateKey object
    Returns:
        DHPublicKey object if successful, None otherwise
    """
    try:
        public_key = private_key.public_key()
        return public_key
    except Exception as e:
        logger.error(f"Error getting DH public key: {str(e)}")
        return None

def get_shared_secret(private_key, peer_public_key):
    """
    Generate a shared secret using Diffie-Hellman.
    Args:
        private_key: DHPrivateKey object
        peer_public_key: DHPublicKey object
    Returns:
        bytes: Shared secret if successful, None otherwise
    """
    try:
        shared_secret = private_key.exchange(peer_public_key)
        
        # Derive a key from the shared secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"dh_key_exchange",
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(shared_secret)
        
        logger.info("Shared secret generated successfully")
        return key
    except Exception as e:
        logger.error(f"Error generating shared secret: {str(e)}")
        return None

def save_dh_public_key(public_key, filename):
    """
    Save a DH public key to a file.
    Args:
        public_key: DHPublicKey object
        filename: Name of the file to save the key
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filename, 'wb') as f:
            f.write(public_bytes)
            
        logger.info(f"DH public key saved to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error saving DH public key: {str(e)}")
        return False

def load_dh_public_key(filename):
    """
    Load a DH public key from a file.
    Args:
        filename: Name of the file containing the public key
    Returns:
        DHPublicKey object if successful, None otherwise
    """
    try:
        with open(filename, 'rb') as f:
            public_bytes = f.read()
            
        public_key = serialization.load_pem_public_key(
            public_bytes,
            backend=default_backend()
        )
        
        return public_key
    except Exception as e:
        logger.error(f"Error loading DH public key: {str(e)}")
        return None

def save_dh_parameters(parameters, filename):
    """
    Save DH parameters to a file.
    Args:
        parameters: DHParameters object
        filename: Name of the file to save the parameters
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        parameter_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        
        with open(filename, 'wb') as f:
            f.write(parameter_bytes)
            
        logger.info(f"DH parameters saved to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error saving DH parameters: {str(e)}")
        return False

def load_dh_parameters(filename):
    """
    Load DH parameters from a file.
    Args:
        filename: Name of the file containing the parameters
    Returns:
        DHParameters object if successful, None otherwise
    """
    try:
        with open(filename, 'rb') as f:
            parameter_bytes = f.read()
            
        parameters = serialization.load_pem_parameters(
            parameter_bytes,
            backend=default_backend()
        )
        
        return parameters
    except Exception as e:
        logger.error(f"Error loading DH parameters: {str(e)}")
        return None

if __name__ == "__main__":
    # Test DH key exchange
    # Generate parameters
    parameters = generate_dh_parameters()
    if parameters:
        print("DH parameters generated successfully")
        
        # Save parameters
        if save_dh_parameters(parameters, "dh_parameters.pem"):
            print("DH parameters saved successfully")
            
            # Generate private key for Alice
            alice_private = generate_dh_private_key(parameters)
            if alice_private:
                print("Alice's private key generated successfully")
                
                # Get Alice's public key
                alice_public = get_dh_public_key(alice_private)
                if alice_public:
                    print("Alice's public key generated successfully")
                    
                    # Save Alice's public key
                    if save_dh_public_key(alice_public, "alice_public.pem"):
                        print("Alice's public key saved successfully")
                        
                        # Generate private key for Bob
                        bob_private = generate_dh_private_key(parameters)
                        if bob_private:
                            print("Bob's private key generated successfully")
                            
                            # Get Bob's public key
                            bob_public = get_dh_public_key(bob_private)
                            if bob_public:
                                print("Bob's public key generated successfully")
                                
                                # Save Bob's public key
                                if save_dh_public_key(bob_public, "bob_public.pem"):
                                    print("Bob's public key saved successfully")
                                    
                                    # Generate shared secrets
                                    alice_secret = get_shared_secret(alice_private, bob_public)
                                    bob_secret = get_shared_secret(bob_private, alice_public)
                                    
                                    if alice_secret and bob_secret and alice_secret == bob_secret:
                                        print("Shared secrets match successfully")
                                        print(f"Shared secret: {base64.b64encode(alice_secret).decode()}") 