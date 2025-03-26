from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import os
from typing import Tuple
from utils import log_key_operation

class DiffieHellman:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.parameters = None
        self.private_key = None
        self.public_key = None

    def generate_parameters(self) -> dh.DHParameters:
        """Generate DH parameters."""
        self.parameters = dh.generate_parameters(
            generator=2,
            key_size=self.key_size
        )
        return self.parameters

    def generate_key_pair(self) -> Tuple[dh.DHPrivateKey, dh.DHPublicKey]:
        """Generate a new key pair."""
        if not self.parameters:
            self.generate_parameters()
        
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        
        return self.private_key, self.public_key

    def get_public_key_bytes(self) -> bytes:
        """Get the public key in bytes format."""
        if not self.public_key:
            raise ValueError("No public key generated yet")
        
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_key(self, peer_public_key_bytes: bytes) -> bytes:
        """Derive a shared key using the peer's public key."""
        if not self.private_key:
            raise ValueError("No private key generated yet")
        
        # Load peer's public key
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        
        # Generate shared key
        shared_key = self.private_key.exchange(peer_public_key)
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        return derived_key

    def save_private_key(self, filename: str):
        """Save the private key to a file."""
        if not self.private_key:
            raise ValueError("No private key to save")
        
        with open(filename, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def load_private_key(self, filename: str):
        """Load a private key from a file."""
        with open(filename, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        self.public_key = self.private_key.public_key()

class KeyExchange:
    def __init__(self):
        self.dh = DiffieHellman()
        self.shared_key = None

    def initiate_key_exchange(self) -> bytes:
        """Initiate a key exchange and return public key."""
        self.dh.generate_parameters()
        self.dh.generate_key_pair()
        return self.dh.get_public_key_bytes()

    def complete_key_exchange(self, peer_public_key: bytes) -> bytes:
        """Complete the key exchange using peer's public key."""
        self.shared_key = self.dh.derive_shared_key(peer_public_key)
        return self.shared_key

    def get_shared_key(self) -> bytes:
        """Get the derived shared key."""
        if not self.shared_key:
            raise ValueError("No shared key available")
        return self.shared_key 