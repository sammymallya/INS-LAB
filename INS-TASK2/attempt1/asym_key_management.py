from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import NameAttribute, Name
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
from typing import Tuple, Optional
from utils import log_key_operation

class AsymmetricKeyManager:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.certificate = None

    def generate_key_pair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate a new RSA key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key

    def save_key_pair(self, private_key_path: str, public_key_path: str):
        """Save the key pair to files."""
        if not self.private_key or not self.public_key:
            raise ValueError("No key pair to save")

        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_key_pair(self, private_key_path: str, public_key_path: str):
        """Load a key pair from files."""
        # Load private key
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        # Load public key
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using the public key."""
        if not self.public_key:
            raise ValueError("No public key available")
        
        return self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using the private key."""
        if not self.private_key:
            raise ValueError("No private key available")
        
        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data using the private key."""
        if not self.private_key:
            raise ValueError("No private key available")
        
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature using the public key."""
        if not self.public_key:
            raise ValueError("No public key available")
        
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

class CertificateManager:
    def __init__(self):
        self.certificate = None

    def create_self_signed_certificate(
        self,
        private_key: rsa.RSAPrivateKey,
        common_name: str,
        organization: str,
        country: str,
        validity_days: int = 365
    ):
        """Create a self-signed certificate."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        self.certificate = cert

    def save_certificate(self, path: str):
        """Save the certificate to a file."""
        if not self.certificate:
            raise ValueError("No certificate to save")
        
        with open(path, 'wb') as f:
            f.write(self.certificate.public_bytes(serialization.Encoding.PEM))

    def load_certificate(self, path: str):
        """Load a certificate from a file."""
        with open(path, 'rb') as f:
            self.certificate = x509.load_pem_x509_certificate(f.read()) 