from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import logging
from pathlib import Path
import json
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CertificateAuthority:
    def __init__(self):
        self.ca_private_key = None
        self.ca_public_key = None
        self.users = {}
        self.load_or_create_ca()

    def load_or_create_ca(self):
        """Load or create CA key pair."""
        try:
            ca_dir = Path("ca")
            ca_dir.mkdir(exist_ok=True)
            
            private_key_path = ca_dir / "ca_private_key.pem"
            public_key_path = ca_dir / "ca_public_key.pem"
            
            if private_key_path.exists() and public_key_path.exists():
                # Load existing CA keys
                with open(private_key_path, "rb") as f:
                    self.ca_private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                with open(public_key_path, "rb") as f:
                    self.ca_public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
            else:
                # Generate new CA keys
                self.ca_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                self.ca_public_key = self.ca_private_key.public_key()
                
                # Save CA keys
                with open(private_key_path, "wb") as f:
                    f.write(self.ca_private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                with open(public_key_path, "wb") as f:
                    f.write(self.ca_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                
            logger.info("CA initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing CA: {str(e)}")
            raise

    def register_user(self, user_id, user_public_key):
        """
        Register a new user and issue a certificate.
        Args:
            user_id: Unique user identifier
            user_public_key: User's public key
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if user_id in self.users:
                logger.warning(f"User {user_id} already registered")
                return False

            # Create certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, user_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "User Certificate"),
            ])

            issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Certificate Authority"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA Organization"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                user_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(user_id)]),
                critical=False,
            ).sign(self.ca_private_key, hashes.SHA256(), default_backend())

            # Save user certificate
            user_dir = Path("users") / user_id
            user_dir.mkdir(parents=True, exist_ok=True)
            
            cert_path = user_dir / "certificate.pem"
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Store user information
            self.users[user_id] = {
                "certificate": cert,
                "public_key": user_public_key,
                "registered": datetime.utcnow().isoformat()
            }

            logger.info(f"User {user_id} registered successfully")
            return True

        except Exception as e:
            logger.error(f"Error registering user {user_id}: {str(e)}")
            return False

    def verify_user_certificate(self, user_id, certificate):
        """
        Verify a user's certificate.
        Args:
            user_id: User identifier
            certificate: User's certificate
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            if user_id not in self.users:
                logger.error(f"User {user_id} not found")
                return False

            stored_cert = self.users[user_id]["certificate"]
            
            # Compare certificates
            if stored_cert.serial_number != certificate.serial_number:
                logger.error("Certificate serial numbers don't match")
                return False
                
            if stored_cert.issuer != certificate.issuer:
                logger.error("Certificate issuers don't match")
                return False
                
            if stored_cert.subject != certificate.subject:
                logger.error("Certificate subjects don't match")
                return False

            # Check expiration
            if datetime.utcnow() > certificate.not_valid_after:
                logger.error("Certificate has expired")
                return False

            logger.info(f"User {user_id} certificate verified successfully")
            return True

        except Exception as e:
            logger.error(f"Error verifying user certificate: {str(e)}")
            return False

    def revoke_user_certificate(self, user_id):
        """
        Revoke a user's certificate.
        Args:
            user_id: User identifier
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if user_id not in self.users:
                logger.error(f"User {user_id} not found")
                return False

            # Remove user certificate
            user_dir = Path("users") / user_id
            cert_path = user_dir / "certificate.pem"
            if cert_path.exists():
                cert_path.unlink()

            # Remove user from registry
            del self.users[user_id]

            logger.info(f"User {user_id} certificate revoked successfully")
            return True

        except Exception as e:
            logger.error(f"Error revoking user certificate: {str(e)}")
            return False

    def get_user_certificate(self, user_id):
        """
        Get a user's certificate.
        Args:
            user_id: User identifier
        Returns:
            X509Certificate object if found, None otherwise
        """
        try:
            if user_id not in self.users:
                logger.error(f"User {user_id} not found")
                return None

            return self.users[user_id]["certificate"]

        except Exception as e:
            logger.error(f"Error getting user certificate: {str(e)}")
            return None

# Global CA instance
ca = CertificateAuthority()

if __name__ == "__main__":
    # Test CA functionality
    test_user_id = "test_user"
    test_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    test_public_key = test_private_key.public_key()

    if ca.register_user(test_user_id, test_public_key):
        print(f"User {test_user_id} registered successfully")
        
        cert = ca.get_user_certificate(test_user_id)
        if cert and ca.verify_user_certificate(test_user_id, cert):
            print("User certificate verified successfully")
            
            if ca.revoke_user_certificate(test_user_id):
                print("User certificate revoked successfully") 