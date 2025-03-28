from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import logging
from pathlib import Path
from rsagen import load_rsa_keys

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_x509_certificate(
    subject_name="localhost",
    organization="Test Organization",
    country="US",
    validity_days=365
):
    """
    Generate a self-signed X.509 certificate.
    Args:
        subject_name: Common name for the certificate
        organization: Organization name
        country: Country code
        validity_days: Number of days the certificate is valid
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Load RSA keys
        private_key, public_key = load_rsa_keys()
        if not private_key or not public_key:
            logger.error("RSA keys not found")
            return False

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject_name)]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Create certificates directory if it doesn't exist
        cert_dir = Path("certificates")
        cert_dir.mkdir(exist_ok=True)

        # Save certificate
        cert_path = cert_dir / "certificate.pem"
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info("X.509 certificate generated successfully")
        return True

    except Exception as e:
        logger.error(f"Error generating X.509 certificate: {str(e)}")
        return False

def load_certificate(cert_path="certificates/certificate.pem"):
    """
    Load an X.509 certificate from a file.
    Args:
        cert_path: Path to the certificate file
    Returns:
        X509Certificate object if successful, None otherwise
    """
    try:
        cert_path = Path(cert_path)
        if not cert_path.exists():
            logger.error(f"Certificate file {cert_path} not found")
            return None

        with open(cert_path, "rb") as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        return cert

    except Exception as e:
        logger.error(f"Error loading certificate: {str(e)}")
        return None

def verify_certificate(cert):
    """
    Verify an X.509 certificate.
    Args:
        cert: X509Certificate object
    Returns:
        bool: True if certificate is valid, False otherwise
    """
    try:
        # Check if certificate is expired
        if datetime.utcnow() > cert.not_valid_after:
            logger.error("Certificate has expired")
            return False

        # Check if certificate is not yet valid
        if datetime.utcnow() < cert.not_valid_before:
            logger.error("Certificate is not yet valid")
            return False

        # Load the public key from the certificate
        public_key = cert.public_key()

        # Verify the certificate signature
        cert.verify_directly_issued_by(cert)
        
        logger.info("Certificate verification successful")
        return True

    except Exception as e:
        logger.error(f"Error verifying certificate: {str(e)}")
        return False

def get_certificate_info(cert):
    """
    Get information about an X.509 certificate.
    Args:
        cert: X509Certificate object
    Returns:
        dict: Certificate information
    """
    try:
        info = {
            "subject": dict(cert.subject),
            "issuer": dict(cert.issuer),
            "serial_number": cert.serial_number,
            "not_valid_before": cert.not_valid_before,
            "not_valid_after": cert.not_valid_after,
            "version": cert.version,
            "extensions": []
        }

        for ext in cert.extensions:
            info["extensions"].append({
                "oid": ext.oid.dotted_string,
                "value": str(ext.value),
                "critical": ext.critical
            })

        return info

    except Exception as e:
        logger.error(f"Error getting certificate info: {str(e)}")
        return None

def revoke_certificate(cert_path="certificates/certificate.pem"):
    """
    Revoke an X.509 certificate.
    Args:
        cert_path: Path to the certificate file
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Load the certificate
        cert = load_certificate(cert_path)
        if not cert:
            return False

        # Create a revocation list
        crl = x509.CertificateRevocationListBuilder().issuer_name(
            cert.issuer
        ).last_update(
            datetime.utcnow()
        ).next_update(
            datetime.utcnow() + timedelta(days=1)
        ).add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(
                cert.serial_number
            ).revocation_date(
                datetime.utcnow()
            ).build(default_backend())
        ).sign(
            cert.private_key(),
            hashes.SHA256(),
            default_backend()
        )

        # Save the CRL
        crl_path = Path("certificates") / "revocation.crl"
        with open(crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        logger.info("Certificate revoked successfully")
        return True

    except Exception as e:
        logger.error(f"Error revoking certificate: {str(e)}")
        return False

if __name__ == "__main__":
    # Test certificate generation
    if generate_x509_certificate():
        print("Certificate generated successfully")
        
        # Load and verify certificate
        cert = load_certificate()
        if cert:
            print("Certificate loaded successfully")
            
            # Get certificate information
            info = get_certificate_info(cert)
            if info:
                print("Certificate information:")
                print(f"Subject: {info['subject']}")
                print(f"Issuer: {info['issuer']}")
                print(f"Serial Number: {info['serial_number']}")
                print(f"Valid from: {info['not_valid_before']}")
                print(f"Valid until: {info['not_valid_after']}")
                
                # Verify certificate
                if verify_certificate(cert):
                    print("Certificate verification successful")
                    
                    # Test certificate revocation
                    if revoke_certificate():
                        print("Certificate revoked successfully") 