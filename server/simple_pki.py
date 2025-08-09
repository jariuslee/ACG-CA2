# server/simple_pki.py - SERVER-SIDE PKI (Full Implementation)
# Place this file in your server/ directory
# IMPORTANT: This file is incharge of creating/loading the CA, signs user certificates, and verifies cert on the server

import os
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding, rsa, ec, ed25519

class SimpleCertificateAuthority:
    """
    SERVER-SIDE Certificate Authority that can create and verify certificates.
    
    This version includes:
    - CA creation and management
    - Secure certificate issuance
    - Certificate verification
    """
    
    def __init__(self, ca_name: str = "SecureMessaging CA"):
        self.ca_name = ca_name
        self.ca_private_key = None
        self.ca_certificate = None
        self.ca_directory = "ca_data"
        
        # SECURITY: Track issued certificates to prevent duplicates
        self.issued_certificates = {}
        
        # Create CA directory
        if not os.path.exists(self.ca_directory):
            os.makedirs(self.ca_directory)
        
        # Load or create CA
        self._setup_ca()
    
    def _setup_ca(self):
        """Load existing CA or create new self-signed CA."""
        ca_key_file = os.path.join(self.ca_directory, "ca_key.pem")
        ca_cert_file = os.path.join(self.ca_directory, "ca_cert.pem")
        
        if os.path.exists(ca_key_file) and os.path.exists(ca_cert_file):
            print("📋 Loading existing CA...")
            self._load_ca(ca_key_file, ca_cert_file)
        else:
            print("🆕 Creating new self-signed CA...")
            self._create_ca(ca_key_file, ca_cert_file)

    # 1) CA Creation or loading at server start
    def _create_ca(self, key_file: str, cert_file: str):
        """Create new self-signed Certificate Authority."""
        print("🔑 Generating CA key pair...")
        
        # Generate CA private key
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create self-signed CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IT2504 SecureMessaging"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        
        # Build CA certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(self.ca_private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))
        
        # Add basic CA extensions
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        
        # Self-sign the certificate
        self.ca_certificate = cert_builder.sign(self.ca_private_key, hashes.SHA256())
        
        # Save CA files in PEM format
        with open(key_file, "wb") as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(cert_file, "wb") as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
        
        print(f"✅ Self-signed CA created and saved")
    
    def _load_ca(self, key_file: str, cert_file: str):
        """Load existing CA from files."""
        try:
            # Load CA private key
            with open(key_file, "rb") as f:
                self.ca_private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            
            # Load CA certificate
            with open(cert_file, "rb") as f:
                self.ca_certificate = x509.load_pem_x509_certificate(f.read())
            
            print(f"✅ CA loaded successfully")
            
        except Exception as e:
            print(f"❌ Failed to load CA: {e}")
            raise
    
    def get_ca_certificate_pem(self) -> str:
        """Get CA certificate in PEM format for clients."""
        return self.ca_certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    def load_ca_certificate_pem(self, pem: str) -> None: # Loads the servers CA cert into the verifier
        """Load CA certificate from PEM string."""
        self.ca_certificate = x509.load_pem_x509_certificate(pem.encode('utf-8'))
    

    # 2) Issuing a user certificate when keys are uploaded
    def issue_user_certificate_authenticated(self, authenticated_username: str, 
                                           ed25519_public_key: str, x25519_public_key: str) -> str:
        """
        🔒 SECURE VERSION: Issue certificate only for authenticated user.
        """
        try:
            print(f"🔒 SECURE: Issuing certificate for AUTHENTICATED user: {authenticated_username}")
            
            # Create certificate subject
            subject = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IT2504 SecureMessaging"),
                x509.NameAttribute(NameOID.COMMON_NAME, authenticated_username),
            ])
            
            # Use CA's public key as certificate public key
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(self.ca_certificate.subject)
            cert_builder = cert_builder.public_key(self.ca_private_key.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(datetime.utcnow())
            cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
            
            # Store user's actual keys in certificate extension
            user_keys_data = {
                "username": authenticated_username,
                "ed25519_public_key": ed25519_public_key,
                "x25519_public_key": x25519_public_key,
                "issued_at": datetime.utcnow().isoformat(),
                "issued_to_authenticated_user": True
            }
            
            # Add custom extension with user keys
            cert_builder = cert_builder.add_extension(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9"),
                    value=json.dumps(user_keys_data).encode('utf-8')
                ),
                critical=False
            )
            
            # Sign certificate with CA private key
            certificate = cert_builder.sign(self.ca_private_key, hashes.SHA256())
            
            # Track issued certificate
            self.issued_certificates[authenticated_username] = {
                'ed25519_public_key': ed25519_public_key,
                'x25519_public_key': x25519_public_key,
                'issued_at': datetime.utcnow().isoformat()
            }
            
            # Return PEM format
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            print(f"✅ SECURE certificate issued for authenticated user: {authenticated_username}")
            return cert_pem
            
        except Exception as e:
            print(f"❌ Failed to issue certificate: {e}")
            raise
    
    def issue_user_certificate(self, username: str, ed25519_public_key: str, 
                              x25519_public_key: str) -> str:
        """Legacy method for backward compatibility."""
        print(f"⚠️ WARNING: Using legacy certificate issuance for {username}")
        
        try:
            subject = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IT2504 SecureMessaging"),
                x509.NameAttribute(NameOID.COMMON_NAME, username),
            ])
            
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(self.ca_certificate.subject)
            cert_builder = cert_builder.public_key(self.ca_private_key.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(datetime.utcnow())
            cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
            
            user_keys_data = {
                "username": username,
                "ed25519_public_key": ed25519_public_key,
                "x25519_public_key": x25519_public_key,
                "issued_at": datetime.utcnow().isoformat(),
                "issued_to_authenticated_user": False
            }
            
            cert_builder = cert_builder.add_extension(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9"),
                    value=json.dumps(user_keys_data).encode('utf-8')
                ),
                critical=False
            )
            
            certificate = cert_builder.sign(self.ca_private_key, hashes.SHA256())
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            print(f"✅ Legacy certificate issued for: {username}")
            return cert_pem
            
        except Exception as e:
            print(f"❌ Failed to issue certificate: {e}")
            raise
    

    # 3) Verifying a user certificate
    def verify_user_certificate(self, certificate_pem: str) -> Tuple[bool, Optional[Dict]]:
        """Verify a user's certificate and extract their keys."""
        try:
            print("🔍 Verifying user certificate...")

            # Load cert
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))

            # Verify CA signature
            ca_public_key = self.ca_certificate.public_key()
            try:
                if isinstance(ca_public_key, rsa.RSAPublicKey):
                    ca_public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        asy_padding.PKCS1v15(),
                        certificate.signature_hash_algorithm,
                    )
                elif isinstance(ca_public_key, ed25519.Ed25519PublicKey):
                    ca_public_key.verify(certificate.signature, certificate.tbs_certificate_bytes)
                elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                    ca_public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        ec.ECDSA(certificate.signature_hash_algorithm),
                    )
                else:
                    print("❌ Unsupported CA key type")
                    return False, None
            except Exception as e:
                print(f"❌ Certificate signature invalid: {e}")
                return False, None

            # Check issuer
            if certificate.issuer != self.ca_certificate.subject:
                print("❌ Certificate not issued by our CA")
                return False, None

            # Check validity
            now = datetime.utcnow()
            if now < certificate.not_valid_before or now > certificate.not_valid_after:
                print("❌ Certificate expired or not yet valid")
                return False, None

            # Extract user data from custom extension
            user_data = None
            for extension in certificate.extensions:
                if extension.oid.dotted_string == "1.2.3.4.5.6.7.8.9":
                    try:
                        # cryptography exposes UnrecognizedExtension.value which contains .value bytes
                        raw_value = getattr(extension.value, 'value', extension.value)
                        user_data = json.loads(raw_value.decode('utf-8'))
                        break
                    except Exception as parse_error:
                        print(f"❌ Failed to parse user data extension: {parse_error}")
                        user_data = None

            if not user_data:
                print("❌ Certificate missing user data")
                return False, None

            print(f"✅ Certificate verified for user: {user_data['username']}")
            return True, user_data

        except Exception as e:
            print(f"❌ Certificate verification failed: {e}")
            return False, None

if __name__ == "__main__":
    # Test CA creation
    ca = SimpleCertificateAuthority("Test CA")
    print("✅ Server-side CA test completed")