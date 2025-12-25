"""
SSL Certificate Manager for MITM Proxy.
Generates CA certificate and dynamic domain certificates.
"""

import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CertificateManager:
    """Manages SSL certificates for MITM proxy."""
    
    def __init__(self, cert_dir: str = ".mitm_certs"):
        """Initialize certificate manager."""
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        
        self.ca_cert_path = self.cert_dir / "ca.crt"
        self.ca_key_path = self.cert_dir / "ca.key"
        
        # Cache for generated certificates
        self.cert_cache = {}
        
        # Load or generate CA certificate
        self._ensure_ca_certificate()
    
    def _ensure_ca_certificate(self):
        """Load existing CA certificate or generate a new one."""
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.info("Loading existing CA certificate")
            self._load_ca_certificate()
        else:
            logger.info("Generating new CA certificate")
            self._generate_ca_certificate()
    
    def _generate_ca_certificate(self):
        """Generate a new CA certificate and private key."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CF Bypasser MITM Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CF Bypasser CA"),
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
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Save certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Save private key
        with open(self.ca_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        self.ca_cert = cert
        self.ca_key = private_key
        
        logger.info(f"CA certificate generated and saved to {self.ca_cert_path}")
        logger.info(f"⚠️  Install {self.ca_cert_path} in your browser/system to trust MITM certificates")
    
    def _load_ca_certificate(self):
        """Load existing CA certificate and private key."""
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        with open(self.ca_key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        logger.info("CA certificate loaded successfully")
    
    def generate_domain_certificate(self, hostname: str) -> Tuple[bytes, bytes]:
        """
        Generate a certificate for a specific domain.
        Returns (cert_pem, key_pem).
        """
        # Check cache
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]
        
        logger.info(f"Generating certificate for {hostname}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CF Bypasser MITM"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName(f"*.{hostname}"),  # Wildcard
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256(), default_backend())

        # Serialize to PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Cache the result
        self.cert_cache[hostname] = (cert_pem, key_pem)

        return cert_pem, key_pem

    def get_ca_certificate_path(self) -> Path:
        """Get the path to the CA certificate file."""
        return self.ca_cert_path

