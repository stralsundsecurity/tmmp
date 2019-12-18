from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, Union
from uuid import uuid4

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography import x509
from cryptography.x509 import CertificateBuilder
from cryptography.x509.oid import NameOID


class CertificateManager(ABC):
    """
    A CertificateManager creates x509 certificates for the TLS proxy.

    It contains an internal keystore for the on-the-fly generation of certificates.
    """
    keys: Dict[str, Any] = {}

    @abstractmethod
    def get_certificate(self, hostname: str) -> str:
        """Creates an x509 certificate in PEM format for the given hostname and
        returns a filename to the certificate."""


    @abstractmethod
    def get_certificate_password(self) \
            -> Union[str, bytes, None]:
        """Returns the password for a previously generated certificate."""

    def keygen(self):
        """Prepares the keys."""
        self.keys["rsa"] = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=default_backend()
        )
        self.keys["ecdsa"] = ec.generate_private_key(
            ec.SECP256R1, default_backend()
        )

    @staticmethod
    def prepare_certificate(hostname):
        # Mostly from:
        # https://www.programcreek.com/python/example/102792/
        #   cryptography.x509.CertificateBuilder
        return CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        ).add_extension(
            extension=x509.SubjectAlternativeName([
                x509.DNSName(hostname)
            ]),
            critical=False
        ).add_extension(
            extension=x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False
            ),
            critical=True
        ).add_extension(
            extension=x509.BasicConstraints(
                ca=False,
                path_length=None
            ),
            critical=True
        ).serial_number(
            uuid4().int
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365 * 10)
        )
