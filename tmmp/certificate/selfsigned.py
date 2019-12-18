from secrets import token_bytes
from tempfile import NamedTemporaryFile
from typing import Union

from .abc import CertificateManager
from ..configuration import Configuration, Configurable
from ..defaults import CERTIFICATE_ISSUER

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import \
    RSAPrivateKeyWithSerialization
from cryptography.hazmat.primitives.serialization import \
    Encoding, PrivateFormat, BestAvailableEncryption


CERTIFICATE_PASSWORD = token_bytes(32)


class SelfSignedCertificateManager(CertificateManager, Configurable):
    """
    Generate self-signed certificates for any given hostname.
    """

    def __init__(self, configuration: Configuration):
        self.keygen()
        self.issuer = configuration.configuration.get(
            "certificate_issuer", CERTIFICATE_ISSUER)
        self.certificates = {}
        super().__init__(configuration)

    def get_certificate(self, hostname: str) -> str:
        key: RSAPrivateKeyWithSerialization = self.keys["rsa"]

        if self.certificates.get(hostname) is None:
            cert_builder = CertificateManager.prepare_certificate(
                hostname
            ).add_extension(
                extension=x509.SubjectKeyIdentifier.from_public_key(
                    key.public_key()),
                critical=False
            ).issuer_name(x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, self.issuer)
            ])).public_key(
                key.public_key()
            )
            cert: x509.Certificate = cert_builder.sign(key, hashes.SHA256(),
                                                       backend=default_backend()
                                                       )

            with NamedTemporaryFile("wb", delete=False) as file:
                file.write(cert.public_bytes(Encoding.PEM))

                file.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                             BestAvailableEncryption(
                                                 CERTIFICATE_PASSWORD
                                             )))

                filename = file.name

            self.certificates[hostname] = filename

            return filename

        else:
            return self.certificates[hostname]

    def get_certificate_password(self) -> \
            Union[str, bytes, None]:
        return CERTIFICATE_PASSWORD
