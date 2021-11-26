from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import Certificate
import datetime

ca_name = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "heilongjiang"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "harbin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "hit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "hit.edu.cn"),
    ]
)

one_day = datetime.timedelta(1, 0, 0)
today = datetime.datetime.today()


class cert:
    def __init__(self, csr: bytes, private_key: bytes) -> None:
        self.raw_obj = self.csr2cer(csr, private_key)
        self.pem = self.raw_obj.public_bytes(serialization.Encoding.PEM)
        self.serial = self.raw_obj.serial_number

    def csr2cer(self, csr: bytes, private_key: bytes) -> Certificate:
        csr = x509.load_pem_x509_csr(csr)
        private_key = serialization.load_pem_private_key(private_key, password=None)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(ca_name)
        builder = builder.not_valid_before(today - one_day)
        builder = builder.not_valid_after(today + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )
        return certificate
