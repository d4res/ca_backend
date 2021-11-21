from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
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


def csr2cer(csr: bytes, private_key: bytes) -> bytes:
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
    return certificate.public_bytes(serialization.Encoding.PEM)
