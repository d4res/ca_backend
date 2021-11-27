from Crypto import PublicKey
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
from cryptography.hazmat.primitives.asymmetric import padding

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


class Cert:
    # 从csr文件创建证书
    # 使用我们自己的私钥进行签名
    def __init__(self, csr: bytes, private_key: bytes):
        self.raw_obj = self.csr2cer(csr, private_key)
        self.pem = self.raw_obj.public_bytes(serialization.Encoding.PEM)
        self.serial = self.raw_obj.serial_number

    # 从pem格式bytes中直接获得证书对象
    def __init__(self, pem: bytes):
        self.raw_obj = x509.load_pem_x509_certificate(pem)
        self.pem = pem.decode()
        self.serial = self.raw_obj.serial_number

    # 获取证书的相关信息
    def info(self) -> dict:
        cert = self.raw_obj
        serial = cert.serial_number
        pub_key = (
            cert.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        subject = cert.subject
        subjectName = {n.rfc4514_attribute_name: n.value for n in subject}

        return {"serial": serial, "pub_key": pub_key, "subjectName": subjectName}

    # 从csr创建证书
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

    # 判断证书是否是我们签名的证书
    def vrfy(self, private_key: bytes):
        cert = self.raw_obj
        public_key = serialization.load_pem_private_key(
            private_key, password=None
        ).public_key()

        try:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except:
            return False
        else:
            return True
