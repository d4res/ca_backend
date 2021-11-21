from os import initgroups
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

with open("privatekey.pem", "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        )
    )

print("请输入相关信息")
province = input("省份: ")
city = input("城市: ")
org = input("公司/组织: ")
cname = input("域名: ")
# TODO: domain_list = input("子域名(可以为空, 空格分隔): ")

csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(
        x509.Name(
            [
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province),
                x509.NameAttribute(NameOID.LOCALITY_NAME, city),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, cname),
            ]
        )
    )
    .add_extension(
        x509.SubjectAlternativeName(
            [
                # Describe what sites we want this certificate for.
                # x509.DNSName(u"mysite.com"),
                # x509.DNSName(u"www.mysite.com"),
                # x509.DNSName(u"subdomain.mysite.com"),
                x509.DNSName(cname)
            ]
        ),
        critical=False,
        # Sign the CSR with our private key.
    )
    .sign(key, hashes.SHA256())
)
# Write our CSR out to disk.
with open("csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))
