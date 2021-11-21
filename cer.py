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
from flask import current_app
import os

# CA NAME

ca_name = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "heilongjiang"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "harbin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "hit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "hit.edu.cn"),
    ]
)


with open("./csr.pem", "rb") as f:
    pem_req_data = f.read()
    csr = x509.load_pem_x509_csr(pem_req_data)
    print(csr.subject)
    print(csr.signature_hash_algorithm)
    print(csr.is_signature_valid)


## run with flask
# with open(os.path.join(current_app.config["CWD"], "priv_keys", "test.pem"), "rb") as f:
#     privatekey = RSA.import_key(f.read())

with open("./priv_keys/test.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

print(private_key)
builder = x509.CertificateBuilder()
builder = builder.subject_name(csr.subject)
builder = builder.issuer_name(ca_name)


one_day = datetime.timedelta(1, 0, 0)
today = datetime.datetime.today()

builder = builder.not_valid_before(today - one_day)
builder = builder.not_valid_after(today + (one_day * 30))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(csr.public_key())

certificate = builder.sign(
    private_key=private_key,
    algorithm=hashes.SHA256(),
)

print(certificate.public_bytes(serialization.Encoding.PEM))
