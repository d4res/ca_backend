import base64
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
from flask import current_app
import os


def encrypt(pt: str):
    return


def decrypt(ct: str):
    with open(
        os.path.join(current_app.config["CWD"], "priv_keys", "test.pem"), "rb"
    ) as f:
        rsakey = RSA.importKey(f.read())
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        pt = cipher.decrypt(base64.b64decode(ct), None)
        return pt.decode("utf-8")
