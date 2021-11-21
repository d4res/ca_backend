import base64
from ssl import DefaultVerifyPaths
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask.json import jsonify

# all using CBC mode

aes_key = "rMQ6l3zYSERlfDlzwRaAosUGhoLMHX1Q4NWzwm+CJ7g="
aes_iv = "fx1fN+u2HfN794g6jujQlg=="


def decrypt(key, iv, ct):
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    # mode = AES.MODE_CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(pt)
    data = data + unpadder.finalize()

    return data.decode()


def encrypt(key, iv, pt):
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    pt = pt.encode()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_pt = padder.update(pt) + padder.finalize()

    ct = encryptor.update(padded_pt) + encryptor.finalize()
    ct = base64.b64encode(ct).decode()
    print(decrypt(aes_key, aes_iv, ct))
    return ct
