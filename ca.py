from flask import Blueprint, request, json, current_app
from flask_jwt_extended.utils import get_jwt

from . import x509
from . import db
from . import aes, rsa
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_csrf_token,
)
from . import rsa
from . import x509
import os

ca = Blueprint("ca", __name__, url_prefix="/ca")


# 根据传入的csr文件，生成ca签名好的证书文件
@ca.route("/getcert", methods=["POST"])
@jwt_required(locations=["cookies"])
def getcert():

    with open(
        os.path.join(current_app.config["CWD"], "priv_keys", "test.pem"), "rb"
    ) as f:
        private_key = f.read()
    data = json.loads(request.get_data().decode())
    csr = data["csr"]
    user = get_jwt_identity()
    cert = x509.cert(csr.encode(), private_key)
    sql = "insert into cert values(%s, %s, %s)"
    print(cert.pem)
    with db.con_db() as DB:
        with DB.cursor() as c:
            # TODO: return check
            ret = c.execute(sql, [user, cert.serial, cert.pem.decode()])
        DB.commit()

    # cert = x509.csr2cer(csr.encode(), private_key)
    return json.jsonify({"cert": cert.pem.decode()})


# 获取证书相关信息
@ca.route("/cerinfo", methods=["POST"])
@jwt_required(locations=["cookies"])
def info():
    raise NotImplementedError


# 验证证书
@ca.route("/vrfy", methods=["POST"])
@jwt_required(locations=["cookies"])
def vrfy():
    raise NotImplementedError
