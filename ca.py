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

# with open(os.path.join(current_app.config["CWD"], "priv_keys", "test.pem"), "rb") as f:
#     private_key = f.read()

with open(os.path.join("ca_backend", "priv_keys", "test.pem"), "rb") as f:
    private_key = f.read()

# 根据传入的csr文件，生成ca签名好的证书文件
@ca.route("/getcert", methods=["POST"])
@jwt_required(locations=["cookies"])
def getcert():
    data = json.loads(request.get_data().decode())
    csr = data["csr"]
    user = get_jwt_identity()
    cert = x509.Cert(csr.encode(), private_key)
    sql = "insert into cert values(%s, %s, %s)"
    print(cert.pem)
    with db.con_db() as DB:
        with DB.cursor() as c:
            # TODO: return check
            ret = c.execute(sql, [user, cert.serial, cert.pem.decode()])
        DB.commit()

    # cert = x509.csr2cer(csr.encode(), private_key)
    return json.jsonify({"cert": cert.pem.decode()})


# 下载证书
@ca.route("/download", methods=["POST"])
@jwt_required(locations=["cookies"])
def download():
    data = json.loads(request.get_data().decode())
    user = get_jwt_identity()
    if data["serial"] != "":  # 通过序列号进行查找
        serial = data["serial"]
        sql = "select cert from cert where serial = %s"
        with db.con_db() as DB:
            with DB.cursor() as c:
                ret = c.execute(sql, serial)
                if ret != 0:
                    res = c.fetchone()[0]
                    return json.jsonify({"error": 0, "msg": "success", "cert": res})
                else:
                    return json.jsonify({"error": 1, "msg": "没有与序列号对应的证书"})
    else:  # 通过已经登录的用户名进行查找
        with db.con_db() as DB:
            with DB.cursor() as c:
                sql = "select cert from cert where username = %s"
                ret = c.execute(sql, user)
                if ret != 0:
                    res = c.fetchone()[0]
                    return json.jsonify({"error": 0, "msg": "success", "cert": res})
                else:
                    return json.jsonify({"error": 1, "msg": "用户暂未注册证书"})


# 获取证书相关信息
@ca.route("/info", methods=["POST"])
@jwt_required(locations=["cookies"])
def info():
    data = json.loads(request.get_data().decode())
    user = get_jwt_identity()
    if data["serial"] != "":  # 通过序列号进行查找
        serial = data["serial"]
        sql = "select cert from cert where serial = %s"
        with db.con_db() as DB:
            with DB.cursor() as c:
                ret = c.execute(sql, serial)
                if ret != 0:
                    res = c.fetchone()[0]
                else:
                    return json.jsonify({"error": 1, "msg": "没有与序列号对应的证书"})
    else:  # 通过已经登录用户进行查找
        with db.con_db() as DB:
            with DB.cursor() as c:
                sql = "select cert from cert where username = %s"
                ret = c.execute(sql, user)
                if ret != 0:
                    res = c.fetchone()[0]
                else:
                    return json.jsonify({"error": 1, "msg": "用户暂未注册证书"})
    cert = x509.cert(res.encode())
    return json.jsonify(cert.info())


# 验证证书
@ca.route("/vrfy", methods=["POST"])
@jwt_required(locations=["cookies"])
def vrfy():
    data = json.loads(request.get_data().decode())
    cert = x509.Cert(data["cert"].encode())
    ret = cert.vrfy(private_key)
    if ret == True:
        return json.jsonify({"error": 0, "msg": "success"})
    else:
        return json.jsonify({"error": 1, "msg": "failed"})
