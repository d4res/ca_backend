from flask import Blueprint, request, json, current_app
from flask.helpers import make_response
from flask_jwt_extended.utils import get_jwt
from pymysql.cursors import DictCursor
from werkzeug.utils import send_file, send_from_directory

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
    try:
        cert = x509.Cert(csr.encode(), private_key)
    except:
        return json.jsonify({"error": 1, "msg": "pem format error"})

    sql_search = "select * from cert where username = %s"
    sql_insert = "insert into cert values(%s, %s, %s)"
    with db.con_db() as DB:
        with DB.cursor() as c:
            # TODO: return check
            ret = c.execute(sql_search, user)
            if ret != 0:
                return json.jsonify({"error": 2, "msg": "cert already exist"})
            c.execute(sql_insert, [user, cert.serial, cert.pem.decode()])
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
                    return json.jsonify({"error": 2, "msg": "用户暂未注册证书"})
    cert = x509.Cert(res.encode())
    return json.jsonify(cert.info())


# 验证证书, 无需要验证
@ca.route("/vrfy", methods=["POST"])
def vrfy():
    data = json.loads(request.get_data().decode())
    cert = x509.Cert(data["cert"].encode())
    ret = cert.vrfy(private_key)
    if ret == True:
        return json.jsonify({"error": 0, "msg": "success"})
    else:
        return json.jsonify({"error": 1, "msg": "failed"})


# TODO: check
# 根据用户名获取公钥
@ca.route("/getpub", methods=["POST"])
def getpub():
    data = json.loads(request.get_data().decode())
    username = data["username"]
    flag = data["flag"]
    with db.con_db() as DB:
        with DB.cursor() as c:
            sql = "select cert from cert where username=%s"
            ret = c.execute(sql, username)
            if ret == 0:
                return json.jsonify(
                    {
                        "success": True,
                        "code": 20000,
                        "message": "成功",
                        "data": {"error": 1, "msg": "fail"},
                    }
                )
            else:
                res = c.fetchone()[0]
                cert = x509.Cert(res.encode())
                pub_key = cert.info()["pub_key"]
                if flag == 0:
                    pub_key = pub_key.replace("-----BEGIN PUBLIC KEY-----", "").replace(
                        "-----END PUBLIC KEY-----", ""
                    )
                return json.jsonify(
                    {
                        "success": True,
                        "code": 20000,
                        "message": "成功",
                        "data": {
                            "error": 0,
                            "username": username,
                            "public_key": pub_key,
                        },
                    }
                )


# 撤销证书
@ca.route("/revoke", methods=["POST"])
@jwt_required(locations=["cookies"])
def revoke():
    data = json.loads(request.get_data().decode())
    serial = data["serial"]
    username = get_jwt_identity()

    with db.con_db() as DB:
        with DB.cursor() as c:
            sql = "select username from cert where serial=%s"
            ret = c.execute(sql, serial)
            if ret == 0:
                return json.jsonify({"error": 2, "msg": "cert not found"})
            res = c.fetchone()[0]
            if res != username and username != "admin":
                return json.jsonify(
                    {"error": 1, "msg": "only admin can revoke other user's cert"}
                )
            sql = "delete from cert where serial = %s"
            ret = c.execute(sql, serial)
        DB.commit()
    return json.jsonify({"error": 0, "msg": "success"})


@ca.route("/usrinfo", methods=["POST"])
@jwt_required(locations=["cookies"])
def usrinfo():

    username = get_jwt_identity()
    resp = {"error": 0, "username": username, "serial": "", "role": "普通用户"}
    if username == "admin":
        resp["role"] = "管理员"
        return json.jsonify(resp)

    with db.con_db() as DB:
        with DB.cursor(DictCursor) as c:
            sql = "select username from user where username = %s"
            ret = c.execute(sql, username)
            if ret == 0:
                return json.jsonify({"error": 1, "msg": "username not found"})
            sql = "select username, serial from cert where username=%s"
            ret = c.execute(sql, username)
            if ret != 0:
                res = c.fetchall()[0]
                resp["serial"] = res["serial"]
                return json.jsonify(resp)
            return json.jsonify(resp)
