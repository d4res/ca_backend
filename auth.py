from flask import Blueprint, request, json, current_app
import bcrypt
from flask.cli import with_appcontext
from pymysql import DATE
from . import db
from . import aes, rsa
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_csrf_token,
)
from . import rsa

auth = Blueprint("auth", __name__, url_prefix="/auth")


@auth.route("/register", methods=["POST"])
def register():
    # json_data = json.loads(request.get_data().decode())
    # username = json_data["username"]
    # password = json_data["password"]
    # password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    json_data = json.loads(request.get_data().decode())
    ct_username = json_data["username"]
    ct_password = json_data["password"]
    ct_key = json_data["aes_key"]
    ct_iv = json_data["aes_iv"]
    key = rsa.decrypt(ct_key)
    iv = rsa.decrypt(ct_iv)
    username = aes.decrypt(key, iv, ct_username)
    password = aes.decrypt(key, iv, ct_password)
    # print(username)
    # print(password)
    password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # TODO: pay attention to the sql injection.
    # addtion: evidence may show that pymysql will help us do the string escape
    search_sql = "select username from user where username=%s"
    insert_sql = "insert into user values(default, %s, %s)"

    with db.con_db() as DB:
        with DB.cursor() as c:
            ret = c.execute(search_sql, username)
            if ret != 0:
                return json.jsonify({"error": "1", "msg": "user already exist"})
            c.execute(insert_sql, (username, password))
        DB.commit()

    return json.jsonify({"error": "0", "msg": "成功注册"})


@auth.route("/login", methods=["POST"])
def login():
    json_data = json.loads(request.get_data().decode())
    ct_username = json_data["username"]
    ct_password = json_data["password"]
    ct_key = json_data["aes_key"]
    ct_iv = json_data["aes_iv"]
    key = rsa.decrypt(ct_key)
    iv = rsa.decrypt(ct_iv)
    username = aes.decrypt(key, iv, ct_username)
    password = aes.decrypt(key, iv, ct_password)
    print(username)
    print(password)
    sql = "select password from user where username = %s"
    with db.con_db() as DB:
        with DB.cursor() as c:
            ret = c.execute(sql, username)
            if ret == 0:
                return json.jsonify({"error": "1", "msg": "user does not exist"})
            res = c.fetchone()[0]
            if bcrypt.checkpw(password.encode(), res.encode()):
                access_token = create_access_token(identity=username)
                csrf_token = get_csrf_token(access_token)
                req = json.jsonify(
                    {
                        "error": "0",
                        "access_token_cookie": access_token,
                        "msg": "login success",
                    }
                )

                req.set_cookie(
                    key="access_token_cookie",
                    value=access_token,
                    samesite="Strict",
                    httponly=True,
                )
                req.set_cookie(key="X-CSRF-TOKEN", value=csrf_token, samesite="Strict")
                return req
            else:
                return json.jsonify({"error": "1", "msg": "login failed"})


@auth.route("/check", methods=["POST"])
@jwt_required(locations=["cookies"])
def check():
    user = get_jwt_identity()
    return json.jsonify({"error": "0", "user": user, "msg": "valid"})


@auth.route("/kex", methods=["POST"])
def kex():
    json_data = json.loads(request.get_data().decode())
    aes_key = json_data["aes_key"]
    aes_iv = json_data["aes_iv"]
    from . import rsa

    print(current_app.config["CWD"])
    print(rsa.decrypt(aes_key))
    return "todo"


@auth.route("/echo", methods=["POST"])
def echo():
    from . import aes

    print(request.get_data().decode())
    json_data = json.loads(request.get_data().decode())
    print(aes.decrypt(aes.aes_key, aes.aes_iv, json_data["ct"]))
    return json.jsonify(
        {"ct": aes.encrypt(aes.aes_key, aes.aes_iv, "hello from server")}
    )
