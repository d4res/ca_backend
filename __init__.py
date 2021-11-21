import os
from flask import Flask
from . import db
from . import auth
from . import ca
from flask_cors import CORS
from flask_jwt_extended import JWTManager


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    CORS(app, supports_credentials=True)
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE={
            "user": "ca",
            "password": "p4ssvvd",
            "database": "ca",
        },
        JWT_SECRET_KEY="secret",  # TODO: change this
        JWT_TOKEN_LOCATION=["cookies"],
        PROJECT_NAME=os.environ.get("FLASK_APP"),
        CWD=os.path.join(os.getcwd(), os.environ.get("FLASK_APP")),
    )

    if test_config is None:
        app.config.from_pyfile("config.py", silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.register_blueprint(auth.auth)
    app.register_blueprint(ca.ca)

    app.teardown_appcontext(db.close_db)
    app.cli.add_command(db.init_db)

    JWTManager(app)
    return app
