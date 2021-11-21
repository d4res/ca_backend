from flask import cli
import pymysql
import click
from flask import current_app, g
from flask.cli import with_appcontext


def con_db():
    if "db" not in g:
        db_config = current_app.config["DATABASE"]
        g.db = pymysql.connect(
            host="127.0.0.1",
            user=db_config["user"],
            passwd=db_config["password"],
            database=db_config["database"],
        )
    return g.db


@click.command("init_db")
@with_appcontext
def init_db():
    with open("ca_backend/schema.sql", "r") as sqlfile:
        sqlfile = sqlfile.read()
        with con_db() as db:
            with db.cursor() as c:
                for sql in sqlfile.split(";"):
                    if sql == "":
                        continue
                    c.execute(sql)
            db.commit()


def close_db(self):
    db = g.get("db")
    if db is not None:
        if db.open is True:
            db.close()
        g.pop("db", None)
