import acme
from flask import Flask

app = Flask(__name__)


def load(path):
    return acme.load(path)


@app.route("/load")
def handler():
    return str(load("m"))


def unused(path):
    return acme.load(path)


acme.load("startup")
