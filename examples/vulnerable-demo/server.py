import os
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.run("ping " + host, shell=True, capture_output=True).stdout


@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "ok"


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


def fetch(url):
    return requests.get(url, verify=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
