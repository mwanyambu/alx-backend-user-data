#!/usr/bin/env python3

""" simple flask app """

from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()

@app.route('/', methods=['GET'])
def hello():
    """ start flask app """
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=["POST"])
def register_user():
    """ register user """
    try:
        email = request.form.get("email")
        password = request.form.get("password")
    except KeyError:
        abort(400)

    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "user created"}), 400
    msg = {"email": email, "message": "user created"}
    return jsonify(msg)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")