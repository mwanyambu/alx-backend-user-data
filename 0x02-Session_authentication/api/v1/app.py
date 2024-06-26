#!/usr/bin/env python3

"""
Route module for the API.

This module sets up the Flask application and handles routing for various endpoints.
It includes authentication mechanisms based on the environment variable AUTH_TYPE.
Supported authentication types include 'auth', 'basic_auth', and 'session_auth'.

Environment Variables:
    AUTH_TYPE: Specifies the type of authentication mechanism to use ('auth', 'basic_auth', 'session_auth').

"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None
AUTH_TYPE = getenv("AUTH_TYPE")

if AUTH_TYPE == "auth":
    from api.v1.auth.auth import Auth
    auth = Auth()
elif AUTH_TYPE == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()
elif AUTH_TYPE == "session_auth":
    from api.v1.auth.session_auth import SessionAuth
    auth = SessionAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """
    Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """
    Unauthorized handler
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """
    forbidden handler
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def before_request() -> str:
    """
    This function is executed before each request is processed.
    It performs authentication checks and sets the current user for the request.

    Returns:
        str: The current user for the request.

    Raises:
        401: If the request is not authenticated.
        403: If the current user is not authorized to access the requested path.
    """
    if auth is None:
        return

    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/',
                      '/api/v1/forbidden/',
                      '/api/v1/auth_session/login/']
    if request.path in excluded_paths:
        return

    if not auth.require_auth(request.path, excluded_paths):
        abort(401)
        return

    auth_header = auth.authorization_header(request)
    if auth_header is None \
        and auth.session_cookie(request) is None:
        abort(401)

    current_user = auth.current_user(auth_header)
    request.current_user = current_user
    if current_user is None:
        abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
