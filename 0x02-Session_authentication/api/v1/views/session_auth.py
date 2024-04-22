#!/usr/bin/env python3

""" session auth view """

from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """ login user """
    email = request.form.get('email')
    if email is None:
      return jsonify({"error": "email missing"}), 400
    
    password = request.form.get('password')
    if password is None:
      return jsonify({"error": "password missing"}), 400
    
    try:
      user = User.search({'email': email})
    except Exception:
      return jsonify({"error": "no user found for this email"}), 404
    
    if user is None:
      return jsonify({"error": "no user found for this email"}), 404
    
    for u in user:
      if not u.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401
    
    from api.v1.app import auth

    u = user[0]
    session_id = auth.create_session(u.id)
    SESSION_NAME = getenv('SESSION_NAME')
    response = jsonify(u.to_json())
    response.set_cookie(SESSION_NAME, session_id)
    return response

@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
  """ logout user """
  from api.v1.app import auth

  logged_out = auth.destroy_session(request)

  if not logged_out:
    abort(404)
  
  return jsonify({}), 200