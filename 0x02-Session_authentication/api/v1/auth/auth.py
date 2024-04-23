#!/usr/bin/env python3

"""
class auth
"""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """ class auth """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ requires authentication """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*"):
                if path.startswith(excluded_path[:-1]):
                    return False
        if path[-1] != '/':
            path += '/'
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """ authorization header """
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """ current user"""
        return None

    def session_cookie(self, request=None):
        """ session cookie """
        if request is None:
            return None

        SESSION_NAME = getenv("SESSION_NAME")

        if SESSION_NAME is None:
            return None
        session_id = request.cookies.get(SESSION_NAME)
        return session_id
