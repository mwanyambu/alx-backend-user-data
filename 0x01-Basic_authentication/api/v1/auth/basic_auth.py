#!/usr/bin/env python3

"""
class basic auth
"""
from api.v1.auth.auth import Auth
from typing import TypeVar
from base64 import b64decode
from models.user import User
import base64
import binascii
from flask import request


class BasicAuth:
    """ basic auth class """

    def extract_base64_authorization_header(self, authorization_header: str) -> str:  # nopep8
        """ extract base64 authorization header """
        if authorization_header is None or type(authorization_header) is not str:  # nopep8
            return None
        if authorization_header[:6] != "Basic ":
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:  # nopep8
        """ decode base64 authorization header """
        if base64_authorization_header is None or type(base64_authorization_header) is not str:  # nopep8
            return None
        try:
            return base64.b64decode(base64_authorization_header).decode('utf-8')  # nopep8
        except binascii.Error:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):  # nopep8
        """ extract user credentials """
        if decoded_base64_authorization_header is None or type(decoded_base64_authorization_header) is not str:  # nopep8
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):  # nopep8
        """ user object from credentials """
        if user_email is None or user_pwd is None or type(user_email) is not str or type(user_pwd) is not str:  # nopep8
            return None
        try:
            user = User.search({'email': user_email})
        except Exception:
            return None
        if user is None or not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """ current user """
        auth = Auth()
        if auth.authorization_header(request) is None:
            return None
        header = auth.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        user_credentials = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(user_credentials[0], user_credentials[1])  # nopep8
