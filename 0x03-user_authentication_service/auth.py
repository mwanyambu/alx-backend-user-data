#!/usr/bin/env python3

""" hashed password """
import bcrypt
from user import Base, User
from db import DB
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """ returns a hashed passwd """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def _generate_uuid() -> str:
    """ returns a string uuid """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()
    
    def register_user(self, email: str, password: str) -> User:
        """ register new user """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed = _hash_password(password)
            user = self._db.add_user(email, hashed)
            return user
        else:
            raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """ validate credentials """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        hashed = user.hashed_password
        passwad = password.encode('utf-8')
        if bcrypt.checkpw(passwad, hashed):
            return True
        return False

    def create_session(self, email: str) -> str:
        """ create new session """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id
    def get_user_from_session_id(session_id: str) -> User:
        """ get user by session id """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user