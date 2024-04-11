#!/usr/bin/env python3

"""
encrypt_password function
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ returns a salted, hashed password """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('UTF-8'), salt)

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ check if passwd is valid """
    validity = False
    if bcrypt.checkpw(password.encode('UTF-8'), hashed_password):
        validity = True
    return validity
