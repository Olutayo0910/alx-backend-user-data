#!/usr/bin/env python3
"""
Password Encryption
"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    Generate a salted hash for a password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Check if a password is valid against its hash """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
