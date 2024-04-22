#!/usr/bin/env python3
"""
Authentication Module
"""

from tabnanny import check
from flask import request
from typing import TypeVar, List
from os import getenv

User = TypeVar('User')

class Auth:
    """
    Class to manage API authentication
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication is required for a given path
        """
        check = path
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            check += "/"
        if check in excluded_paths or path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from a request
        """
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> User:
        """
        Retrieves the current user from a request
        """
        return None

    def session_cookie(self, request=None):
        """
        Retrieves a session cookie from a request
        """
        if request:
            session_name = getenv("SESSION_NAME")
            return request.cookie.get(session_name, None)