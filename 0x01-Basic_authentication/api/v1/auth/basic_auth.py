#!/usr/bin/env python3
"""This file contains the BasicAuth class"""
from typing import TypeVar

from api.v1.auth.auth import Auth
from models.base import Base
from models.user import User

import base64


class BasicAuth(Auth):
    """The Basic Auth class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """This method returns the Base64 part of
        the Authorization header for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split("Basic ", 1)[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """This method returns the decoded value of a
        Base64 string base64_authorization_header
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            auth_str = base64.b64decode(base64_authorization_header)
            return auth_str.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """This method returns the user email and
        password from the Base64 decoded value
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        # data = decoded_base64_authorization_header.split(':')
        data = decoded_base64_authorization_header.partition(":")
        return data[0], data[2]

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """This method returns the User instance
        based on his email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        userList = User().search({'email': user_email})
        if len(userList) > 0 and userList[0].is_valid_password(user_pwd):
            return userList[0]
        else:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """This method overloads Auth and retrieves
        the User instance for a request
        """
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        base64_header = self.extract_base64_authorization_header(auth_header)
        if base64_header is None:
            return None
        decoded_base64_header = self.decode_base64_authorization_header(
                                    base64_header)
        if decoded_base64_header is None:
            return None
        user_credentials = self.extract_user_credentials(decoded_base64_header)
        if user_credentials is None:
            return None
        user = self.user_object_from_credentials(user_credentials[0],
                                                 user_credentials[1])
        return user
