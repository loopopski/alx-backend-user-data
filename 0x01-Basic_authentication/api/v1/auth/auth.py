#!/usr/bin/env python3
"""This file contains the Auth class"""
from typing import List, TypeVar
from flask import request


class Auth:
    """The Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """The require_auth method"""
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        full_path = "{}/".format(path)
        if path in excluded_paths or full_path in excluded_paths:
            return False
        if path.endswith("/"):
            abs_path = path[:-1]
        else:
            abs_path = path
        # for url in excluded_paths:
        #     if url.endswith("*/"):
        #         extracted_path = url[:-2]
        #         sub_path = abs_path[0: len(extracted_path)]
        #         if sub_path == extracted_path:
        #             return False
        #     if url.endswith("*"):
        #         extracted_path = url[:-1]
        #         sub_path = abs_path[0: len(extracted_path)]
        #         if sub_path == extracted_path:
        #             return False
        for url in excluded_paths:
            extracted_path = ""
            if url.endswith("*/"):
                extracted_path = url[:-2]
            if url.endswith("*"):
                extracted_path = url[:-1]
            if len(extracted_path) > 0:
                sub_path = abs_path[0: len(extracted_path)]
                if sub_path == extracted_path:
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """The authorization_header method"""
        if request is None:
            return None
        if 'Authorization' not in request.headers.keys():
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """The current_user method"""
        return None
