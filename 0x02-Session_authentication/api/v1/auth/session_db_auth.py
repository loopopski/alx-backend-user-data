#!/usr/bin/env python3
""" SessionDBAuth module
"""
from .session_exp_auth import SessionExpAuth
from datetime import datetime, timedelta
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """ SessionDBAuth class
    Class that creates and stores sessions in database
    """

    def create_session(self, user_id=None) -> str:
        """ create_session
        Creates and stores a session ID for user(s)
        """
        session_id = super().create_session(user_id)
        if type(session_id) == str:
            kwargs = {
                'user_id': user_id,
                'session_id': session_id
            }
            user_session = UserSession(**kwargs)
            user_session.save()
            return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ user_id_for_session_id method
        Retrieves the user ID based on the session ID
        """
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        if len(sessions) <= 0:
            return None
        current_time = datetime.now()
        time_span = timedelta(seconds=self.session_duration)
        expiry_time = sessions[0].created_at + time_span
        if expiry_time < current_time:
            return None
        return sessions[0].user_id

    def destroy_session(self, request=None):
        """ destroy_session method
        Ends a running session
        """
        session_id = self.session_cookie(request)
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False
        if len(sessions) <= 0:
            return False
        sessions[0].remove()
        return True
