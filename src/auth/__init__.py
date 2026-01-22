"""
Authentication Module
Provides JWT-based authentication for API endpoints
"""

from .jwt_handler import (
    create_access_token,
    verify_token,
    get_current_user,
    hash_password,
    verify_password,
    authenticate_user
)
from .user_store import UserStore

__all__ = [
    'create_access_token',
    'verify_token',
    'get_current_user',
    'hash_password',
    'verify_password',
    'authenticate_user',
    'UserStore'
]
