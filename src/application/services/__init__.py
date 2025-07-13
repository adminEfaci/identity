"""Service implementations for the Identity module.

This module contains the concrete implementations of application services
that orchestrate domain operations and provide the main business logic.
"""

from .user_service import UserService

__all__ = [
    "UserService",
]
