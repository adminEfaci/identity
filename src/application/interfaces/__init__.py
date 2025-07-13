"""Interface definitions for the Identity application layer.

This module contains all interface contracts that define the boundaries
between the application layer and other layers.
"""

from .command_handler import ICommandHandler
from .query_handler import IQueryHandler
from .user_service import IUserService

__all__ = [
    "ICommandHandler",
    "IQueryHandler",
    "IUserService",
]
