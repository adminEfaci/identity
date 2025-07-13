"""Query definitions for the Identity module.

This module contains all query objects that represent read operations
in the CQRS pattern.
"""

from .get_user_query import GetUserQuery
from .list_users_query import ListUsersQuery

__all__ = [
    "GetUserQuery",
    "ListUsersQuery",
]
