"""GraphQL schema and resolvers for the Identity module."""

from .resolvers import schema
from .types import (
    CreateUserInput,
    ModifyUserInput,
    MutationResult,
    User,
    UserConnection,
)

__all__ = [
    "schema",
    "User",
    "CreateUserInput",
    "ModifyUserInput",
    "UserConnection",
    "MutationResult",
]
