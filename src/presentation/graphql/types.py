"""GraphQL types and schema definitions using Strawberry.

This module defines the GraphQL types, inputs, and schema for the Identity module
using Strawberry GraphQL framework.
"""

from datetime import datetime
from typing import Optional

import strawberry
from strawberry.types import Info

from ...application.interfaces.user_service import IUserService


@strawberry.type
class User:
    """GraphQL User type.

    Represents a user entity in the GraphQL schema.
    """

    id: str = strawberry.field(description="Unique user identifier")
    email: str = strawberry.field(description="User email address")
    username: str = strawberry.field(description="Unique username")
    first_name: str = strawberry.field(description="User's first name")
    last_name: str = strawberry.field(description="User's last name")
    is_active: bool = strawberry.field(description="Whether the user is active")
    created_at: datetime = strawberry.field(description="User creation timestamp")
    updated_at: datetime = strawberry.field(description="Last update timestamp")


@strawberry.input
class CreateUserInput:
    """GraphQL input type for creating a new user.

    Contains all required fields for user creation.
    """

    email: str = strawberry.field(description="User email address")
    username: str = strawberry.field(description="Unique username")
    first_name: str = strawberry.field(description="User's first name")
    last_name: str = strawberry.field(description="User's last name")
    password: str = strawberry.field(description="User password")


@strawberry.input
class ModifyUserInput:
    """GraphQL input type for modifying an existing user.

    All fields are optional to support partial updates.
    """

    email: Optional[str] = strawberry.field(default=None, description="New email address")
    username: Optional[str] = strawberry.field(default=None, description="New username")
    first_name: Optional[str] = strawberry.field(default=None, description="New first name")
    last_name: Optional[str] = strawberry.field(default=None, description="New last name")
    is_active: Optional[bool] = strawberry.field(default=None, description="New active status")


@strawberry.type
class UserConnection:
    """GraphQL connection type for paginated user results.

    Follows GraphQL connection pattern for pagination.
    """

    users: list[User] = strawberry.field(description="List of users")
    total_count: int = strawberry.field(description="Total number of users")
    has_next_page: bool = strawberry.field(description="Whether there are more users")
    has_previous_page: bool = strawberry.field(description="Whether there are previous users")


@strawberry.type
class MutationResult:
    """GraphQL result type for mutations.

    Provides success status and optional error information.
    """

    success: bool = strawberry.field(description="Whether the operation succeeded")
    message: str = strawberry.field(description="Result message")
    user: Optional[User] = strawberry.field(default=None, description="User data if applicable")


def get_user_service_from_context(info: Info) -> IUserService:
    """Extract user service from GraphQL context.

    Args:
        info: GraphQL resolver info containing context

    Returns:
        User service instance

    Raises:
        RuntimeError: If user service is not available in context
    """
    user_service = getattr(info.context, "user_service", None)
    if not user_service:
        raise RuntimeError("User service not available in GraphQL context")
    return user_service


def get_current_user_from_context(info: Info) -> Optional[dict]:
    """Extract current user from GraphQL context.

    Args:
        info: GraphQL resolver info containing context

    Returns:
        Current user information or None if not authenticated
    """
    return getattr(info.context, "current_user", None)


def require_authentication(info: Info) -> dict:
    """Require authentication for GraphQL resolvers.

    Args:
        info: GraphQL resolver info containing context

    Returns:
        Current user information

    Raises:
        RuntimeError: If user is not authenticated
    """
    user = get_current_user_from_context(info)
    if not user:
        raise RuntimeError("Authentication required")
    return user
