"""User Data Transfer Objects for the Identity module."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class UserDto:
    """Data Transfer Object for User entity.

    Represents a user in a format suitable for external communication.
    """

    id: str
    email: str
    username: str
    first_name: str
    last_name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class CreateUserDto:
    """Data Transfer Object for creating a new user.

    Contains the required information to create a new user.
    """

    email: str
    username: str
    first_name: str
    last_name: str
    password: str


@dataclass(frozen=True)
class ModifyUserDto:
    """Data Transfer Object for modifying an existing user.

    Contains the optional fields that can be updated for a user.
    All fields are optional to support partial updates.
    """

    email: Optional[str] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None
