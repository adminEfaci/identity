"""Modify User Command for the Identity module."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ModifyUserCommand:
    """Command to modify an existing user.

    This command encapsulates the information needed to update
    an existing user in the system. All fields except user_id
    are optional to support partial updates.

    Attributes:
        user_id: The unique identifier of the user to modify
        email: The new email address (optional)
        username: The new username (optional)
        first_name: The new first name (optional)
        last_name: The new last name (optional)
        is_active: The new active status (optional)
    """

    user_id: str
    email: Optional[str] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None
