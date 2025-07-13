"""Delete User Command for the Identity module."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DeleteUserCommand:
    """Command to delete an existing user.

    This command encapsulates the information needed to delete
    a user from the system.

    Attributes:
        user_id: The unique identifier of the user to delete
    """

    user_id: str
