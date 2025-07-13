"""Create User Command for the Identity module."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CreateUserCommand:
    """Command to create a new user.

    This command encapsulates all the information needed to create
    a new user in the system.

    Attributes:
        email: The user's email address
        username: The user's unique username
        first_name: The user's first name
        last_name: The user's last name
        password: The user's password (will be hashed)
    """

    email: str
    username: str
    first_name: str
    last_name: str
    password: str
