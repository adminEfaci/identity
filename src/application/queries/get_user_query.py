"""Get User Query for the Identity module."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class GetUserQuery:
    """Query to retrieve a single user.

    This query can retrieve a user by either ID, email, or username.
    Exactly one of these fields must be provided.

    Attributes:
        user_id: The unique identifier of the user (optional)
        email: The email address of the user (optional)
        username: The username of the user (optional)
    """

    user_id: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate that exactly one identifier is provided."""
        provided_fields = sum(
            1
            for field in [self.user_id, self.email, self.username]
            if field is not None
        )

        if provided_fields != 1:
            raise ValueError(
                "Exactly one of user_id, email, or username must be provided"
            )
