"""List Users Query for the Identity module."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ListUsersQuery:
    """Query to retrieve a list of users with optional filtering and pagination.

    This query supports filtering by active status and pagination
    through limit and offset parameters.

    Attributes:
        is_active: Filter users by active status (optional)
        limit: Maximum number of users to return (optional, default: 50)
        offset: Number of users to skip for pagination (optional, default: 0)
    """

    is_active: Optional[bool] = None
    limit: int = 50
    offset: int = 0

    def __post_init__(self) -> None:
        """Validate pagination parameters."""
        if self.limit < 1:
            raise ValueError("Limit must be greater than 0")

        if self.offset < 0:
            raise ValueError("Offset must be non-negative")

        if self.limit > 1000:
            raise ValueError("Limit cannot exceed 1000")
