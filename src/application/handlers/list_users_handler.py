"""List Users Query Handler for the Identity module."""

from ..dtos import UserDto
from ..interfaces import IQueryHandler, IUserService
from ..queries import ListUsersQuery


class ListUsersHandler(IQueryHandler[ListUsersQuery, list[UserDto]]):
    """Handler for ListUsersQuery.

    This handler processes queries to retrieve a list of users from the system.
    It delegates to the user service for the actual business logic.
    """

    def __init__(self, user_service: IUserService) -> None:
        """Initialize the handler with required dependencies.

        Args:
            user_service: The user service for business operations
        """
        self._user_service = user_service

    async def handle(self, query: ListUsersQuery) -> list[UserDto]:
        """Handle the ListUsersQuery.

        Args:
            query: The query containing filtering and pagination criteria

        Returns:
            List of user DTOs matching the criteria
        """
        return await self._user_service.list_users(
            is_active=query.is_active, limit=query.limit, offset=query.offset
        )
