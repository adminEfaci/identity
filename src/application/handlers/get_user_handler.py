"""Get User Query Handler for the Identity module."""

from typing import Optional

from ..dtos import UserDto
from ..interfaces import IQueryHandler, IUserService
from ..queries import GetUserQuery


class GetUserHandler(IQueryHandler[GetUserQuery, Optional[UserDto]]):
    """Handler for GetUserQuery.

    This handler processes queries to retrieve a single user from the system.
    It delegates to the user service for the actual business logic.
    """

    def __init__(self, user_service: IUserService) -> None:
        """Initialize the handler with required dependencies.

        Args:
            user_service: The user service for business operations
        """
        self._user_service = user_service

    async def handle(self, query: GetUserQuery) -> Optional[UserDto]:
        """Handle the GetUserQuery.

        Args:
            query: The query containing user lookup criteria

        Returns:
            The user DTO if found, None otherwise
        """
        if query.user_id is not None:
            return await self._user_service.get_user_by_id(query.user_id)
        elif query.email is not None:
            return await self._user_service.get_user_by_email(query.email)
        elif query.username is not None:
            return await self._user_service.get_user_by_username(query.username)
        else:
            # This should not happen due to validation in GetUserQuery
            raise ValueError("No valid identifier provided in query")
