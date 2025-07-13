"""User Service interface for the Identity module."""

from abc import ABC, abstractmethod
from typing import Optional

from ..dtos import CreateUserDto, ModifyUserDto, UserDto


class IUserService(ABC):
    """Interface for user service operations.

    This service provides high-level operations for managing users
    and serves as the primary contract for the application layer.
    """

    @abstractmethod
    async def create_user(self, user_data: CreateUserDto) -> UserDto:
        """Create a new user.

        Args:
            user_data: The data for creating the user

        Returns:
            The created user as a DTO

        Raises:
            UserAlreadyExistsError: If a user with the same email or username exists
            InvalidUserDataError: If the user data is invalid
        """
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[UserDto]:
        """Get a user by their ID.

        Args:
            user_id: The unique identifier of the user

        Returns:
            The user DTO if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[UserDto]:
        """Get a user by their email address.

        Args:
            email: The email address of the user

        Returns:
            The user DTO if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[UserDto]:
        """Get a user by their username.

        Args:
            username: The username of the user

        Returns:
            The user DTO if found, None otherwise
        """
        pass

    @abstractmethod
    async def list_users(
        self,
        is_active: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0
    ) -> list[UserDto]:
        """List users with optional filtering and pagination.

        Args:
            is_active: Filter by active status (optional)
            limit: Maximum number of users to return
            offset: Number of users to skip for pagination

        Returns:
            List of user DTOs
        """
        pass

    @abstractmethod
    async def modify_user(self, user_id: str, user_data: ModifyUserDto) -> UserDto:
        """Modify an existing user.

        Args:
            user_id: The unique identifier of the user to modify
            user_data: The data for modifying the user

        Returns:
            The modified user as a DTO

        Raises:
            UserNotFoundError: If the user does not exist
            UserAlreadyExistsError: If trying to change to an existing email/username
            InvalidUserDataError: If the user data is invalid
        """
        pass

    @abstractmethod
    async def delete_user(self, user_id: str) -> None:
        """Delete a user.

        Args:
            user_id: The unique identifier of the user to delete

        Raises:
            UserNotFoundError: If the user does not exist
        """
        pass
