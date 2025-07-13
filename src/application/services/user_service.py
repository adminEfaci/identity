"""User Service implementation for the Identity module."""

from typing import Optional

from ...domain.entities import User
from ...domain.exceptions import (
    InvalidUserDataError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from ...domain.repositories import IUserRepository
from ...domain.services import UserDomainService
from ...domain.value_objects import Email, Password, PersonName, UserId, Username
from ..dtos import CreateUserDto, ModifyUserDto, UserDto
from ..interfaces import IUserService


class UserService(IUserService):
    """Implementation of the user service interface.

    This service orchestrates domain operations and provides the main
    business logic for user management operations.
    """

    def __init__(
        self,
        user_repository: IUserRepository,
        user_domain_service: UserDomainService
    ) -> None:
        """Initialize the service with required dependencies.

        Args:
            user_repository: Repository for user persistence operations
            user_domain_service: Domain service for user business logic
        """
        self._user_repository = user_repository
        self._user_domain_service = user_domain_service

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
        try:
            # Check if user already exists
            existing_user_by_email = await self._user_repository.find_by_email(
                Email(user_data.email)
            )
            if existing_user_by_email:
                raise UserAlreadyExistsError(f"User with email {user_data.email} already exists")

            existing_user_by_username = await self._user_repository.find_by_username(
                Username(user_data.username)
            )
            if existing_user_by_username:
                raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")

            # Create domain objects
            user_id = UserId.generate()
            email = Email(user_data.email)
            username = Username(user_data.username)
            password = Password.create(user_data.password)
            first_name = PersonName(user_data.first_name)
            last_name = PersonName(user_data.last_name)

            # Create user entity
            user = User.create(
                user_id=user_id,
                email=email,
                username=username,
                password=password,
                first_name=first_name,
                last_name=last_name
            )

            # Save user
            await self._user_repository.save(user)

            return self._user_to_dto(user)

        except (ValueError, TypeError) as e:
            raise InvalidUserDataError(f"Invalid user data: {str(e)}") from e

    async def get_user_by_id(self, user_id: str) -> Optional[UserDto]:
        """Get a user by their ID.

        Args:
            user_id: The unique identifier of the user

        Returns:
            The user DTO if found, None otherwise
        """
        try:
            user_id_vo = UserId(user_id)
            user = await self._user_repository.find_by_id(user_id_vo)
            return self._user_to_dto(user) if user else None
        except ValueError:
            return None

    async def get_user_by_email(self, email: str) -> Optional[UserDto]:
        """Get a user by their email address.

        Args:
            email: The email address of the user

        Returns:
            The user DTO if found, None otherwise
        """
        try:
            email_vo = Email(email)
            user = await self._user_repository.find_by_email(email_vo)
            return self._user_to_dto(user) if user else None
        except ValueError:
            return None

    async def get_user_by_username(self, username: str) -> Optional[UserDto]:
        """Get a user by their username.

        Args:
            username: The username of the user

        Returns:
            The user DTO if found, None otherwise
        """
        try:
            username_vo = Username(username)
            user = await self._user_repository.find_by_username(username_vo)
            return self._user_to_dto(user) if user else None
        except ValueError:
            return None

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
        users = await self._user_repository.find_all(
            is_active=is_active,
            limit=limit,
            offset=offset
        )
        return [self._user_to_dto(user) for user in users]

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
        try:
            # Get existing user
            user_id_vo = UserId(user_id)
            user = await self._user_repository.find_by_id(user_id_vo)
            if not user:
                raise UserNotFoundError(f"User with ID {user_id} not found")

            # Check for conflicts if email or username is being changed
            if user_data.email and user_data.email != user.email.value:
                existing_user = await self._user_repository.find_by_email(Email(user_data.email))
                if existing_user and existing_user.id != user.id:
                    raise UserAlreadyExistsError(f"User with email {user_data.email} already exists")

            if user_data.username and user_data.username != user.username.value:
                existing_user = await self._user_repository.find_by_username(Username(user_data.username))
                if existing_user and existing_user.id != user.id:
                    raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")

            # Update user fields
            if user_data.email:
                user.change_email(Email(user_data.email))

            if user_data.username:
                user.change_username(Username(user_data.username))

            if user_data.first_name:
                user.change_first_name(PersonName(user_data.first_name))

            if user_data.last_name:
                user.change_last_name(PersonName(user_data.last_name))

            if user_data.is_active is not None:
                if user_data.is_active:
                    user.activate()
                else:
                    user.deactivate()

            # Save updated user
            await self._user_repository.save(user)

            return self._user_to_dto(user)

        except ValueError as e:
            raise InvalidUserDataError(f"Invalid user data: {str(e)}") from e

    async def delete_user(self, user_id: str) -> None:
        """Delete a user.

        Args:
            user_id: The unique identifier of the user to delete

        Raises:
            UserNotFoundError: If the user does not exist
        """
        try:
            user_id_vo = UserId(user_id)
            user = await self._user_repository.find_by_id(user_id_vo)
            if not user:
                raise UserNotFoundError(f"User with ID {user_id} not found")

            await self._user_repository.delete(user_id_vo)

        except ValueError as e:
            raise InvalidUserDataError(f"Invalid user ID: {str(e)}") from e

    def _user_to_dto(self, user: User) -> UserDto:
        """Convert a User entity to a UserDto.

        Args:
            user: The user entity to convert

        Returns:
            The user DTO
        """
        return UserDto(
            id=user.id.value,
            email=user.email.value,
            username=user.username.value,
            first_name=user.first_name.value,
            last_name=user.last_name.value,
            is_active=user.is_active,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
