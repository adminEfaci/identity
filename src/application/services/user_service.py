"""User Service implementation for the Identity module."""

from typing import Optional
from uuid import uuid4

from ...domain.entities import User
from ...domain.events import UserCreated, UserDeleted, UserModified
from ...domain.exceptions import (
    UserAlreadyExistsError,
    UserNotFoundError,
    ValidationError,
)
from ...domain.repositories import UserRepository
from ...domain.services import UserDomainService
from ...domain.value_objects import Email, Password, PersonName, UserId, Username
from ...infrastructure.messaging import MessageBus
from ..dtos import CreateUserDto, ModifyUserDto, UserDto
from ..interfaces import IUserService


class UserService(IUserService):
    """Implementation of the user service interface.

    This service orchestrates domain operations and provides the main
    business logic for user management operations.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        user_domain_service: UserDomainService,
        message_bus: Optional[MessageBus] = None,
    ) -> None:
        """Initialize the service with required dependencies.

        Args:
            user_repository: Repository for user persistence operations
            user_domain_service: Domain service for user business logic
            message_bus: Message bus for publishing domain events (optional)
        """
        self._user_repository = user_repository
        self._user_domain_service = user_domain_service
        self._message_bus = message_bus

    async def create_user(self, user_data: CreateUserDto) -> UserDto:
        """Create a new user.

        Args:
            user_data: The data for creating the user

        Returns:
            The created user as a DTO

        Raises:
            UserAlreadyExistsError: If a user with the same email or username exists
            ValidationError: If the user data is invalid
        """
        try:
            # Check if user already exists
            existing_user_by_email = await self._user_repository.find_by_email(
                Email(user_data.email)
            )
            if existing_user_by_email:
                raise UserAlreadyExistsError(
                    f"User with email {user_data.email} already exists"
                )

            existing_user_by_username = await self._user_repository.find_by_username(
                Username(user_data.username)
            )
            if existing_user_by_username:
                raise UserAlreadyExistsError(
                    f"User with username {user_data.username} already exists"
                )

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
                last_name=last_name,
            )

            # Save user
            await self._user_repository.save(user)

            # Publish UserCreated domain event
            await self._publish_user_created_event(user)

            return self._user_to_dto(user)

        except (ValueError, TypeError) as e:
            raise ValidationError(f"Invalid user data: {str(e)}") from e

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
        self, is_active: Optional[bool] = None, limit: int = 50, offset: int = 0
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
            is_active=is_active, limit=limit, offset=offset
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
            ValidationError: If the user data is invalid
        """
        try:
            # Get existing user
            user_id_vo = UserId(user_id)
            user = await self._user_repository.find_by_id(user_id_vo)
            if not user:
                raise UserNotFoundError(f"User with ID {user_id} not found")

            # Check for conflicts if email or username is being changed
            if user_data.email and user_data.email != user.email.value:
                existing_user = await self._user_repository.find_by_email(
                    Email(user_data.email)
                )
                if existing_user and existing_user.id != user.id:
                    raise UserAlreadyExistsError(
                        f"User with email {user_data.email} already exists"
                    )

            if user_data.username and user_data.username != user.username.value:
                existing_user = await self._user_repository.find_by_username(
                    Username(user_data.username)
                )
                if existing_user and existing_user.id != user.id:
                    raise UserAlreadyExistsError(
                        f"User with username {user_data.username} already exists"
                    )

            # Capture changes for audit event
            changes = {}
            previous_values = {}

            # Update user fields and track changes
            if user_data.email and user_data.email != user.email.value:
                previous_values["email"] = user.email.value
                user.change_email(Email(user_data.email))
                changes["email"] = user_data.email

            if user_data.username and user_data.username != user.username.value:
                previous_values["username"] = user.username.value
                user.change_username(Username(user_data.username))
                changes["username"] = user_data.username

            if user_data.first_name and user_data.first_name != user.first_name.value:
                previous_values["first_name"] = user.first_name.value
                user.change_first_name(PersonName(user_data.first_name))
                changes["first_name"] = user_data.first_name

            if user_data.last_name and user_data.last_name != user.last_name.value:
                previous_values["last_name"] = user.last_name.value
                user.change_last_name(PersonName(user_data.last_name))
                changes["last_name"] = user_data.last_name

            if user_data.is_active is not None and user_data.is_active != user.is_active:
                previous_values["is_active"] = user.is_active
                if user_data.is_active:
                    user.activate()
                else:
                    user.deactivate()
                changes["is_active"] = user_data.is_active

            # Save updated user only if there are changes
            if changes:
                await self._user_repository.save(user)

                # Publish UserModified domain event
                await self._publish_user_modified_event(user, changes, previous_values)

            return self._user_to_dto(user)

        except ValueError as e:
            raise ValidationError(f"Invalid user data: {str(e)}") from e

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

            # Capture user details before deletion for audit event
            user_email = user.email

            await self._user_repository.delete(user_id_vo)

            # Publish UserDeleted domain event
            await self._publish_user_deleted_event(user, user_email)

        except ValueError as e:
            raise ValidationError(f"Invalid user ID: {str(e)}") from e

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
            updated_at=user.updated_at,
        )

    async def _publish_user_created_event(self, user: User) -> None:
        """Publish UserCreated domain event.

        Args:
            user: The created user entity
        """
        if not self._message_bus:
            return

        try:
            from datetime import datetime

            event = UserCreated(
                event_id=uuid4(),
                aggregate_id=user.id.value,
                occurred_at=datetime.utcnow(),
                user_id=user.id,
                email=user.email,
                status=user.status,
                created_by=user.id.value,  # For now, assume self-creation
                correlation_id=uuid4(),
            )

            await self._message_bus.publish_audit_domain_event(event)

        except Exception as e:
            # Log error but don't fail the user creation
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to publish UserCreated event: {e}")

    async def _publish_user_modified_event(
        self, user: User, changes: dict, previous_values: dict
    ) -> None:
        """Publish UserModified domain event.

        Args:
            user: The modified user entity
            changes: Dictionary of changed fields
            previous_values: Dictionary of previous values
        """
        if not self._message_bus:
            return

        try:
            from datetime import datetime

            event = UserModified(
                event_id=uuid4(),
                aggregate_id=user.id.value,
                occurred_at=datetime.utcnow(),
                user_id=user.id,
                modified_by=user.id.value,  # For now, assume self-modification
                changes=changes,
                previous_values=previous_values,
                correlation_id=uuid4(),
            )

            await self._message_bus.publish_audit_domain_event(event)

        except Exception as e:
            # Log error but don't fail the user modification
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to publish UserModified event: {e}")

    async def _publish_user_deleted_event(self, user: User, user_email: Email) -> None:
        """Publish UserDeleted domain event.

        Args:
            user: The deleted user entity
            user_email: Email of the deleted user
        """
        if not self._message_bus:
            return

        try:
            from datetime import datetime

            event = UserDeleted(
                event_id=uuid4(),
                aggregate_id=user.id.value,
                occurred_at=datetime.utcnow(),
                user_id=user.id,
                deleted_by=user.id.value,  # For now, assume self-deletion
                email=user_email,
                soft_delete=True,  # Assuming soft delete by default
                correlation_id=uuid4(),
            )

            await self._message_bus.publish_audit_domain_event(event)

        except Exception as e:
            # Log error but don't fail the user deletion
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to publish UserDeleted event: {e}")
