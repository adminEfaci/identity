"""GraphQL resolvers for user operations.

This module implements the GraphQL query and mutation resolvers
for user management operations.
"""

import logging
from typing import Optional

import strawberry
from strawberry.types import Info

from ...application.dtos import CreateUserDto, ModifyUserDto
from ...domain.exceptions import (
    UserAlreadyExistsError,
    UserNotFoundError,
    ValidationError,
)
from .types import (
    CreateUserInput,
    ModifyUserInput,
    MutationResult,
    User,
    UserConnection,
    get_user_service_from_context,
    require_authentication,
)

logger = logging.getLogger(__name__)


@strawberry.type
class Query:
    """GraphQL Query root type.

    Defines all available query operations for the Identity module.
    """

    @strawberry.field(description="Get a user by their ID")
    async def user(self, info: Info, id: str) -> Optional[User]:
        """Get a user by their ID.

        Args:
            info: GraphQL resolver info
            id: User ID to retrieve

        Returns:
            User object or None if not found
        """
        try:
            # Authentication is optional for single user queries
            user_service = get_user_service_from_context(info)
            user_dto = await user_service.get_user_by_id(id)

            if not user_dto:
                return None

            return User(
                id=user_dto.id,
                email=user_dto.email,
                username=user_dto.username,
                first_name=user_dto.first_name,
                last_name=user_dto.last_name,
                is_active=user_dto.is_active,
                created_at=user_dto.created_at,
                updated_at=user_dto.updated_at,
            )

        except Exception as e:
            logger.error(f"Error retrieving user {id}: {e}")
            raise RuntimeError(f"Failed to retrieve user: {e}") from e

    @strawberry.field(description="Get a list of users with optional filtering")
    async def users(
        self,
        info: Info,
        is_active: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> UserConnection:
        """Get a list of users with optional filtering and pagination.

        Args:
            info: GraphQL resolver info
            is_active: Filter by active status (optional)
            limit: Maximum number of users to return
            offset: Number of users to skip for pagination

        Returns:
            UserConnection with paginated results
        """
        try:
            # Require authentication for user listing
            require_authentication(info)

            user_service = get_user_service_from_context(info)
            user_dtos = await user_service.list_users(
                is_active=is_active,
                limit=limit,
                offset=offset,
            )

            # Convert DTOs to GraphQL types
            users = [
                User(
                    id=dto.id,
                    email=dto.email,
                    username=dto.username,
                    first_name=dto.first_name,
                    last_name=dto.last_name,
                    is_active=dto.is_active,
                    created_at=dto.created_at,
                    updated_at=dto.updated_at,
                )
                for dto in user_dtos
            ]

            # Calculate pagination metadata
            total_count = len(users)  # In real implementation, get from service
            has_next_page = len(users) == limit
            has_previous_page = offset > 0

            return UserConnection(
                users=users,
                total_count=total_count,
                has_next_page=has_next_page,
                has_previous_page=has_previous_page,
            )

        except Exception as e:
            logger.error(f"Error listing users: {e}")
            raise RuntimeError(f"Failed to list users: {e}") from e


@strawberry.type
class Mutation:
    """GraphQL Mutation root type.

    Defines all available mutation operations for the Identity module.
    """

    @strawberry.field(description="Create a new user")
    async def create_user(
        self, info: Info, input: CreateUserInput
    ) -> MutationResult:
        """Create a new user.

        Args:
            info: GraphQL resolver info
            input: User creation input data

        Returns:
            MutationResult with success status and user data
        """
        try:
            user_service = get_user_service_from_context(info)

            # Convert GraphQL input to DTO
            create_dto = CreateUserDto(
                email=input.email,
                username=input.username,
                first_name=input.first_name,
                last_name=input.last_name,
                password=input.password,
            )

            # Create user
            user_dto = await user_service.create_user(create_dto)

            # Convert DTO to GraphQL type
            user = User(
                id=user_dto.id,
                email=user_dto.email,
                username=user_dto.username,
                first_name=user_dto.first_name,
                last_name=user_dto.last_name,
                is_active=user_dto.is_active,
                created_at=user_dto.created_at,
                updated_at=user_dto.updated_at,
            )

            logger.info(f"User created successfully: {user_dto.id}")

            return MutationResult(
                success=True,
                message="User created successfully",
                user=user,
            )

        except UserAlreadyExistsError as e:
            logger.warning(f"User creation failed - already exists: {e}")
            return MutationResult(
                success=False,
                message=f"User already exists: {e}",
                user=None,
            )

        except ValidationError as e:
            logger.warning(f"User creation failed - invalid data: {e}")
            return MutationResult(
                success=False,
                message=f"Invalid user data: {e}",
                user=None,
            )

        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return MutationResult(
                success=False,
                message=f"Failed to create user: {e}",
                user=None,
            )

    @strawberry.field(description="Modify an existing user")
    async def modify_user(
        self, info: Info, id: str, input: ModifyUserInput
    ) -> MutationResult:
        """Modify an existing user.

        Args:
            info: GraphQL resolver info
            id: User ID to modify
            input: User modification input data

        Returns:
            MutationResult with success status and updated user data
        """
        try:
            # Require authentication
            current_user = require_authentication(info)

            # Check if user can modify this user (basic authorization)
            if current_user["user_id"] != id and "admin" not in current_user.get("roles", []):
                return MutationResult(
                    success=False,
                    message="Insufficient permissions to modify this user",
                    user=None,
                )

            user_service = get_user_service_from_context(info)

            # Convert GraphQL input to DTO
            modify_dto = ModifyUserDto(
                email=input.email,
                username=input.username,
                first_name=input.first_name,
                last_name=input.last_name,
                is_active=input.is_active,
            )

            # Modify user
            user_dto = await user_service.modify_user(id, modify_dto)

            # Convert DTO to GraphQL type
            user = User(
                id=user_dto.id,
                email=user_dto.email,
                username=user_dto.username,
                first_name=user_dto.first_name,
                last_name=user_dto.last_name,
                is_active=user_dto.is_active,
                created_at=user_dto.created_at,
                updated_at=user_dto.updated_at,
            )

            logger.info(f"User modified successfully: {id}")

            return MutationResult(
                success=True,
                message="User modified successfully",
                user=user,
            )

        except UserNotFoundError as e:
            logger.warning(f"User modification failed - not found: {e}")
            return MutationResult(
                success=False,
                message=f"User not found: {e}",
                user=None,
            )

        except UserAlreadyExistsError as e:
            logger.warning(f"User modification failed - conflict: {e}")
            return MutationResult(
                success=False,
                message=f"User already exists: {e}",
                user=None,
            )

        except ValidationError as e:
            logger.warning(f"User modification failed - invalid data: {e}")
            return MutationResult(
                success=False,
                message=f"Invalid user data: {e}",
                user=None,
            )

        except Exception as e:
            logger.error(f"Error modifying user {id}: {e}")
            return MutationResult(
                success=False,
                message=f"Failed to modify user: {e}",
                user=None,
            )

    @strawberry.field(description="Delete a user")
    async def delete_user(self, info: Info, id: str) -> MutationResult:
        """Delete a user.

        Args:
            info: GraphQL resolver info
            id: User ID to delete

        Returns:
            MutationResult with success status
        """
        try:
            # Require authentication
            current_user = require_authentication(info)

            # Check if user can delete this user (basic authorization)
            if current_user["user_id"] != id and "admin" not in current_user.get("roles", []):
                return MutationResult(
                    success=False,
                    message="Insufficient permissions to delete this user",
                    user=None,
                )

            user_service = get_user_service_from_context(info)

            # Delete user
            await user_service.delete_user(id)

            logger.info(f"User deleted successfully: {id}")

            return MutationResult(
                success=True,
                message="User deleted successfully",
                user=None,
            )

        except UserNotFoundError as e:
            logger.warning(f"User deletion failed - not found: {e}")
            return MutationResult(
                success=False,
                message=f"User not found: {e}",
                user=None,
            )

        except Exception as e:
            logger.error(f"Error deleting user {id}: {e}")
            return MutationResult(
                success=False,
                message=f"Failed to delete user: {e}",
                user=None,
            )


# Create the GraphQL schema
schema = strawberry.Schema(query=Query, mutation=Mutation)
