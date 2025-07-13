"""REST API endpoints for user management.

This module implements the REST API endpoints for user operations
using FastAPI with proper HTTP methods and status codes.
"""

import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from ...application.dtos import CreateUserDto, ModifyUserDto
from ...application.interfaces.user_service import IUserService
from ...domain.exceptions import (
    UserAlreadyExistsError,
    UserNotFoundError,
    ValidationError,
)
from ..middleware.auth import require_auth
from ..models.api import (
    CreateUserRequest,
    ErrorResponse,
    ModifyUserRequest,
    SuccessResponse,
    UserListResponse,
    UserResponse,
)

logger = logging.getLogger(__name__)

# Create router for user endpoints
router = APIRouter(prefix="/api/users", tags=["users"])


def get_user_service() -> IUserService:
    """Dependency to get user service instance.

    This would typically be injected via dependency injection container.
    For now, it's a placeholder that should be configured in the main app.

    Returns:
        User service instance

    Raises:
        RuntimeError: If user service is not configured
    """
    # This should be replaced with proper dependency injection
    raise RuntimeError("User service dependency not configured")


@router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user",
    description="Create a new user with the provided information",
    responses={
        201: {"description": "User created successfully"},
        400: {"model": ErrorResponse, "description": "Invalid user data"},
        409: {"model": ErrorResponse, "description": "User already exists"},
    },
)
async def create_user(
    request: CreateUserRequest,
    user_service: Annotated[IUserService, Depends(get_user_service)],
) -> UserResponse:
    """Create a new user.

    Args:
        request: User creation request data
        user_service: User service dependency

    Returns:
        Created user data

    Raises:
        HTTPException: If user creation fails
    """
    try:
        # Convert request to DTO
        create_dto = CreateUserDto(
            email=request.email,
            username=request.username,
            first_name=request.first_name,
            last_name=request.last_name,
            password=request.password,
        )

        # Create user
        user_dto = await user_service.create_user(create_dto)

        logger.info(f"User created successfully: {user_dto.id}")

        # Convert DTO to response model
        return UserResponse(
            id=user_dto.id,
            email=user_dto.email,
            username=user_dto.username,
            first_name=user_dto.first_name,
            last_name=user_dto.last_name,
            is_active=user_dto.is_active,
            created_at=user_dto.created_at,
            updated_at=user_dto.updated_at,
        )

    except UserAlreadyExistsError as e:
        logger.warning(f"User creation failed - already exists: {e}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User already exists: {e}",
        ) from e

    except ValidationError as e:
        logger.warning(f"User creation failed - invalid data: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid user data: {e}",
        ) from e

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/",
    response_model=UserListResponse,
    summary="Get list of users",
    description="Get a paginated list of users with optional filtering",
    responses={
        200: {"description": "Users retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def get_users(
    request: Request,
    user_service: Annotated[IUserService, Depends(get_user_service)],
    current_user: Annotated[dict, Depends(require_auth)],
    is_active: Annotated[Optional[bool], Query(description="Filter by active status")] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Number of users per page")] = 50,
    offset: Annotated[int, Query(ge=0, description="Number of users to skip")] = 0,
) -> UserListResponse:
    """Get a list of users with optional filtering and pagination.

    Args:
        request: HTTP request
        user_service: User service dependency
        current_user: Current authenticated user
        is_active: Filter by active status (optional)
        limit: Maximum number of users to return
        offset: Number of users to skip for pagination

    Returns:
        Paginated list of users

    Raises:
        HTTPException: If user retrieval fails
    """
    try:
        # Get users from service
        user_dtos = await user_service.list_users(
            is_active=is_active,
            limit=limit,
            offset=offset,
        )

        # Convert DTOs to response models
        users = [
            UserResponse(
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

        logger.debug(f"Retrieved {len(users)} users for user {current_user['user_id']}")

        return UserListResponse(
            users=users,
            total=len(users),  # In real implementation, get total from service
            limit=limit,
            offset=offset,
        )

    except Exception as e:
        logger.error(f"Error retrieving users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID",
    description="Get a specific user by their ID",
    responses={
        200: {"description": "User retrieved successfully"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
async def get_user(
    user_id: str,
    user_service: Annotated[IUserService, Depends(get_user_service)],
) -> UserResponse:
    """Get a user by their ID.

    Args:
        user_id: User ID to retrieve
        user_service: User service dependency

    Returns:
        User data

    Raises:
        HTTPException: If user is not found
    """
    try:
        # Get user from service
        user_dto = await user_service.get_user_by_id(user_id)

        if not user_dto:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {user_id}",
            )

        logger.debug(f"Retrieved user: {user_id}")

        # Convert DTO to response model
        return UserResponse(
            id=user_dto.id,
            email=user_dto.email,
            username=user_dto.username,
            first_name=user_dto.first_name,
            last_name=user_dto.last_name,
            is_active=user_dto.is_active,
            created_at=user_dto.created_at,
            updated_at=user_dto.updated_at,
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error retrieving user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Modify user",
    description="Modify an existing user with partial updates",
    responses={
        200: {"description": "User modified successfully"},
        400: {"model": ErrorResponse, "description": "Invalid user data"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        404: {"model": ErrorResponse, "description": "User not found"},
        409: {"model": ErrorResponse, "description": "User already exists"},
    },
)
async def modify_user(
    user_id: str,
    request: ModifyUserRequest,
    user_service: Annotated[IUserService, Depends(get_user_service)],
    current_user: Annotated[dict, Depends(require_auth)],
) -> UserResponse:
    """Modify an existing user.

    Args:
        user_id: User ID to modify
        request: User modification request data
        user_service: User service dependency
        current_user: Current authenticated user

    Returns:
        Modified user data

    Raises:
        HTTPException: If user modification fails
    """
    try:
        # Check if user can modify this user (basic authorization)
        if current_user["user_id"] != user_id and "admin" not in current_user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to modify this user",
            )

        # Convert request to DTO
        modify_dto = ModifyUserDto(
            email=request.email,
            username=request.username,
            first_name=request.first_name,
            last_name=request.last_name,
            is_active=request.is_active,
        )

        # Modify user
        user_dto = await user_service.modify_user(user_id, modify_dto)

        logger.info(f"User modified successfully: {user_id}")

        # Convert DTO to response model
        return UserResponse(
            id=user_dto.id,
            email=user_dto.email,
            username=user_dto.username,
            first_name=user_dto.first_name,
            last_name=user_dto.last_name,
            is_active=user_dto.is_active,
            created_at=user_dto.created_at,
            updated_at=user_dto.updated_at,
        )

    except UserNotFoundError as e:
        logger.warning(f"User modification failed - not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {e}",
        ) from e

    except UserAlreadyExistsError as e:
        logger.warning(f"User modification failed - conflict: {e}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User already exists: {e}",
        ) from e

    except ValidationError as e:
        logger.warning(f"User modification failed - invalid data: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid user data: {e}",
        ) from e

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error modifying user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/{user_id}",
    response_model=SuccessResponse,
    summary="Delete user",
    description="Delete an existing user",
    responses={
        200: {"description": "User deleted successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
async def delete_user(
    user_id: str,
    user_service: Annotated[IUserService, Depends(get_user_service)],
    current_user: Annotated[dict, Depends(require_auth)],
) -> SuccessResponse:
    """Delete a user.

    Args:
        user_id: User ID to delete
        user_service: User service dependency
        current_user: Current authenticated user

    Returns:
        Success response

    Raises:
        HTTPException: If user deletion fails
    """
    try:
        # Check if user can delete this user (basic authorization)
        if current_user["user_id"] != user_id and "admin" not in current_user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to delete this user",
            )

        # Delete user
        await user_service.delete_user(user_id)

        logger.info(f"User deleted successfully: {user_id}")

        return SuccessResponse(
            success=True,
            message="User deleted successfully",
        )

    except UserNotFoundError as e:
        logger.warning(f"User deletion failed - not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {e}",
        ) from e

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e
