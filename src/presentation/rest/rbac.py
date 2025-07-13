"""REST API endpoints for Role-Based Access Control (RBAC) management.

This module implements REST API endpoints for RBAC operations including
role management, permission assignment, and access control.
"""

import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ...core.permissions import PermissionChecker, RBACManager
from ...domain.exceptions import ValidationError
from ..middleware.auth import require_auth
from ..models.api import ErrorResponse, SuccessResponse

logger = logging.getLogger(__name__)

# Create router for RBAC endpoints
router = APIRouter(prefix="/api/rbac", tags=["rbac"])


# Request/Response Models
class CreateRoleRequest(BaseModel):
    """Request to create a new role."""
    name: str = Field(..., min_length=1, max_length=100, description="Role name")
    description: Optional[str] = Field(None, max_length=500, description="Role description")
    permissions: list[str] = Field(default_factory=list, description="List of permission names")


class UpdateRoleRequest(BaseModel):
    """Request to update an existing role."""
    description: Optional[str] = Field(None, max_length=500, description="Role description")
    permissions: Optional[list[str]] = Field(None, description="List of permission names")


class RoleResponse(BaseModel):
    """Response model for role data."""
    id: str = Field(..., description="Role ID")
    name: str = Field(..., description="Role name")
    description: Optional[str] = Field(None, description="Role description")
    permissions: list[str] = Field(..., description="List of permission names")
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: str = Field(..., description="Last update timestamp")


class PermissionResponse(BaseModel):
    """Response model for permission data."""
    id: str = Field(..., description="Permission ID")
    name: str = Field(..., description="Permission name")
    description: Optional[str] = Field(None, description="Permission description")
    resource: str = Field(..., description="Resource type")
    action: str = Field(..., description="Action type")
    scope: Optional[str] = Field(None, description="Permission scope")


class UserRoleResponse(BaseModel):
    """Response model for user role assignments."""
    user_id: str = Field(..., description="User ID")
    roles: list[RoleResponse] = Field(..., description="Assigned roles")
    effective_permissions: list[str] = Field(..., description="All effective permissions")


class AssignRoleRequest(BaseModel):
    """Request to assign role to user."""
    user_id: str = Field(..., description="User ID")
    role_name: str = Field(..., description="Role name to assign")


class PermissionCheckRequest(BaseModel):
    """Request to check user permissions."""
    user_id: str = Field(..., description="User ID")
    resource: str = Field(..., description="Resource to check")
    action: str = Field(..., description="Action to check")
    scope: Optional[str] = Field(None, description="Optional scope")


class PermissionCheckResponse(BaseModel):
    """Response for permission check."""
    granted: bool = Field(..., description="Whether permission is granted")
    reason: Optional[str] = Field(None, description="Reason if denied")
    matching_permissions: list[str] = Field(..., description="Matching permission names")


# Dependency injection helpers
def get_rbac_manager() -> RBACManager:
    """Get RBAC manager instance."""
    # This should be injected via DI container
    return RBACManager()


def get_permission_checker() -> PermissionChecker:
    """Get permission checker instance."""
    # This should be injected via DI container
    return PermissionChecker()


def require_admin_role(current_user: dict = Depends(require_auth)) -> dict:
    """Require admin role for administrative operations."""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required",
        )
    return current_user


@router.get(
    "/roles",
    response_model=list[RoleResponse],
    summary="List all roles",
    description="Get a list of all available roles",
    responses={
        200: {"description": "Roles retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
    },
)
async def list_roles(
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
    limit: Annotated[int, Query(ge=1, le=100, description="Number of roles per page")] = 50,
    offset: Annotated[int, Query(ge=0, description="Number of roles to skip")] = 0,
) -> list[RoleResponse]:
    """List all roles with pagination.

    Args:
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency
        limit: Maximum number of roles to return
        offset: Number of roles to skip

    Returns:
        List of roles

    Raises:
        HTTPException: If role listing fails
    """
    try:
        # Get all roles
        roles = await rbac_manager.list_roles(limit=limit, offset=offset)

        logger.debug(f"Retrieved {len(roles)} roles")

        return [
            RoleResponse(
                id=str(role.id),
                name=role.name,
                description=role.description,
                permissions=[perm.name for perm in role.permissions],
                created_at=role.created_at.isoformat(),
                updated_at=role.updated_at.isoformat(),
            )
            for role in roles
        ]

    except Exception as e:
        logger.error(f"Error listing roles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/roles",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new role",
    description="Create a new role with specified permissions",
    responses={
        201: {"description": "Role created successfully"},
        400: {"model": ErrorResponse, "description": "Invalid role data"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
        409: {"model": ErrorResponse, "description": "Role already exists"},
    },
)
async def create_role(
    request: CreateRoleRequest,
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> RoleResponse:
    """Create a new role.

    Args:
        request: Role creation request data
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        Created role data

    Raises:
        HTTPException: If role creation fails
    """
    try:
        # Create role
        role = await rbac_manager.create_role(
            name=request.name,
            description=request.description,
            permission_names=request.permissions,
        )

        logger.info(f"Role created: {role.name} by user {current_user['user_id']}")

        return RoleResponse(
            id=str(role.id),
            name=role.name,
            description=role.description,
            permissions=[perm.name for perm in role.permissions],
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat(),
        )

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role data: {e}",
        ) from e

    except Exception as e:
        logger.error(f"Error creating role: {e}")
        if "already exists" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Role already exists: {request.name}",
            ) from e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/roles/{role_name}",
    response_model=RoleResponse,
    summary="Get role by name",
    description="Get detailed information about a specific role",
    responses={
        200: {"description": "Role retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
        404: {"model": ErrorResponse, "description": "Role not found"},
    },
)
async def get_role(
    role_name: str,
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> RoleResponse:
    """Get a role by name.

    Args:
        role_name: Name of the role to retrieve
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        Role data

    Raises:
        HTTPException: If role is not found
    """
    try:
        role = await rbac_manager.get_role_by_name(role_name)

        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role not found: {role_name}",
            )

        logger.debug(f"Retrieved role: {role_name}")

        return RoleResponse(
            id=str(role.id),
            name=role.name,
            description=role.description,
            permissions=[perm.name for perm in role.permissions],
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat(),
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error retrieving role {role_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.patch(
    "/roles/{role_name}",
    response_model=RoleResponse,
    summary="Update role",
    description="Update an existing role's description and permissions",
    responses={
        200: {"description": "Role updated successfully"},
        400: {"model": ErrorResponse, "description": "Invalid role data"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
        404: {"model": ErrorResponse, "description": "Role not found"},
    },
)
async def update_role(
    role_name: str,
    request: UpdateRoleRequest,
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> RoleResponse:
    """Update an existing role.

    Args:
        role_name: Name of the role to update
        request: Role update request data
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        Updated role data

    Raises:
        HTTPException: If role update fails
    """
    try:
        # Update role
        role = await rbac_manager.update_role(
            role_name=role_name,
            description=request.description,
            permission_names=request.permissions,
        )

        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role not found: {role_name}",
            )

        logger.info(f"Role updated: {role_name} by user {current_user['user_id']}")

        return RoleResponse(
            id=str(role.id),
            name=role.name,
            description=role.description,
            permissions=[perm.name for perm in role.permissions],
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat(),
        )

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role data: {e}",
        ) from e

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error updating role {role_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/roles/{role_name}",
    response_model=SuccessResponse,
    summary="Delete role",
    description="Delete an existing role",
    responses={
        200: {"description": "Role deleted successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
        404: {"model": ErrorResponse, "description": "Role not found"},
        409: {"model": ErrorResponse, "description": "Role is in use"},
    },
)
async def delete_role(
    role_name: str,
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> SuccessResponse:
    """Delete a role.

    Args:
        role_name: Name of the role to delete
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        Success response

    Raises:
        HTTPException: If role deletion fails
    """
    try:
        # Check if role is in use
        users_with_role = await rbac_manager.get_users_with_role(role_name)
        if users_with_role:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Role is assigned to {len(users_with_role)} users. Remove assignments first.",
            )

        # Delete role
        success = await rbac_manager.delete_role(role_name)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role not found: {role_name}",
            )

        logger.info(f"Role deleted: {role_name} by user {current_user['user_id']}")

        return SuccessResponse(
            success=True,
            message=f"Role '{role_name}' deleted successfully",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error deleting role {role_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/permissions",
    response_model=list[PermissionResponse],
    summary="List all permissions",
    description="Get a list of all available permissions",
    responses={
        200: {"description": "Permissions retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
    },
)
async def list_permissions(
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> list[PermissionResponse]:
    """List all available permissions.

    Args:
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        List of permissions

    Raises:
        HTTPException: If permission listing fails
    """
    try:
        permissions = await rbac_manager.list_permissions()

        logger.debug(f"Retrieved {len(permissions)} permissions")

        return [
            PermissionResponse(
                id=str(perm.id),
                name=perm.name,
                description=perm.description,
                resource=perm.resource,
                action=perm.action,
                scope=perm.scope,
            )
            for perm in permissions
        ]

    except Exception as e:
        logger.error(f"Error listing permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/users/{user_id}/roles",
    response_model=SuccessResponse,
    summary="Assign role to user",
    description="Assign a role to a specific user",
    responses={
        200: {"description": "Role assigned successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
        404: {"model": ErrorResponse, "description": "User or role not found"},
    },
)
async def assign_role_to_user(
    user_id: str,
    request: AssignRoleRequest,
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> SuccessResponse:
    """Assign a role to a user.

    Args:
        user_id: User ID to assign role to
        request: Role assignment request
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        Success response

    Raises:
        HTTPException: If role assignment fails
    """
    try:
        # Verify user_id matches request
        if user_id != request.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User ID in path and request body must match",
            )

        # Assign role
        success = await rbac_manager.assign_role(
            user_id=user_id,
            role_name=request.role_name,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User or role not found",
            )

        logger.info(f"Role '{request.role_name}' assigned to user {user_id} by {current_user['user_id']}")

        return SuccessResponse(
            success=True,
            message=f"Role '{request.role_name}' assigned successfully",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error assigning role to user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/users/{user_id}/roles/{role_name}",
    response_model=SuccessResponse,
    summary="Remove role from user",
    description="Remove a role assignment from a specific user",
    responses={
        200: {"description": "Role removed successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
        404: {"model": ErrorResponse, "description": "User or role not found"},
    },
)
async def remove_role_from_user(
    user_id: str,
    role_name: str,
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> SuccessResponse:
    """Remove a role from a user.

    Args:
        user_id: User ID to remove role from
        role_name: Role name to remove
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        Success response

    Raises:
        HTTPException: If role removal fails
    """
    try:
        success = await rbac_manager.remove_role(
            user_id=user_id,
            role_name=role_name,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User or role assignment not found",
            )

        logger.info(f"Role '{role_name}' removed from user {user_id} by {current_user['user_id']}")

        return SuccessResponse(
            success=True,
            message=f"Role '{role_name}' removed successfully",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error removing role from user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/users/{user_id}/roles",
    response_model=UserRoleResponse,
    summary="Get user roles",
    description="Get roles and effective permissions for a specific user",
    responses={
        200: {"description": "User roles retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Administrative privileges required"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
async def get_user_roles(
    user_id: str,
    current_user: Annotated[dict, Depends(require_admin_role)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> UserRoleResponse:
    """Get roles and permissions for a user.

    Args:
        user_id: User ID to get roles for
        current_user: Current authenticated admin user
        rbac_manager: RBAC manager dependency

    Returns:
        User roles and permissions

    Raises:
        HTTPException: If user role retrieval fails
    """
    try:
        # Get user roles
        user_roles = await rbac_manager.get_user_roles(user_id)

        # Get effective permissions
        user_permissions = await rbac_manager.get_user_permissions(user_id)

        logger.debug(f"Retrieved roles for user {user_id}")

        return UserRoleResponse(
            user_id=user_id,
            roles=[
                RoleResponse(
                    id=str(role.id),
                    name=role.name,
                    description=role.description,
                    permissions=[perm.name for perm in role.permissions],
                    created_at=role.created_at.isoformat(),
                    updated_at=role.updated_at.isoformat(),
                )
                for role in user_roles
            ],
            effective_permissions=[perm.name for perm in user_permissions],
        )

    except Exception as e:
        logger.error(f"Error retrieving user roles for {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/check-permission",
    response_model=PermissionCheckResponse,
    summary="Check user permission",
    description="Check if a user has permission to perform an action on a resource",
    responses={
        200: {"description": "Permission check completed"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def check_permission(
    request: PermissionCheckRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    permission_checker: Annotated[PermissionChecker, Depends(get_permission_checker)],
) -> PermissionCheckResponse:
    """Check if a user has a specific permission.

    Args:
        request: Permission check request
        current_user: Current authenticated user
        permission_checker: Permission checker dependency

    Returns:
        Permission check result

    Raises:
        HTTPException: If permission check fails
    """
    try:
        # Check permission
        result = await permission_checker.check_permission(
            user_id=request.user_id,
            resource=request.resource,
            action=request.action,
            scope=request.scope,
        )

        logger.debug(f"Permission check for user {request.user_id}: {result.granted}")

        return PermissionCheckResponse(
            granted=result.granted,
            reason=result.reason,
            matching_permissions=[perm.name for perm in result.matching_permissions],
        )

    except Exception as e:
        logger.error(f"Error checking permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e
