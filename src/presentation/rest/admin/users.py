"""Admin user management REST API endpoints.

This module provides administrative endpoints for managing users including
advanced search, bulk operations, role assignments, and user analytics.
"""

from datetime import datetime, timedelta
from typing import Annotated, Optional, Any

from fastapi import Depends, Query, Body, Path
from pydantic import BaseModel, Field, EmailStr

from ..._base import (
    APIRouter,
    DataResponse,
    PaginatedResponse,
    ResponseMessages,
    get_pagination_params,
    PaginationParams,
    AdminMetadata,
    AuditableResponse,
    ErrorCodes,
    create_error_response,
)
from ...middleware.auth import require_admin


# Models for admin user management
class AdminUserDetails(BaseModel):
    """Detailed user information for admins."""
    
    id: str = Field(description="User ID")
    email: EmailStr = Field(description="User email")
    username: str = Field(description="Username")
    first_name: str = Field(description="First name")
    last_name: str = Field(description="Last name")
    is_active: bool = Field(description="Active status")
    is_verified: bool = Field(description="Email verification status")
    mfa_enabled: bool = Field(description="MFA enabled status")
    roles: list[str] = Field(description="User roles")
    permissions: list[str] = Field(description="Direct permissions")
    created_at: datetime = Field(description="Account creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")
    login_count: int = Field(description="Total login count")
    failed_login_count: int = Field(description="Failed login attempts")
    locked_until: Optional[datetime] = Field(default=None, description="Account lock expiry")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class UserSearchFilters(BaseModel):
    """Advanced user search filters."""
    
    query: Optional[str] = Field(default=None, description="Search in email, username, name")
    email: Optional[str] = Field(default=None, description="Filter by email (partial match)")
    username: Optional[str] = Field(default=None, description="Filter by username (partial match)")
    role: Optional[str] = Field(default=None, description="Filter by role")
    is_active: Optional[bool] = Field(default=None, description="Filter by active status")
    is_verified: Optional[bool] = Field(default=None, description="Filter by verification status")
    mfa_enabled: Optional[bool] = Field(default=None, description="Filter by MFA status")
    created_from: Optional[datetime] = Field(default=None, description="Created after date")
    created_to: Optional[datetime] = Field(default=None, description="Created before date")
    last_login_from: Optional[datetime] = Field(default=None, description="Last login after date")
    last_login_to: Optional[datetime] = Field(default=None, description="Last login before date")


class BulkUserOperation(BaseModel):
    """Bulk user operation request."""
    
    user_ids: list[str] = Field(description="List of user IDs")
    operation: str = Field(description="Operation to perform", example="activate")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Operation parameters")


class UserRoleAssignment(BaseModel):
    """User role assignment request."""
    
    role_ids: list[str] = Field(description="Role IDs to assign")
    replace: bool = Field(default=False, description="Replace existing roles")


class UserPermissionAssignment(BaseModel):
    """Direct permission assignment request."""
    
    permission_ids: list[str] = Field(description="Permission IDs to assign")
    replace: bool = Field(default=False, description="Replace existing permissions")


class UserLockRequest(BaseModel):
    """User account lock request."""
    
    reason: str = Field(description="Lock reason")
    duration_minutes: Optional[int] = Field(default=None, description="Lock duration in minutes")
    notify_user: bool = Field(default=True, description="Send notification to user")


class UserPasswordReset(BaseModel):
    """Admin password reset request."""
    
    temporary_password: Optional[str] = Field(default=None, description="Temporary password")
    require_change: bool = Field(default=True, description="Require password change on login")
    notify_user: bool = Field(default=True, description="Send notification to user")


class UserAnalytics(BaseModel):
    """User analytics data."""
    
    user_id: str = Field(description="User ID")
    total_sessions: int = Field(description="Total number of sessions")
    average_session_duration: int = Field(description="Average session duration in seconds")
    last_activity: datetime = Field(description="Last activity timestamp")
    device_count: int = Field(description="Number of devices used")
    location_count: int = Field(description="Number of unique locations")
    security_score: int = Field(description="Security score (0-100)")
    risk_factors: list[str] = Field(description="Identified risk factors")


# Create router
router = APIRouter(prefix="/api/admin/users", tags=["admin-users"])


@router.get(
    "/search",
    response_model=PaginatedResponse[AdminUserDetails],
    summary="Search users with advanced filters",
    description="Search and filter users with advanced criteria",
)
async def search_users(
    current_user: Annotated[dict, Depends(require_admin)],
    filters: Annotated[UserSearchFilters, Depends()],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
) -> PaginatedResponse[AdminUserDetails]:
    """Search users with advanced filtering."""
    # Mock data
    users = [
        AdminUserDetails(
            id=f"user{i}",
            email=f"user{i}@example.com",
            username=f"user{i}",
            first_name=f"First{i}",
            last_name=f"Last{i}",
            is_active=i % 10 != 0,
            is_verified=i % 3 != 0,
            mfa_enabled=i % 4 == 0,
            roles=["user"] if i % 5 != 0 else ["user", "admin"],
            permissions=[],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_login=datetime.utcnow() if i % 2 == 0 else None,
            login_count=i * 10,
            failed_login_count=i % 3,
            locked_until=None,
            metadata={},
        )
        for i in range(1, 101)
    ]
    
    # Apply filters (simplified)
    if filters.query:
        users = [
            u for u in users
            if filters.query.lower() in u.email.lower()
            or filters.query.lower() in u.username.lower()
        ]
    
    if filters.is_active is not None:
        users = [u for u in users if u.is_active == filters.is_active]
    
    # Paginate
    total = len(users)
    start = pagination.offset
    end = start + pagination.limit
    
    return PaginatedResponse.create(
        items=users[start:end],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        message="Users retrieved successfully",
    )


@router.get(
    "/{user_id}",
    response_model=DataResponse[AdminUserDetails],
    summary="Get user details",
    description="Get detailed user information for admin view",
)
async def get_user_details(
    user_id: str = Path(description="User ID"),
    current_user: dict = Depends(require_admin),
) -> DataResponse[AdminUserDetails]:
    """Get detailed user information."""
    user = AdminUserDetails(
        id=user_id,
        email=f"{user_id}@example.com",
        username=user_id,
        first_name="John",
        last_name="Doe",
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        roles=["user"],
        permissions=["read:profile"],
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        last_login=datetime.utcnow(),
        login_count=150,
        failed_login_count=2,
        locked_until=None,
        metadata={"source": "web", "referrer": "google"},
    )
    
    return DataResponse(
        status="success",
        message="User details retrieved successfully",
        data=user,
    )


@router.post(
    "/bulk-operation",
    response_model=AuditableResponse[dict],
    summary="Perform bulk user operation",
    description="Perform operations on multiple users at once",
)
async def bulk_user_operation(
    operation: BulkUserOperation = Body(...),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[dict]:
    """Perform bulk operations on users."""
    # Validate operation
    valid_operations = ["activate", "deactivate", "delete", "verify", "reset-mfa", "unlock"]
    if operation.operation not in valid_operations:
        return create_error_response(
            status_code=400,
            error_code=ErrorCodes.INVALID_INPUT,
            message=f"Invalid operation: {operation.operation}",
        )
    
    # Mock execution
    result = {
        "operation": operation.operation,
        "total_users": len(operation.user_ids),
        "successful": len(operation.user_ids),
        "failed": 0,
        "details": [],
    }
    
    return AuditableResponse(
        status="success",
        message=f"Bulk operation '{operation.operation}' completed successfully",
        data=result,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.post(
    "/{user_id}/roles",
    response_model=AuditableResponse[AdminUserDetails],
    summary="Assign roles to user",
    description="Assign or replace user roles",
)
async def assign_user_roles(
    user_id: str = Path(description="User ID"),
    assignment: UserRoleAssignment = Body(...),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[AdminUserDetails]:
    """Assign roles to a user."""
    # Mock user update
    user = AdminUserDetails(
        id=user_id,
        email=f"{user_id}@example.com",
        username=user_id,
        first_name="John",
        last_name="Doe",
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        roles=assignment.role_ids,
        permissions=["read:profile"],
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        last_login=datetime.utcnow(),
        login_count=150,
        failed_login_count=2,
        locked_until=None,
        metadata={},
    )
    
    return AuditableResponse(
        status="success",
        message="Roles assigned successfully",
        data=user,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.post(
    "/{user_id}/permissions",
    response_model=AuditableResponse[AdminUserDetails],
    summary="Assign direct permissions",
    description="Assign direct permissions to user",
)
async def assign_user_permissions(
    user_id: str = Path(description="User ID"),
    assignment: UserPermissionAssignment = Body(...),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[AdminUserDetails]:
    """Assign direct permissions to a user."""
    # Mock user update
    user = AdminUserDetails(
        id=user_id,
        email=f"{user_id}@example.com",
        username=user_id,
        first_name="John",
        last_name="Doe",
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        roles=["user"],
        permissions=assignment.permission_ids,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        last_login=datetime.utcnow(),
        login_count=150,
        failed_login_count=2,
        locked_until=None,
        metadata={},
    )
    
    return AuditableResponse(
        status="success",
        message="Permissions assigned successfully",
        data=user,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.post(
    "/{user_id}/lock",
    response_model=AuditableResponse[dict],
    summary="Lock user account",
    description="Lock a user account with reason",
)
async def lock_user_account(
    user_id: str = Path(description="User ID"),
    lock_request: UserLockRequest = Body(...),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[dict]:
    """Lock a user account."""
    lock_until = None
    if lock_request.duration_minutes:
        lock_until = datetime.utcnow() + timedelta(minutes=lock_request.duration_minutes)
    
    result = {
        "user_id": user_id,
        "locked": True,
        "locked_until": lock_until.isoformat() if lock_until else None,
        "reason": lock_request.reason,
        "notified": lock_request.notify_user,
    }
    
    return AuditableResponse(
        status="success",
        message="User account locked successfully",
        data=result,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.post(
    "/{user_id}/unlock",
    response_model=AuditableResponse[dict],
    summary="Unlock user account",
    description="Unlock a locked user account",
)
async def unlock_user_account(
    user_id: str = Path(description="User ID"),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[dict]:
    """Unlock a user account."""
    result = {
        "user_id": user_id,
        "locked": False,
        "unlocked_at": datetime.utcnow().isoformat(),
    }
    
    return AuditableResponse(
        status="success",
        message="User account unlocked successfully",
        data=result,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.post(
    "/{user_id}/reset-password",
    response_model=AuditableResponse[dict],
    summary="Reset user password",
    description="Admin reset of user password",
)
async def reset_user_password(
    user_id: str = Path(description="User ID"),
    reset_request: UserPasswordReset = Body(...),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[dict]:
    """Reset a user's password."""
    import secrets
    
    temp_password = reset_request.temporary_password or secrets.token_urlsafe(16)
    
    result = {
        "user_id": user_id,
        "temporary_password": temp_password if not reset_request.notify_user else None,
        "require_change": reset_request.require_change,
        "notified": reset_request.notify_user,
        "reset_at": datetime.utcnow().isoformat(),
    }
    
    return AuditableResponse(
        status="success",
        message="Password reset successfully",
        data=result,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.post(
    "/{user_id}/disable-mfa",
    response_model=AuditableResponse[dict],
    summary="Disable user MFA",
    description="Disable multi-factor authentication for user",
)
async def disable_user_mfa(
    user_id: str = Path(description="User ID"),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[dict]:
    """Disable MFA for a user."""
    result = {
        "user_id": user_id,
        "mfa_enabled": False,
        "disabled_at": datetime.utcnow().isoformat(),
    }
    
    return AuditableResponse(
        status="success",
        message="MFA disabled successfully",
        data=result,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.get(
    "/{user_id}/analytics",
    response_model=DataResponse[UserAnalytics],
    summary="Get user analytics",
    description="Get detailed analytics for a user",
)
async def get_user_analytics(
    user_id: str = Path(description="User ID"),
    current_user: dict = Depends(require_admin),
) -> DataResponse[UserAnalytics]:
    """Get user analytics data."""
    analytics = UserAnalytics(
        user_id=user_id,
        total_sessions=245,
        average_session_duration=1800,
        last_activity=datetime.utcnow(),
        device_count=3,
        location_count=5,
        security_score=85,
        risk_factors=["Multiple locations", "Unusual login time"],
    )
    
    return DataResponse(
        status="success",
        message="User analytics retrieved successfully",
        data=analytics,
    )


@router.post(
    "/{user_id}/impersonate",
    response_model=DataResponse[dict],
    summary="Impersonate user",
    description="Start impersonating a user (super admin only)",
)
async def impersonate_user(
    user_id: str = Path(description="User ID"),
    current_user: dict = Depends(require_admin),
) -> DataResponse[dict]:
    """Impersonate a user account."""
    # Check super admin permission
    if "super_admin" not in current_user.get("roles", []):
        return create_error_response(
            status_code=403,
            error_code=ErrorCodes.FORBIDDEN,
            message="Super admin permission required",
        )
    
    # Generate impersonation token
    impersonation_data = {
        "impersonation_token": "imp_token_123",
        "original_user_id": current_user["user_id"],
        "impersonated_user_id": user_id,
        "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
    }
    
    return DataResponse(
        status="success",
        message="Impersonation started successfully",
        data=impersonation_data,
    )