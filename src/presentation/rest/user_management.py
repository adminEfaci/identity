"""REST API endpoints for comprehensive user account management with MFA integration.

This module implements user account management endpoints that integrate with
MFA, RBAC, and security features for complete user lifecycle management.
"""

import logging
from typing import Annotated, Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from ...core.auth import JWTManager
from ...core.mfa import BackupCodeManager, HardwareTokenManager, TOTPManager
from ...core.permissions import RBACManager
from ...domain.exceptions import ValidationError, WeakPasswordError
from ..middleware.auth import require_auth
from ..models.api import ErrorResponse, SuccessResponse

logger = logging.getLogger(__name__)

# Create router for user management endpoints
router = APIRouter(prefix="/api/user-management", tags=["user-management"])


# Request/Response Models
class UserAccountResponse(BaseModel):
    """Comprehensive user account information."""
    id: str = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    username: str = Field(..., description="Username")
    first_name: str = Field(..., description="First name")
    last_name: str = Field(..., description="Last name")
    status: str = Field(..., description="Account status")
    is_active: bool = Field(..., description="Whether account is active")
    email_verified: bool = Field(..., description="Whether email is verified")
    created_at: str = Field(..., description="Account creation date")
    updated_at: str = Field(..., description="Last update date")
    last_login: Optional[str] = Field(None, description="Last login timestamp")
    login_count: int = Field(..., description="Total login count")

    # MFA Information
    mfa_enabled: bool = Field(..., description="Whether MFA is enabled")
    totp_configured: bool = Field(..., description="Whether TOTP is configured")
    hardware_tokens_count: int = Field(..., description="Number of hardware tokens")

    # RBAC Information
    roles: list[str] = Field(..., description="Assigned roles")
    permissions: list[str] = Field(..., description="Effective permissions")


class ChangePasswordRequest(BaseModel):
    """Request to change password."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")
    mfa_token: Optional[str] = Field(None, description="MFA token if required")


class ResetPasswordRequest(BaseModel):
    """Request to initiate password reset."""
    email: EmailStr = Field(..., description="User email address")


class UpdateProfileRequest(BaseModel):
    """Request to update user profile."""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    email: Optional[EmailStr] = Field(None, description="New email address")


class SecuritySettingsResponse(BaseModel):
    """User security settings."""
    password_last_changed: str = Field(..., description="Password last changed date")
    require_password_change: bool = Field(..., description="Whether password change is required")
    failed_login_attempts: int = Field(..., description="Recent failed login attempts")
    account_locked: bool = Field(..., description="Whether account is locked")
    login_notification_enabled: bool = Field(..., description="Login notifications enabled")
    session_timeout_minutes: int = Field(..., description="Session timeout in minutes")


class UpdateSecuritySettingsRequest(BaseModel):
    """Request to update security settings."""
    login_notification_enabled: Optional[bool] = None
    session_timeout_minutes: Optional[int] = Field(None, ge=5, le=480)


class AccountLockRequest(BaseModel):
    """Request to lock/unlock account."""
    locked: bool = Field(..., description="Whether to lock the account")
    reason: Optional[str] = Field(None, description="Reason for locking")


class UserSessionResponse(BaseModel):
    """User session information."""
    session_id: str = Field(..., description="Session ID")
    ip_address: str = Field(..., description="IP address")
    user_agent: str = Field(..., description="User agent")
    created_at: str = Field(..., description="Session creation time")
    last_activity: str = Field(..., description="Last activity time")
    expires_at: str = Field(..., description="Session expiration time")
    is_current: bool = Field(..., description="Whether this is the current session")


# Dependency injection helpers
def get_user_service() -> Any:
    """Get user service instance."""
    # This should be injected via DI container
    raise RuntimeError("User service dependency not configured")


def get_jwt_manager() -> JWTManager:
    """Get JWT manager instance."""
    # This should be injected via DI container
    return JWTManager()


def get_totp_manager() -> TOTPManager:
    """Get TOTP manager instance."""
    return TOTPManager()


def get_hardware_token_manager() -> HardwareTokenManager:
    """Get hardware token manager instance."""
    return HardwareTokenManager()


def get_backup_code_manager() -> BackupCodeManager:
    """Get backup code manager instance."""
    return BackupCodeManager()


def get_rbac_manager() -> RBACManager:
    """Get RBAC manager instance."""
    return RBACManager()


@router.get(
    "/profile",
    response_model=UserAccountResponse,
    summary="Get user profile",
    description="Get comprehensive profile information for the current user",
    responses={
        200: {"description": "Profile retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def get_user_profile(
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
    totp_manager: Annotated[TOTPManager, Depends(get_totp_manager)],
    hardware_manager: Annotated[HardwareTokenManager, Depends(get_hardware_token_manager)],
    rbac_manager: Annotated[RBACManager, Depends(get_rbac_manager)],
) -> UserAccountResponse:
    """Get comprehensive user profile information.

    Args:
        current_user: Current authenticated user
        user_service: User service dependency
        totp_manager: TOTP manager dependency
        hardware_manager: Hardware token manager dependency
        rbac_manager: RBAC manager dependency

    Returns:
        Comprehensive user profile

    Raises:
        HTTPException: If profile retrieval fails
    """
    try:
        user_id = current_user["user_id"]

        # Get user details
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Get MFA status
        totp_configured = await totp_manager.is_totp_configured(user_id)
        hardware_tokens = await hardware_manager.get_user_tokens(user_id)

        # Get RBAC information
        user_roles = await rbac_manager.get_user_roles(user_id)
        user_permissions = await rbac_manager.get_user_permissions(user_id)

        # Get additional user stats
        login_stats = await user_service.get_user_login_stats(user_id)

        logger.debug(f"Retrieved profile for user {user_id}")

        return UserAccountResponse(
            id=str(user.id),
            email=user.email,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            status=user.status.value,
            is_active=user.is_active,
            email_verified=user.email_verified,
            created_at=user.created_at.isoformat(),
            updated_at=user.updated_at.isoformat(),
            last_login=login_stats.last_login.isoformat() if login_stats.last_login else None,
            login_count=login_stats.login_count,
            mfa_enabled=totp_configured or len(hardware_tokens) > 0,
            totp_configured=totp_configured,
            hardware_tokens_count=len(hardware_tokens),
            roles=[role.name for role in user_roles],
            permissions=[perm.name for perm in user_permissions],
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error retrieving user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.patch(
    "/profile",
    response_model=SuccessResponse,
    summary="Update user profile",
    description="Update user profile information",
    responses={
        200: {"description": "Profile updated successfully"},
        400: {"model": ErrorResponse, "description": "Invalid profile data"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        409: {"model": ErrorResponse, "description": "Email already in use"},
    },
)
async def update_user_profile(
    request: UpdateProfileRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
    background_tasks: BackgroundTasks,
) -> SuccessResponse:
    """Update user profile information.

    Args:
        request: Profile update request
        current_user: Current authenticated user
        user_service: User service dependency
        background_tasks: Background tasks for notifications

    Returns:
        Success response

    Raises:
        HTTPException: If profile update fails
    """
    try:
        user_id = current_user["user_id"]

        # Update profile
        updated_user = await user_service.update_user_profile(
            user_id=user_id,
            first_name=request.first_name,
            last_name=request.last_name,
            email=request.email,
        )

        # If email was changed, send verification email
        if request.email and request.email != updated_user.email:
            background_tasks.add_task(
                user_service.send_email_verification,
                user_id=user_id,
                new_email=request.email,
            )

        logger.info(f"Profile updated for user {user_id}")

        return SuccessResponse(
            success=True,
            message="Profile updated successfully",
        )

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid profile data: {e}",
        ) from e

    except Exception as e:
        logger.error(f"Error updating user profile: {e}")
        if "already in use" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email address is already in use",
            ) from e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/change-password",
    response_model=SuccessResponse,
    summary="Change password",
    description="Change user password with MFA verification if enabled",
    responses={
        200: {"description": "Password changed successfully"},
        400: {"model": ErrorResponse, "description": "Invalid password data"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "MFA verification required"},
    },
)
async def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
    totp_manager: Annotated[TOTPManager, Depends(get_totp_manager)],
    http_request: Request,
    background_tasks: BackgroundTasks,
) -> SuccessResponse:
    """Change user password.

    Args:
        request: Password change request
        current_user: Current authenticated user
        user_service: User service dependency
        totp_manager: TOTP manager dependency
        http_request: HTTP request for IP address
        background_tasks: Background tasks for notifications

    Returns:
        Success response

    Raises:
        HTTPException: If password change fails
    """
    try:
        user_id = current_user["user_id"]

        # Check if MFA is required
        mfa_configured = await totp_manager.is_totp_configured(user_id)
        if mfa_configured and not request.mfa_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification required for password change",
            )

        # Verify MFA token if provided
        if request.mfa_token:
            totp_secret = await totp_manager.get_user_totp_secret(user_id)
            client_ip = http_request.client.host if http_request.client else "unknown"

            is_valid = await totp_manager.verify_totp(
                secret=totp_secret,
                token=request.mfa_token,
                user_id=user_id,
                ip_address=client_ip,
            )

            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid MFA token",
                )

        # Change password
        await user_service.change_password(
            user_id=user_id,
            current_password=request.current_password,
            new_password=request.new_password,
        )

        # Send notification
        background_tasks.add_task(
            user_service.send_password_change_notification,
            user_id=user_id,
            ip_address=http_request.client.host if http_request.client else "unknown",
        )

        logger.info(f"Password changed for user {user_id}")

        return SuccessResponse(
            success=True,
            message="Password changed successfully",
        )

    except WeakPasswordError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password does not meet requirements: {e}",
        ) from e

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error changing password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/reset-password",
    response_model=SuccessResponse,
    summary="Request password reset",
    description="Request a password reset email",
    responses={
        200: {"description": "Password reset email sent"},
        400: {"model": ErrorResponse, "description": "Invalid email"},
        429: {"model": ErrorResponse, "description": "Too many requests"},
    },
)
async def request_password_reset(
    request: ResetPasswordRequest,
    user_service: Annotated[Any, Depends(get_user_service)],
    http_request: Request,
    background_tasks: BackgroundTasks,
) -> SuccessResponse:
    """Request a password reset email.

    Args:
        request: Password reset request
        user_service: User service dependency
        http_request: HTTP request for IP address
        background_tasks: Background tasks for email sending

    Returns:
        Success response

    Raises:
        HTTPException: If password reset request fails
    """
    try:
        client_ip = http_request.client.host if http_request.client else "unknown"

        # Request password reset
        background_tasks.add_task(
            user_service.request_password_reset,
            email=str(request.email),
            ip_address=client_ip,
        )

        logger.info(f"Password reset requested for email {request.email}")

        # Always return success for security (don't reveal if email exists)
        return SuccessResponse(
            success=True,
            message="If the email address exists, a password reset link has been sent",
        )

    except Exception as e:
        logger.error(f"Error requesting password reset: {e}")
        # Return success even on error for security
        return SuccessResponse(
            success=True,
            message="If the email address exists, a password reset link has been sent",
        )


@router.get(
    "/security",
    response_model=SecuritySettingsResponse,
    summary="Get security settings",
    description="Get current security settings for the user",
    responses={
        200: {"description": "Security settings retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def get_security_settings(
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
) -> SecuritySettingsResponse:
    """Get user security settings.

    Args:
        current_user: Current authenticated user
        user_service: User service dependency

    Returns:
        Security settings

    Raises:
        HTTPException: If security settings retrieval fails
    """
    try:
        user_id = current_user["user_id"]

        # Get security settings
        settings = await user_service.get_security_settings(user_id)

        logger.debug(f"Retrieved security settings for user {user_id}")

        return SecuritySettingsResponse(
            password_last_changed=settings.password_last_changed.isoformat(),
            require_password_change=settings.require_password_change,
            failed_login_attempts=settings.failed_login_attempts,
            account_locked=settings.account_locked,
            login_notification_enabled=settings.login_notification_enabled,
            session_timeout_minutes=settings.session_timeout_minutes,
        )

    except Exception as e:
        logger.error(f"Error retrieving security settings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.patch(
    "/security",
    response_model=SuccessResponse,
    summary="Update security settings",
    description="Update user security preferences",
    responses={
        200: {"description": "Security settings updated successfully"},
        400: {"model": ErrorResponse, "description": "Invalid settings"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def update_security_settings(
    request: UpdateSecuritySettingsRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
) -> SuccessResponse:
    """Update user security settings.

    Args:
        request: Security settings update request
        current_user: Current authenticated user
        user_service: User service dependency

    Returns:
        Success response

    Raises:
        HTTPException: If security settings update fails
    """
    try:
        user_id = current_user["user_id"]

        # Update security settings
        await user_service.update_security_settings(
            user_id=user_id,
            login_notification_enabled=request.login_notification_enabled,
            session_timeout_minutes=request.session_timeout_minutes,
        )

        logger.info(f"Security settings updated for user {user_id}")

        return SuccessResponse(
            success=True,
            message="Security settings updated successfully",
        )

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid settings: {e}",
        ) from e

    except Exception as e:
        logger.error(f"Error updating security settings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/sessions",
    response_model=list[UserSessionResponse],
    summary="List user sessions",
    description="Get list of active sessions for the current user",
    responses={
        200: {"description": "Sessions retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def list_user_sessions(
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
    http_request: Request,
) -> list[UserSessionResponse]:
    """List active sessions for the current user.

    Args:
        current_user: Current authenticated user
        user_service: User service dependency
        http_request: HTTP request for current session detection

    Returns:
        List of active sessions

    Raises:
        HTTPException: If session listing fails
    """
    try:
        user_id = current_user["user_id"]
        current_session_id = current_user.get("session_id")

        # Get user sessions
        sessions = await user_service.get_user_sessions(user_id)

        logger.debug(f"Retrieved {len(sessions)} sessions for user {user_id}")

        return [
            UserSessionResponse(
                session_id=str(session.id),
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                created_at=session.created_at.isoformat(),
                last_activity=session.last_activity.isoformat(),
                expires_at=session.expires_at.isoformat(),
                is_current=str(session.id) == current_session_id,
            )
            for session in sessions
        ]

    except Exception as e:
        logger.error(f"Error listing user sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/sessions/{session_id}",
    response_model=SuccessResponse,
    summary="Revoke session",
    description="Revoke a specific session",
    responses={
        200: {"description": "Session revoked successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Cannot revoke other user's session"},
        404: {"model": ErrorResponse, "description": "Session not found"},
    },
)
async def revoke_session(
    session_id: str,
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
) -> SuccessResponse:
    """Revoke a specific session.

    Args:
        session_id: Session ID to revoke
        current_user: Current authenticated user
        user_service: User service dependency

    Returns:
        Success response

    Raises:
        HTTPException: If session revocation fails
    """
    try:
        user_id = current_user["user_id"]

        # Revoke session
        success = await user_service.revoke_session(
            user_id=user_id,
            session_id=session_id,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or access denied",
            )

        logger.info(f"Session {session_id} revoked by user {user_id}")

        return SuccessResponse(
            success=True,
            message="Session revoked successfully",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error revoking session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/sessions",
    response_model=SuccessResponse,
    summary="Revoke all sessions",
    description="Revoke all sessions except the current one",
    responses={
        200: {"description": "All sessions revoked successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def revoke_all_sessions(
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
) -> SuccessResponse:
    """Revoke all sessions except the current one.

    Args:
        current_user: Current authenticated user
        user_service: User service dependency

    Returns:
        Success response

    Raises:
        HTTPException: If session revocation fails
    """
    try:
        user_id = current_user["user_id"]
        current_session_id = current_user.get("session_id")

        # Revoke all sessions except current
        revoked_count = await user_service.revoke_all_sessions_except(
            user_id=user_id,
            except_session_id=current_session_id,
        )

        logger.info(f"Revoked {revoked_count} sessions for user {user_id}")

        return SuccessResponse(
            success=True,
            message=f"Revoked {revoked_count} sessions successfully",
        )

    except Exception as e:
        logger.error(f"Error revoking all sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/account",
    response_model=SuccessResponse,
    summary="Delete account",
    description="Request account deletion (soft delete with recovery period)",
    responses={
        200: {"description": "Account deletion requested successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "MFA verification required"},
    },
)
async def request_account_deletion(
    current_user: Annotated[dict, Depends(require_auth)],
    user_service: Annotated[Any, Depends(get_user_service)],
    background_tasks: BackgroundTasks,
) -> SuccessResponse:
    """Request account deletion.

    Args:
        current_user: Current authenticated user
        user_service: User service dependency
        background_tasks: Background tasks for notifications

    Returns:
        Success response

    Raises:
        HTTPException: If account deletion request fails
    """
    try:
        user_id = current_user["user_id"]

        # Schedule account deletion
        await user_service.schedule_account_deletion(user_id)

        # Send confirmation email
        background_tasks.add_task(
            user_service.send_account_deletion_confirmation,
            user_id=user_id,
        )

        logger.info(f"Account deletion scheduled for user {user_id}")

        return SuccessResponse(
            success=True,
            message="Account deletion scheduled. You have 30 days to cancel this request.",
        )

    except Exception as e:
        logger.error(f"Error requesting account deletion: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e
