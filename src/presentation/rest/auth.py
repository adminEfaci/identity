"""Authentication REST API endpoints.

This module provides standardized authentication endpoints including
login, logout, token refresh, password reset, and session management.
"""

from datetime import datetime, timedelta
from typing import Annotated, Optional, Any

from fastapi import Depends, HTTPException, Body, Query, Header, Request
from pydantic import BaseModel, Field, EmailStr

from ._base import (
    APIRouter,
    DataResponse,
    ResponseMessages,
    ErrorCodes,
    create_error_response,
)
from ..middleware.auth import require_auth, get_current_user_optional


# Models for authentication
class LoginRequest(BaseModel):
    """Login request model."""
    
    username: str = Field(description="Username or email")
    password: str = Field(description="User password")
    remember_me: bool = Field(default=False, description="Extended session duration")


class LoginResponse(BaseModel):
    """Login response model."""
    
    access_token: str = Field(description="JWT access token")
    refresh_token: str = Field(description="Refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Token expiration time in seconds")
    user: dict[str, Any] = Field(description="User information")
    requires_mfa: bool = Field(default=False, description="MFA required")
    session_id: str = Field(description="Session identifier")


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    
    refresh_token: str = Field(description="Refresh token")


class PasswordResetRequest(BaseModel):
    """Password reset request."""
    
    email: EmailStr = Field(description="User email address")


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation."""
    
    token: str = Field(description="Reset token from email")
    new_password: str = Field(description="New password")


class ChangePasswordRequest(BaseModel):
    """Change password request."""
    
    current_password: str = Field(description="Current password")
    new_password: str = Field(description="New password")


class SessionInfo(BaseModel):
    """Session information model."""
    
    session_id: str = Field(description="Session ID")
    user_id: str = Field(description="User ID")
    created_at: datetime = Field(description="Session creation time")
    last_activity: datetime = Field(description="Last activity time")
    expires_at: datetime = Field(description="Session expiration time")
    ip_address: str = Field(description="Client IP address")
    user_agent: str = Field(description="Client user agent")
    device_info: dict[str, Any] = Field(description="Device information")
    is_current: bool = Field(description="Is current session")


# Create router
router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.post(
    "/login",
    response_model=DataResponse[LoginResponse],
    summary="User login",
    description="Authenticate user and receive access tokens",
    responses={
        200: {"description": "Login successful"},
        401: {"description": "Invalid credentials"},
        403: {"description": "Account locked or disabled"},
    },
)
async def login(
    request: Request,
    credentials: LoginRequest = Body(...),
    user_agent: Optional[str] = Header(None),
) -> DataResponse[LoginResponse]:
    """Authenticate user and return tokens."""
    # Mock authentication - in real implementation, verify against database
    if credentials.username == "admin@example.com" and credentials.password == "admin123":
        user = {
            "id": "user123",
            "email": "admin@example.com",
            "username": "admin",
            "first_name": "Admin",
            "last_name": "User",
            "roles": ["admin", "user"],
            "mfa_enabled": True,
        }
        
        # Generate tokens (mock)
        import secrets
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        
        response = LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=1800 if not credentials.remember_me else 86400,
            user=user,
            requires_mfa=user["mfa_enabled"],
            session_id=f"session_{secrets.token_hex(8)}",
        )
        
        return DataResponse(
            status="success",
            message="Login successful" if not user["mfa_enabled"] else "MFA verification required",
            data=response,
        )
    
    raise HTTPException(
        status_code=401,
        detail={"code": ErrorCodes.INVALID_CREDENTIALS, "message": "Invalid username or password"},
    )


@router.post(
    "/logout",
    response_model=DataResponse[dict],
    summary="User logout",
    description="Logout and invalidate current session",
)
async def logout(
    current_user: Annotated[dict, Depends(require_auth)],
    everywhere: bool = Query(False, description="Logout from all devices"),
) -> DataResponse[dict]:
    """Logout user and invalidate tokens."""
    # In real implementation, invalidate tokens and clear sessions
    result = {
        "user_id": current_user["user_id"],
        "sessions_cleared": "all" if everywhere else "current",
        "logged_out_at": datetime.utcnow().isoformat(),
    }
    
    return DataResponse(
        status="success",
        message=f"Logged out successfully{' from all devices' if everywhere else ''}",
        data=result,
    )


@router.post(
    "/refresh",
    response_model=DataResponse[LoginResponse],
    summary="Refresh access token",
    description="Exchange refresh token for new access token",
)
async def refresh_token(
    token_request: RefreshTokenRequest = Body(...),
) -> DataResponse[LoginResponse]:
    """Refresh access token using refresh token."""
    # Mock token refresh - validate refresh token in real implementation
    import secrets
    
    new_access_token = secrets.token_urlsafe(32)
    new_refresh_token = secrets.token_urlsafe(32)
    
    response = LoginResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=1800,
        user={
            "id": "user123",
            "email": "user@example.com",
            "username": "user",
            "roles": ["user"],
            "mfa_enabled": False,
        },
        requires_mfa=False,
        session_id="session_refreshed",
    )
    
    return DataResponse(
        status="success",
        message="Token refreshed successfully",
        data=response,
    )


@router.post(
    "/password/reset",
    response_model=DataResponse[dict],
    summary="Request password reset",
    description="Send password reset email to user",
)
async def request_password_reset(
    reset_request: PasswordResetRequest = Body(...),
) -> DataResponse[dict]:
    """Request password reset email."""
    # In real implementation, generate reset token and send email
    result = {
        "email": reset_request.email,
        "message": "If the email exists, a reset link has been sent",
        "expires_in_minutes": 30,
    }
    
    return DataResponse(
        status="success",
        message="Password reset requested",
        data=result,
    )


@router.post(
    "/password/reset/confirm",
    response_model=DataResponse[dict],
    summary="Confirm password reset",
    description="Reset password using token from email",
)
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirm = Body(...),
) -> DataResponse[dict]:
    """Confirm password reset with token."""
    # Validate token and update password in real implementation
    if len(reset_confirm.new_password) < 8:
        raise HTTPException(
            status_code=400,
            detail={"code": ErrorCodes.VALIDATION_ERROR, "message": "Password too short"},
        )
    
    result = {
        "reset_successful": True,
        "message": "Password has been reset successfully",
    }
    
    return DataResponse(
        status="success",
        message="Password reset successful",
        data=result,
    )


@router.post(
    "/password/change",
    response_model=DataResponse[dict],
    summary="Change password",
    description="Change password for authenticated user",
)
async def change_password(
    current_user: Annotated[dict, Depends(require_auth)],
    password_change: ChangePasswordRequest = Body(...),
) -> DataResponse[dict]:
    """Change user password."""
    # Verify current password and update in real implementation
    if password_change.current_password == password_change.new_password:
        raise HTTPException(
            status_code=400,
            detail={
                "code": ErrorCodes.VALIDATION_ERROR,
                "message": "New password must be different from current password",
            },
        )
    
    result = {
        "password_changed": True,
        "changed_at": datetime.utcnow().isoformat(),
        "next_change_required": None,
    }
    
    return DataResponse(
        status="success",
        message="Password changed successfully",
        data=result,
    )


@router.get(
    "/sessions",
    response_model=DataResponse[list[SessionInfo]],
    summary="Get active sessions",
    description="Get all active sessions for current user",
)
async def get_sessions(
    current_user: Annotated[dict, Depends(require_auth)],
) -> DataResponse[list[SessionInfo]]:
    """Get user's active sessions."""
    # Mock sessions - retrieve from database in real implementation
    sessions = [
        SessionInfo(
            session_id="session_current",
            user_id=current_user["user_id"],
            created_at=datetime.utcnow() - timedelta(hours=2),
            last_activity=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=22),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            device_info={
                "type": "desktop",
                "browser": "Chrome",
                "os": "macOS",
            },
            is_current=True,
        ),
        SessionInfo(
            session_id="session_mobile",
            user_id=current_user["user_id"],
            created_at=datetime.utcnow() - timedelta(days=1),
            last_activity=datetime.utcnow() - timedelta(hours=3),
            expires_at=datetime.utcnow() + timedelta(days=6),
            ip_address="192.168.1.101",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1)",
            device_info={
                "type": "mobile",
                "browser": "Safari",
                "os": "iOS",
            },
            is_current=False,
        ),
    ]
    
    return DataResponse(
        status="success",
        message="Sessions retrieved successfully",
        data=sessions,
    )


@router.delete(
    "/sessions/{session_id}",
    response_model=DataResponse[dict],
    summary="Revoke session",
    description="Revoke a specific session",
)
async def revoke_session(
    session_id: str,
    current_user: Annotated[dict, Depends(require_auth)],
) -> DataResponse[dict]:
    """Revoke a specific session."""
    # Validate and revoke session in real implementation
    result = {
        "session_id": session_id,
        "revoked": True,
        "revoked_at": datetime.utcnow().isoformat(),
    }
    
    return DataResponse(
        status="success",
        message="Session revoked successfully",
        data=result,
    )


@router.get(
    "/verify",
    response_model=DataResponse[dict],
    summary="Verify authentication",
    description="Verify if current token is valid",
)
async def verify_auth(
    current_user: Optional[dict] = Depends(get_current_user_optional),
) -> DataResponse[dict]:
    """Verify authentication status."""
    if current_user:
        return DataResponse(
            status="success",
            message="Authentication valid",
            data={
                "authenticated": True,
                "user_id": current_user["user_id"],
                "email": current_user.get("email"),
                "roles": current_user.get("roles", []),
                "session_valid": True,
            },
        )
    
    return DataResponse(
        status="success",
        message="Not authenticated",
        data={
            "authenticated": False,
            "session_valid": False,
        },
    )


@router.post(
    "/register",
    response_model=DataResponse[dict],
    summary="Register new user",
    description="Register a new user account",
)
async def register(
    email: EmailStr = Body(...),
    username: str = Body(...),
    password: str = Body(...),
    first_name: str = Body(...),
    last_name: str = Body(...),
    terms_accepted: bool = Body(...),
) -> DataResponse[dict]:
    """Register new user account."""
    if not terms_accepted:
        raise HTTPException(
            status_code=400,
            detail={
                "code": ErrorCodes.VALIDATION_ERROR,
                "message": "Terms and conditions must be accepted",
            },
        )
    
    # Create user in real implementation
    result = {
        "user_id": f"user_{datetime.utcnow().timestamp()}",
        "email": email,
        "username": username,
        "verification_required": True,
        "verification_sent": True,
    }
    
    return DataResponse(
        status="success",
        message="Registration successful. Please check your email to verify your account.",
        data=result,
    )


@router.post(
    "/verify-email",
    response_model=DataResponse[dict],
    summary="Verify email address",
    description="Verify user email with token",
)
async def verify_email(
    token: str = Query(..., description="Email verification token"),
) -> DataResponse[dict]:
    """Verify email address."""
    # Validate token and mark email as verified in real implementation
    result = {
        "email_verified": True,
        "verified_at": datetime.utcnow().isoformat(),
        "can_login": True,
    }
    
    return DataResponse(
        status="success",
        message="Email verified successfully",
        data=result,
    )


@router.post(
    "/resend-verification",
    response_model=DataResponse[dict],
    summary="Resend verification email",
    description="Resend email verification link",
)
async def resend_verification(
    email: EmailStr = Body(...),
) -> DataResponse[dict]:
    """Resend verification email."""
    result = {
        "email": email,
        "verification_sent": True,
        "expires_in_hours": 24,
    }
    
    return DataResponse(
        status="success",
        message="Verification email sent",
        data=result,
    )