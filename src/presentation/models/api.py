"""Pydantic models for API requests and responses.

This module defines the data models used for REST API endpoints,
providing validation, serialization, and documentation.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserResponse(BaseModel):
    """Response model for user data.

    Used for returning user information in API responses.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique user identifier")
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., description="Unique username")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    is_active: bool = Field(..., description="Whether the user is active")
    created_at: datetime = Field(..., description="User creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class CreateUserRequest(BaseModel):
    """Request model for creating a new user.

    Contains all required fields for user creation.
    """

    email: EmailStr = Field(..., description="User email address")
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique username (3-50 characters)"
    )
    first_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="User's first name"
    )
    last_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="User's last name"
    )
    password: str = Field(
        ...,
        min_length=8,
        description="User password (minimum 8 characters)"
    )


class ModifyUserRequest(BaseModel):
    """Request model for modifying an existing user.

    All fields are optional to support partial updates.
    """

    email: Optional[EmailStr] = Field(None, description="New email address")
    username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=50,
        description="New username (3-50 characters)"
    )
    first_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=100,
        description="New first name"
    )
    last_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=100,
        description="New last name"
    )
    is_active: Optional[bool] = Field(None, description="New active status")


class UserListResponse(BaseModel):
    """Response model for user list endpoints.

    Contains paginated user data with metadata.
    """

    users: list[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of users")
    limit: int = Field(..., description="Number of users per page")
    offset: int = Field(..., description="Number of users skipped")


class ErrorResponse(BaseModel):
    """Standard error response model.

    Provides consistent error formatting across all endpoints.
    """

    error: str = Field(..., description="Error type or code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict] = Field(None, description="Additional error details")


class SuccessResponse(BaseModel):
    """Standard success response model.

    Used for operations that don't return specific data.
    """

    success: bool = Field(True, description="Operation success status")
    message: str = Field(..., description="Success message")


class TokenResponse(BaseModel):
    """Response model for authentication tokens.

    Contains access and refresh tokens with metadata.
    """

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")


class LoginRequest(BaseModel):
    """Request model for user login.

    Supports login with either email or username.
    """

    email_or_username: str = Field(..., description="Email address or username")
    password: str = Field(..., description="User password")


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh.

    Contains the refresh token for generating new access tokens.
    """

    refresh_token: str = Field(..., description="Valid refresh token")
