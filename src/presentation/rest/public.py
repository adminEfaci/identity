"""Public REST API endpoints.

This module provides public endpoints that don't require authentication,
including health checks, public user profiles, and system information.
"""

from datetime import datetime, timedelta
from typing import Optional, Any

from fastapi import Query, Path
from pydantic import BaseModel, Field

from ._base import (
    APIRouter,
    DataResponse,
    PaginatedResponse,
    ResponseMessages,
)


# Models for public endpoints
class HealthStatus(BaseModel):
    """Health check status model."""
    
    status: str = Field(description="Service status", example="healthy")
    service: str = Field(description="Service name")
    version: str = Field(description="API version")
    timestamp: datetime = Field(description="Current timestamp")
    uptime_seconds: int = Field(description="Service uptime in seconds")


class SystemInfo(BaseModel):
    """Public system information."""
    
    api_version: str = Field(description="API version")
    supported_features: list[str] = Field(description="Supported features")
    authentication_methods: list[str] = Field(description="Available auth methods")
    mfa_methods: list[str] = Field(description="Available MFA methods")
    rate_limits: dict[str, int] = Field(description="Rate limit information")
    contact: dict[str, str] = Field(description="Contact information")
    documentation_url: str = Field(description="API documentation URL")


class PublicUserProfile(BaseModel):
    """Public user profile information."""
    
    username: str = Field(description="Username")
    display_name: str = Field(description="Display name")
    avatar_url: Optional[str] = Field(default=None, description="Avatar URL")
    bio: Optional[str] = Field(default=None, description="User bio")
    joined_date: datetime = Field(description="Account creation date")
    is_verified: bool = Field(description="Verified status")
    public_email: Optional[str] = Field(default=None, description="Public email if enabled")


class PasswordStrength(BaseModel):
    """Password strength analysis."""
    
    score: int = Field(description="Strength score (0-100)")
    strength: str = Field(description="Strength level", example="strong")
    suggestions: list[str] = Field(description="Improvement suggestions")
    meets_requirements: bool = Field(description="Meets minimum requirements")
    checks: dict[str, bool] = Field(description="Individual check results")


class UsernameAvailability(BaseModel):
    """Username availability check result."""
    
    username: str = Field(description="Checked username")
    available: bool = Field(description="Is available")
    suggestions: list[str] = Field(description="Alternative suggestions if unavailable")


# Create router
router = APIRouter(prefix="/api/public", tags=["public"])


@router.get(
    "/health",
    response_model=HealthStatus,
    summary="Health check",
    description="Check if the service is healthy and running",
)
async def health_check() -> HealthStatus:
    """Health check endpoint."""
    import time
    
    # Calculate uptime (mock - would track actual start time)
    start_time = time.time() - 86400  # Mock 1 day uptime
    
    return HealthStatus(
        status="healthy",
        service="identity-module",
        version="1.0.0",
        timestamp=datetime.utcnow(),
        uptime_seconds=int(time.time() - start_time),
    )


@router.get(
    "/info",
    response_model=DataResponse[SystemInfo],
    summary="System information",
    description="Get public system information and capabilities",
)
async def system_info() -> DataResponse[SystemInfo]:
    """Get system information."""
    info = SystemInfo(
        api_version="1.0.0",
        supported_features=[
            "user_registration",
            "multi_factor_auth",
            "role_based_access",
            "session_management",
            "password_reset",
            "email_verification",
        ],
        authentication_methods=["password", "oauth2", "api_key"],
        mfa_methods=["totp", "sms", "email", "hardware_token"],
        rate_limits={
            "anonymous": 100,
            "authenticated": 1000,
            "admin": 10000,
        },
        contact={
            "support": "support@example.com",
            "security": "security@example.com",
        },
        documentation_url="https://api.example.com/docs",
    )
    
    return DataResponse(
        status="success",
        message="System information retrieved",
        data=info,
    )


@router.get(
    "/users/{username}/profile",
    response_model=DataResponse[PublicUserProfile],
    summary="Get public user profile",
    description="Get publicly available user profile information",
)
async def get_public_profile(
    username: str = Path(description="Username"),
) -> DataResponse[PublicUserProfile]:
    """Get public user profile."""
    # Mock profile - would fetch from database
    profile = PublicUserProfile(
        username=username,
        display_name=f"{username.title()} User",
        avatar_url=f"https://api.example.com/avatars/{username}.jpg",
        bio="This is a sample user bio",
        joined_date=datetime.utcnow() - timedelta(days=365),
        is_verified=True,
        public_email=None,  # Only if user enabled public email
    )
    
    return DataResponse(
        status="success",
        message="Profile retrieved successfully",
        data=profile,
    )


@router.post(
    "/check/username",
    response_model=DataResponse[UsernameAvailability],
    summary="Check username availability",
    description="Check if a username is available for registration",
)
async def check_username(
    username: str = Query(..., min_length=3, max_length=30, description="Username to check"),
) -> DataResponse[UsernameAvailability]:
    """Check username availability."""
    # Mock check - would query database
    taken_usernames = ["admin", "user", "test", "demo"]
    available = username.lower() not in taken_usernames
    
    suggestions = []
    if not available:
        # Generate suggestions
        import random
        suffixes = [str(random.randint(1, 999)), "_alt", "_new", f"_{datetime.now().year}"]
        suggestions = [f"{username}{suffix}" for suffix in suffixes][:3]
    
    result = UsernameAvailability(
        username=username,
        available=available,
        suggestions=suggestions,
    )
    
    return DataResponse(
        status="success",
        message=f"Username {'is available' if available else 'is already taken'}",
        data=result,
    )


@router.post(
    "/check/password-strength",
    response_model=DataResponse[PasswordStrength],
    summary="Check password strength",
    description="Analyze password strength without storing it",
)
async def check_password_strength(
    password: str = Query(..., description="Password to analyze"),
) -> DataResponse[PasswordStrength]:
    """Check password strength."""
    import re
    
    # Analyze password
    checks = {
        "min_length": len(password) >= 8,
        "has_uppercase": bool(re.search(r'[A-Z]', password)),
        "has_lowercase": bool(re.search(r'[a-z]', password)),
        "has_digit": bool(re.search(r'\d', password)),
        "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        "no_common_patterns": not any(
            pattern in password.lower()
            for pattern in ["password", "123456", "qwerty", "admin"]
        ),
    }
    
    # Calculate score
    score = sum(10 if check else 0 for check in checks.values())
    score += min(len(password) * 2, 40)  # Length bonus
    
    # Determine strength
    if score >= 80:
        strength = "strong"
    elif score >= 60:
        strength = "medium"
    elif score >= 40:
        strength = "weak"
    else:
        strength = "very_weak"
    
    # Generate suggestions
    suggestions = []
    if not checks["min_length"]:
        suggestions.append("Use at least 8 characters")
    if not checks["has_uppercase"]:
        suggestions.append("Include uppercase letters")
    if not checks["has_lowercase"]:
        suggestions.append("Include lowercase letters")
    if not checks["has_digit"]:
        suggestions.append("Include numbers")
    if not checks["has_special"]:
        suggestions.append("Include special characters")
    if not checks["no_common_patterns"]:
        suggestions.append("Avoid common patterns")
    
    result = PasswordStrength(
        score=min(score, 100),
        strength=strength,
        suggestions=suggestions,
        meets_requirements=score >= 60,
        checks=checks,
    )
    
    return DataResponse(
        status="success",
        message="Password strength analyzed",
        data=result,
    )


@router.get(
    "/stats",
    response_model=DataResponse[dict],
    summary="Get public statistics",
    description="Get public system statistics",
)
async def get_public_stats() -> DataResponse[dict]:
    """Get public statistics."""
    stats = {
        "total_users": 12500,
        "active_today": 3420,
        "new_users_this_week": 156,
        "countries_represented": 45,
        "average_session_duration_minutes": 25,
        "peak_hours_utc": [14, 15, 16, 20, 21],
    }
    
    return DataResponse(
        status="success",
        message="Statistics retrieved successfully",
        data=stats,
    )


@router.get(
    "/announcements",
    response_model=DataResponse[list[dict]],
    summary="Get public announcements",
    description="Get system announcements and news",
)
async def get_announcements(
    limit: int = Query(5, ge=1, le=20, description="Number of announcements"),
) -> DataResponse[list[dict]]:
    """Get public announcements."""
    announcements = [
        {
            "id": "ann_1",
            "title": "New MFA Options Available",
            "summary": "We've added support for hardware security keys",
            "date": datetime.utcnow().isoformat(),
            "type": "feature",
            "url": "https://blog.example.com/new-mfa-options",
        },
        {
            "id": "ann_2",
            "title": "Scheduled Maintenance",
            "summary": "System maintenance scheduled for Sunday 2-4 AM UTC",
            "date": (datetime.utcnow() + timedelta(days=3)).isoformat(),
            "type": "maintenance",
            "url": None,
        },
    ]
    
    return DataResponse(
        status="success",
        message="Announcements retrieved",
        data=announcements[:limit],
    )


@router.get(
    "/terms",
    response_model=DataResponse[dict],
    summary="Get terms of service",
    description="Get current terms of service information",
)
async def get_terms() -> DataResponse[dict]:
    """Get terms of service."""
    terms = {
        "version": "2.1",
        "effective_date": "2024-01-01",
        "url": "https://example.com/terms",
        "summary": "By using our service, you agree to our terms",
        "last_updated": "2023-12-15",
        "languages": ["en", "es", "fr", "de"],
    }
    
    return DataResponse(
        status="success",
        message="Terms retrieved",
        data=terms,
    )


@router.get(
    "/privacy",
    response_model=DataResponse[dict],
    summary="Get privacy policy",
    description="Get current privacy policy information",
)
async def get_privacy() -> DataResponse[dict]:
    """Get privacy policy."""
    privacy = {
        "version": "1.5",
        "effective_date": "2024-01-01",
        "url": "https://example.com/privacy",
        "summary": "We respect your privacy and protect your data",
        "last_updated": "2023-12-15",
        "languages": ["en", "es", "fr", "de"],
        "data_controller": "Example Corp",
        "contact": "privacy@example.com",
    }
    
    return DataResponse(
        status="success",
        message="Privacy policy retrieved",
        data=privacy,
    )


@router.get(
    "/supported-languages",
    response_model=DataResponse[list[dict]],
    summary="Get supported languages",
    description="Get list of supported languages for the UI",
)
async def get_supported_languages() -> DataResponse[list[dict]]:
    """Get supported languages."""
    languages = [
        {"code": "en", "name": "English", "native_name": "English", "rtl": False},
        {"code": "es", "name": "Spanish", "native_name": "Español", "rtl": False},
        {"code": "fr", "name": "French", "native_name": "Français", "rtl": False},
        {"code": "de", "name": "German", "native_name": "Deutsch", "rtl": False},
        {"code": "ar", "name": "Arabic", "native_name": "العربية", "rtl": True},
        {"code": "zh", "name": "Chinese", "native_name": "中文", "rtl": False},
        {"code": "ja", "name": "Japanese", "native_name": "日本語", "rtl": False},
    ]
    
    return DataResponse(
        status="success",
        message="Languages retrieved",
        data=languages,
    )