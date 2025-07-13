"""Main entry point for the Identity Module REST API.

This module creates and runs the FastAPI application.
"""

import logging
import os
from pathlib import Path

import uvicorn

# Add the parent directory to the Python path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.application.interfaces.user_service import IUserService
from src.infrastructure.config import SecurityConfig
from src.presentation.app import create_app, run_app

logger = logging.getLogger(__name__)


def get_mock_user_service() -> IUserService:
    """Get a mock user service for development.
    
    In production, this should be replaced with proper dependency injection.
    """
    from src.application.services.user_service import UserService
    from src.infrastructure.repositories.user_repository import UserRepository
    from src.infrastructure.database import get_session
    
    # This is a simplified setup - in production, use proper DI
    return UserService(UserRepository(get_session))


def get_security_config() -> SecurityConfig:
    """Get security configuration from environment."""
    return SecurityConfig(
        secret_key=os.getenv("SECRET_KEY", "your-secret-key-here"),
        algorithm=os.getenv("ALGORITHM", "HS256"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
        refresh_token_expire_days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")),
        password_min_length=int(os.getenv("PASSWORD_MIN_LENGTH", "8")),
        password_require_uppercase=os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true",
        password_require_lowercase=os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true",
        password_require_numbers=os.getenv("PASSWORD_REQUIRE_NUMBERS", "true").lower() == "true",
        password_require_special=os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true",
        password_history_count=int(os.getenv("PASSWORD_HISTORY_COUNT", "5")),
        max_login_attempts=int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")),
        lockout_duration_minutes=int(os.getenv("LOCKOUT_DURATION_MINUTES", "30")),
        mfa_issuer_name=os.getenv("MFA_ISSUER_NAME", "Identity Service"),
        mfa_token_validity_window=int(os.getenv("MFA_TOKEN_VALIDITY_WINDOW", "1")),
    )


# Create the FastAPI app
try:
    # For now, create a simplified user service
    user_service = get_mock_user_service()
    security_config = get_security_config()
    
    app = create_app(
        user_service=user_service,
        security_config=security_config,
        debug=os.getenv("APP_DEBUG", "false").lower() == "true"
    )
    
    logger.info("FastAPI application created successfully")
    
except Exception as e:
    logger.error(f"Failed to create FastAPI application: {e}")
    raise


if __name__ == "__main__":
    # Run the application directly
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000"))
    reload = os.getenv("APP_RELOAD", "true").lower() == "true"
    
    uvicorn.run(
        "src.presentation.rest.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )