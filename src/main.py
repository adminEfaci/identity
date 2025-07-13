"""Main entry point for the Identity Module API.

This module creates and runs the FastAPI application with all configured
routers, middleware, and services.
"""

import logging
import os
from typing import Any

from presentation.app import create_app, run_app
from infrastructure.config import SecurityConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MockUserService:
    """Mock user service for development."""
    
    async def create_user(self, dto: Any) -> Any:
        """Mock create user."""
        from datetime import datetime
        return type('UserDto', (), {
            'id': 'user123',
            'email': dto.email,
            'username': dto.username,
            'first_name': dto.first_name,
            'last_name': dto.last_name,
            'is_active': True,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
        })()
    
    async def get_user_by_id(self, user_id: str) -> Any:
        """Mock get user."""
        from datetime import datetime
        return type('UserDto', (), {
            'id': user_id,
            'email': 'user@example.com',
            'username': 'user',
            'first_name': 'John',
            'last_name': 'Doe',
            'is_active': True,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
        })()
    
    async def list_users(self, **kwargs) -> list:
        """Mock list users."""
        return []
    
    async def modify_user(self, user_id: str, dto: Any) -> Any:
        """Mock modify user."""
        from datetime import datetime
        return type('UserDto', (), {
            'id': user_id,
            'email': dto.email or 'user@example.com',
            'username': dto.username or 'user',
            'first_name': dto.first_name or 'John',
            'last_name': dto.last_name or 'Doe',
            'is_active': dto.is_active if dto.is_active is not None else True,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
        })()
    
    async def delete_user(self, user_id: str) -> None:
        """Mock delete user."""
        pass


def main() -> None:
    """Run the REST API application."""
    # Create mock user service for development
    user_service = MockUserService()
    
    # Create security config from environment or defaults
    security_config = SecurityConfig(
        secret_key=os.getenv("SECRET_KEY", "development-secret-key-change-in-production"),
        algorithm=os.getenv("ALGORITHM", "HS256"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
    )
    
    # Run the application
    logger.info("Starting Identity Module REST API...")
    run_app(
        user_service=user_service,
        security_config=security_config,
        host="0.0.0.0",
        port=8000,
        debug=True,
    )


if __name__ == "__main__":
    main()