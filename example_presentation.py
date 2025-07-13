"""Example script demonstrating the Identity module presentation layer.

This script shows how to set up and run the FastAPI application with both
REST and GraphQL endpoints for user management.
"""

import asyncio
import logging
from typing import Any

from src.application.services.user_service import UserService
from src.infrastructure.config import DatabaseConfig, SecurityConfig
from src.infrastructure.database import DatabaseManager
from src.infrastructure.repositories import SqlAlchemyUserRepository
from src.infrastructure.security import Argon2PasswordHasher, JWTTokenService
from src.presentation import create_app, get_presentation_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


async def setup_dependencies() -> tuple[UserService, SecurityConfig]:
    """Set up all dependencies for the presentation layer.
    
    Returns:
        Tuple of (user_service, security_config)
    """
    # Database configuration
    db_config = DatabaseConfig(
        database_url="sqlite+aiosqlite:///./identity.db",
        echo=False,
    )
    
    # Security configuration
    security_config = SecurityConfig(
        jwt_secret_key="your-secret-key-change-in-production",
        jwt_algorithm="HS256",
        jwt_access_token_expire_minutes=30,
        jwt_refresh_token_expire_days=7,
    )
    
    # Initialize database
    db_manager = DatabaseManager(db_config)
    await db_manager.initialize()
    
    # Create repositories
    user_repository = SqlAlchemyUserRepository(db_manager.session_factory)
    
    # Create security services
    password_hasher = Argon2PasswordHasher(security_config)
    token_service = JWTTokenService(security_config)
    
    # Create user service
    user_service = UserService(
        user_repository=user_repository,
        password_hasher=password_hasher,
    )
    
    logger.info("Dependencies initialized successfully")
    return user_service, security_config


async def run_example() -> None:
    """Run the example application."""
    try:
        # Set up dependencies
        user_service, security_config = await setup_dependencies()
        
        # Get presentation configuration
        presentation_config = get_presentation_config()
        
        # Create FastAPI application
        app = create_app(
            user_service=user_service,
            security_config=security_config,
            debug=presentation_config.debug,
        )
        
        logger.info("FastAPI application created successfully")
        logger.info("Available endpoints:")
        logger.info("  - REST API: http://localhost:8000/api/users/")
        logger.info("  - GraphQL: http://localhost:8000/graphql")
        logger.info("  - Documentation: http://localhost:8000/docs")
        logger.info("  - Health Check: http://localhost:8000/health")
        
        # Import uvicorn here to avoid import issues
        import uvicorn
        
        # Run the application
        uvicorn.run(
            app,
            host=presentation_config.host,
            port=presentation_config.port,
            log_level=presentation_config.log_level.lower(),
            reload=presentation_config.reload,
        )
        
    except Exception as e:
        logger.error(f"Failed to run application: {e}")
        raise


def main() -> None:
    """Main entry point."""
    logger.info("Starting Identity Module Presentation Layer Example")
    
    try:
        asyncio.run(run_example())
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Application failed: {e}")
        raise


if __name__ == "__main__":
    main()