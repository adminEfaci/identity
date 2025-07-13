"""Main FastAPI application for the Identity module.

This module creates and configures the FastAPI application with both
REST API and GraphQL endpoints, middleware, and documentation.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from strawberry.fastapi import GraphQLRouter

from ..application.interfaces.user_service import IUserService
from ..infrastructure.config import SecurityConfig
from ..infrastructure.security import JWTTokenService
from .graphql.resolvers import schema
from .middleware.auth import JWTAuthMiddleware, get_current_user
from .rest.mfa import router as mfa_router
from .rest.rbac import router as rbac_router
from .rest.user_management import router as user_management_router
from .rest.users import router as users_router

logger = logging.getLogger(__name__)


class GraphQLContext:
    """GraphQL context class for dependency injection.

    Provides access to services and user information in GraphQL resolvers.
    """

    def __init__(self, request: Request, user_service: IUserService) -> None:
        """Initialize GraphQL context.

        Args:
            request: HTTP request
            user_service: User service instance
        """
        self.request = request
        self.user_service = user_service
        self.current_user = get_current_user(request)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager.

    Handles startup and shutdown events for the FastAPI application.

    Args:
        app: FastAPI application instance

    Yields:
        None during application runtime
    """
    # Startup
    logger.info("Starting Identity module presentation layer")

    # Initialize services here
    # This would typically involve setting up database connections,
    # dependency injection containers, etc.

    yield

    # Shutdown
    logger.info("Shutting down Identity module presentation layer")


def create_app(
    user_service: IUserService,
    security_config: SecurityConfig,
    debug: bool = False,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        user_service: User service instance
        security_config: Security configuration
        debug: Whether to enable debug mode

    Returns:
        Configured FastAPI application
    """
    # Create FastAPI app
    app = FastAPI(
        title="Identity Module API with MFA & RBAC",
        description="Comprehensive REST and GraphQL API for user identity management, Multi-Factor Authentication, and Role-Based Access Control",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        debug=debug,
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add JWT authentication middleware
    token_service = JWTTokenService(security_config)
    app.add_middleware(JWTAuthMiddleware, token_service=token_service)

    # Configure dependency injection
    def get_user_service_override() -> IUserService:
        return user_service

    # Create a modified router with dependency override
    from .rest.users import get_user_service
    app.dependency_overrides[get_user_service] = get_user_service_override

    # Include REST API routes
    app.include_router(users_router)
    app.include_router(mfa_router)
    app.include_router(rbac_router)
    app.include_router(user_management_router)

    # Create GraphQL router with context
    async def get_context(request: Request) -> GraphQLContext:
        return GraphQLContext(request, user_service)

    graphql_app = GraphQLRouter(
        schema,
        context_getter=get_context,
    )

    # Include GraphQL endpoint
    app.include_router(graphql_app, prefix="/graphql")

    # Add health check endpoint
    @app.get("/health")
    async def health_check() -> dict[str, str]:
        """Health check endpoint.

        Returns:
            Health status information
        """
        return {"status": "healthy", "service": "identity-module"}

    # Add global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Global exception handler for unhandled errors.

        Args:
            request: HTTP request
            exc: Unhandled exception

        Returns:
            JSON error response
        """
        logger.error(f"Unhandled exception: {exc}", exc_info=True)

        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "message": "An internal server error occurred",
                "details": str(exc) if debug else None,
            },
        )

    logger.info("FastAPI application created and configured")
    return app


def run_app(
    user_service: IUserService,
    security_config: SecurityConfig,
    host: str = "0.0.0.0",
    port: int = 8000,
    debug: bool = False,
) -> None:
    """Run the FastAPI application with Uvicorn.

    Args:
        user_service: User service instance
        security_config: Security configuration
        host: Host to bind to
        port: Port to bind to
        debug: Whether to enable debug mode
    """
    import uvicorn

    app = create_app(user_service, security_config, debug)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="debug" if debug else "info",
        reload=debug,
    )
