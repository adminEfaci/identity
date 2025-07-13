"""JWT Authentication Middleware for FastAPI and GraphQL.

This module provides middleware for JWT token validation and user authentication
across both REST and GraphQL endpoints.
"""

import logging
from typing import Any, Callable, Optional

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

from ...infrastructure.security import JWTTokenService, SecurityError

logger = logging.getLogger(__name__)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """JWT Authentication Middleware for FastAPI applications.

    Validates JWT tokens and adds user information to request state
    for both REST and GraphQL endpoints.
    """

    def __init__(self, app: Any, token_service: JWTTokenService) -> None:
        """Initialize JWT authentication middleware.

        Args:
            app: FastAPI application instance
            token_service: JWT token service for validation
        """
        super().__init__(app)
        self._token_service = token_service

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        """Process request with JWT authentication.

        Args:
            request: HTTP request
            call_next: Next middleware in chain

        Returns:
            HTTP response
        """
        # Skip authentication for certain paths
        if self._should_skip_auth(request.url.path):
            return await call_next(request)

        try:
            # Extract and validate JWT token
            token = self._extract_token(request)
            if token:
                claims = self._token_service.validate_token(token)

                # Add user information to request state
                request.state.user_id = claims.get("sub")
                request.state.user_email = claims.get("email")
                request.state.user_roles = claims.get("roles", [])
                request.state.is_authenticated = True

                logger.debug(f"Authenticated user {claims.get('sub')}")
            else:
                request.state.is_authenticated = False

        except SecurityError as e:
            logger.warning(f"JWT validation failed: {e}")
            request.state.is_authenticated = False

        return await call_next(request)

    def _should_skip_auth(self, path: str) -> bool:
        """Check if authentication should be skipped for a path.

        Args:
            path: Request path

        Returns:
            True if authentication should be skipped
        """
        skip_paths = [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/graphql",  # GraphQL handles auth separately
        ]

        return any(path.startswith(skip_path) for skip_path in skip_paths)

    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract JWT token from request headers.

        Args:
            request: HTTP request

        Returns:
            JWT token string or None if not found
        """
        # Try Authorization header first
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove "Bearer " prefix

        # Try cookie as fallback
        return request.cookies.get("access_token")


class JWTBearer(HTTPBearer):
    """JWT Bearer token dependency for FastAPI endpoints.

    Provides JWT token validation as a FastAPI dependency that can be
    used to protect individual endpoints.
    """

    def __init__(self, token_service: JWTTokenService, auto_error: bool = True) -> None:
        """Initialize JWT Bearer dependency.

        Args:
            token_service: JWT token service for validation
            auto_error: Whether to automatically raise HTTP exceptions
        """
        super().__init__(auto_error=auto_error)
        self._token_service = token_service


def validate_jwt_token(
    token_service: JWTTokenService,
    credentials: Optional[HTTPAuthorizationCredentials],
    auto_error: bool = True,
) -> Optional[dict[str, Any]]:
    """Validate JWT token and return claims.

    Args:
        token_service: JWT token service
        credentials: HTTP authorization credentials
        auto_error: Whether to raise exceptions on errors

    Returns:
        JWT token claims or None if not authenticated

    Raises:
        HTTPException: If token is invalid and auto_error is True
    """
    if not credentials:
        if auto_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None

    try:
        claims = token_service.validate_token(credentials.credentials)
        logger.debug(f"Token validated for user {claims.get('sub')}")
        return claims

    except SecurityError as e:
        logger.warning(f"Token validation failed: {e}")
        if auto_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {e}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e
        return None


def get_current_user(request: Request) -> Optional[dict[str, Any]]:
    """Get current authenticated user from request state.

    Args:
        request: HTTP request with user state

    Returns:
        User information dictionary or None if not authenticated
    """
    if not getattr(request.state, "is_authenticated", False):
        return None

    return {
        "user_id": getattr(request.state, "user_id", None),
        "email": getattr(request.state, "user_email", None),
        "roles": getattr(request.state, "user_roles", []),
    }


def require_auth(request: Request) -> dict[str, Any]:
    """Require authentication and return user information.

    Args:
        request: HTTP request

    Returns:
        User information dictionary

    Raises:
        HTTPException: If user is not authenticated
    """
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(required_roles: list[str]) -> Callable:
    """Create a dependency that requires specific roles.

    Args:
        required_roles: List of required roles

    Returns:
        Dependency function that validates roles
    """
    def check_roles(request: Request) -> dict[str, Any]:
        user = require_auth(request)
        user_roles = user.get("roles", [])

        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}",
            )

        return user

    return check_roles


def require_admin(request: Request) -> dict[str, Any]:
    """Require admin role.

    Args:
        request: HTTP request

    Returns:
        User information dictionary

    Raises:
        HTTPException: If user is not an admin
    """
    return require_roles(["admin"])(request)


def get_current_user_optional(request: Request) -> Optional[dict[str, Any]]:
    """Get current user if authenticated, otherwise return None.

    Args:
        request: HTTP request

    Returns:
        User information dictionary or None
    """
    return get_current_user(request)
