"""JWT authentication utilities for the identity service."""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Union
from uuid import uuid4

import jwt
from pydantic import BaseModel, Field, validator

from ..logging import get_logger

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Authentication-related errors."""
    pass


class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    pass


class TokenInvalidError(AuthenticationError):
    """Token is invalid."""
    pass


class JWTClaims(BaseModel):
    """JWT token claims model."""

    # Standard claims
    sub: str = Field(..., description="Subject (user ID)")
    iss: str = Field(..., description="Issuer")
    aud: Union[str, list[str]] = Field(..., description="Audience")
    exp: datetime = Field(..., description="Expiration time")
    iat: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Issued at")
    nbf: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Not before")
    jti: str = Field(default_factory=lambda: str(uuid4()), description="JWT ID")

    # Custom claims
    email: Optional[str] = None
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    mfa_verified: bool = False
    token_type: str = "access"

    @validator('exp', 'iat', 'nbf', pre=True)
    def parse_datetime(cls, v: Any) -> datetime:
        """Parse datetime from various formats."""
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc)
        return v

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JWT encoding."""
        data = self.dict()

        # Convert datetime objects to timestamps
        for field in ['exp', 'iat', 'nbf']:
            if isinstance(data[field], datetime):
                data[field] = int(data[field].timestamp())

        return data


class JWTManager:
    """JWT token manager with comprehensive token operations."""

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        issuer: str = "identity-service",
        audience: str = "identity-api",
        access_token_expire_minutes: int = 15,
        refresh_token_expire_days: int = 30
    ):
        """Initialize JWT manager.

        Args:
            secret_key: Secret key for signing tokens
            algorithm: JWT algorithm
            issuer: Token issuer
            audience: Token audience
            access_token_expire_minutes: Access token expiration in minutes
            refresh_token_expire_days: Refresh token expiration in days
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days

    def create_access_token(
        self,
        user_id: str,
        email: Optional[str] = None,
        roles: Optional[list[str]] = None,
        permissions: Optional[list[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        mfa_verified: bool = False,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create an access token.

        Args:
            user_id: User identifier
            email: User email
            roles: User roles
            permissions: User permissions
            session_id: Session identifier
            device_id: Device identifier
            mfa_verified: Whether MFA is verified
            expires_delta: Custom expiration delta

        Returns:
            Encoded JWT token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)

        claims = JWTClaims(
            sub=user_id,
            iss=self.issuer,
            aud=self.audience,
            exp=expire,
            email=email,
            roles=roles or [],
            permissions=permissions or [],
            session_id=session_id,
            device_id=device_id,
            mfa_verified=mfa_verified,
            token_type="access"
        )

        token = jwt.encode(claims.to_dict(), self.secret_key, algorithm=self.algorithm)

        logger.info(
            "Access token created",
            user_id=user_id,
            token_id=claims.jti,
            expires_at=expire.isoformat()
        )

        return token

    def create_refresh_token(
        self,
        user_id: str,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a refresh token.

        Args:
            user_id: User identifier
            session_id: Session identifier
            device_id: Device identifier
            expires_delta: Custom expiration delta

        Returns:
            Encoded JWT refresh token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days)

        claims = JWTClaims(
            sub=user_id,
            iss=self.issuer,
            aud=self.audience,
            exp=expire,
            session_id=session_id,
            device_id=device_id,
            token_type="refresh"
        )

        token = jwt.encode(claims.to_dict(), self.secret_key, algorithm=self.algorithm)

        logger.info(
            "Refresh token created",
            user_id=user_id,
            token_id=claims.jti,
            expires_at=expire.isoformat()
        )

        return token

    def decode_token(self, token: str) -> JWTClaims:
        """Decode and validate a JWT token.

        Args:
            token: JWT token to decode

        Returns:
            Decoded JWT claims

        Raises:
            TokenExpiredError: If token is expired
            TokenInvalidError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer
            )

            claims = JWTClaims(**payload)

            logger.debug(
                "Token decoded successfully",
                user_id=claims.sub,
                token_id=claims.jti,
                token_type=claims.token_type
            )

            return claims

        except jwt.ExpiredSignatureError as e:
            logger.warning("Token expired", error=str(e))
            raise TokenExpiredError("Token has expired") from e
        except jwt.InvalidTokenError as e:
            logger.warning("Invalid token", error=str(e))
            raise TokenInvalidError("Invalid token") from e

    def verify_token(self, token: str) -> bool:
        """Verify if a token is valid.

        Args:
            token: JWT token to verify

        Returns:
            True if token is valid, False otherwise
        """
        try:
            self.decode_token(token)
            return True
        except (TokenExpiredError, TokenInvalidError):
            return False

    def get_token_claims(self, token: str) -> Optional[JWTClaims]:
        """Get token claims without verification (for expired tokens).

        Args:
            token: JWT token

        Returns:
            Token claims or None if token is malformed
        """
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False}
            )
            return JWTClaims(**payload)
        except Exception as e:
            logger.warning("Failed to parse token claims", error=str(e))
            return None


class TokenValidator:
    """Token validation utilities."""

    def __init__(self, jwt_manager: JWTManager):
        """Initialize token validator.

        Args:
            jwt_manager: JWT manager instance
        """
        self.jwt_manager = jwt_manager

    def validate_access_token(self, token: str) -> JWTClaims:
        """Validate an access token.

        Args:
            token: Access token to validate

        Returns:
            Token claims

        Raises:
            TokenInvalidError: If token is not an access token
        """
        claims = self.jwt_manager.decode_token(token)

        if claims.token_type != "access":
            raise TokenInvalidError("Token is not an access token")

        return claims

    def validate_refresh_token(self, token: str) -> JWTClaims:
        """Validate a refresh token.

        Args:
            token: Refresh token to validate

        Returns:
            Token claims

        Raises:
            TokenInvalidError: If token is not a refresh token
        """
        claims = self.jwt_manager.decode_token(token)

        if claims.token_type != "refresh":
            raise TokenInvalidError("Token is not a refresh token")

        return claims

    def require_mfa(self, claims: JWTClaims) -> None:
        """Require MFA verification for the token.

        Args:
            claims: Token claims

        Raises:
            AuthenticationError: If MFA is not verified
        """
        if not claims.mfa_verified:
            raise AuthenticationError("MFA verification required")

    def require_roles(self, claims: JWTClaims, required_roles: list[str]) -> None:
        """Require specific roles for the token.

        Args:
            claims: Token claims
            required_roles: List of required roles

        Raises:
            AuthenticationError: If required roles are not present
        """
        user_roles = set(claims.roles)
        required_roles_set = set(required_roles)

        if not required_roles_set.intersection(user_roles):
            raise AuthenticationError(f"Required roles not found: {required_roles}")

    def require_permissions(self, claims: JWTClaims, required_permissions: list[str]) -> None:
        """Require specific permissions for the token.

        Args:
            claims: Token claims
            required_permissions: List of required permissions

        Raises:
            AuthenticationError: If required permissions are not present
        """
        user_permissions = set(claims.permissions)
        required_permissions_set = set(required_permissions)

        if not required_permissions_set.issubset(user_permissions):
            missing = required_permissions_set - user_permissions
            raise AuthenticationError(f"Missing permissions: {list(missing)}")


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Extract bearer token from Authorization header.

    Args:
        authorization_header: Authorization header value

    Returns:
        Bearer token or None
    """
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1]
