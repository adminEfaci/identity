"""Security Infrastructure for Identity Module.

This module provides security implementations including Argon2 password hashing,
JWT token management, and comprehensive security services for authentication
and authorization.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import (
    HashingError,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

from ..domain.value_objects import PasswordHash
from .config import SecurityConfig

logger = logging.getLogger(__name__)


class PasswordHasherInterface(ABC):
    """Abstract interface for password hashing implementations.

    Defines the contract for password hashing services to support
    different hashing algorithms while maintaining security standards.
    """

    @abstractmethod
    def hash_password(self, password: str) -> PasswordHash:
        """Hash a plaintext password.

        Args:
            password: Plaintext password to hash

        Returns:
            PasswordHash value object with hashed password and metadata

        Raises:
            SecurityError: If hashing fails
        """
        pass

    @abstractmethod
    def verify_password(self, password: str, password_hash: PasswordHash) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plaintext password to verify
            password_hash: PasswordHash value object to verify against

        Returns:
            True if password matches, False otherwise

        Raises:
            SecurityError: If verification fails due to invalid hash
        """
        pass

    @abstractmethod
    def needs_rehash(self, password_hash: PasswordHash) -> bool:
        """Check if a password hash needs to be rehashed.

        Args:
            password_hash: PasswordHash value object to check

        Returns:
            True if rehashing is recommended, False otherwise
        """
        pass


class TokenServiceInterface(ABC):
    """Abstract interface for token management implementations.

    Defines the contract for JWT token services including generation,
    validation, and refresh token management.
    """

    @abstractmethod
    def generate_access_token(
        self,
        user_id: str,
        email: str,
        roles: list[str],
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """Generate an access token for a user.

        Args:
            user_id: User ID
            email: User email
            roles: List of user roles
            additional_claims: Optional additional JWT claims

        Returns:
            JWT access token string

        Raises:
            SecurityError: If token generation fails
        """
        pass

    @abstractmethod
    def generate_refresh_token(
        self,
        user_id: str,
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """Generate a refresh token for a user.

        Args:
            user_id: User ID
            additional_claims: Optional additional JWT claims

        Returns:
            JWT refresh token string

        Raises:
            SecurityError: If token generation fails
        """
        pass

    @abstractmethod
    def validate_token(self, token: str) -> dict[str, Any]:
        """Validate and decode a JWT token.

        Args:
            token: JWT token string to validate

        Returns:
            Decoded token claims

        Raises:
            SecurityError: If token is invalid or expired
        """
        pass

    @abstractmethod
    def refresh_access_token(self, refresh_token: str) -> str:
        """Generate a new access token using a refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New JWT access token string

        Raises:
            SecurityError: If refresh token is invalid or expired
        """
        pass

    @abstractmethod
    def revoke_token(self, token: str) -> bool:
        """Revoke a JWT token.

        Args:
            token: JWT token to revoke

        Returns:
            True if token was revoked successfully, False otherwise
        """
        pass


class SecurityError(Exception):
    """Base exception for security-related errors."""

    pass


class Argon2PasswordHasher(PasswordHasherInterface):
    """Argon2-based password hashing implementation.

    Provides secure password hashing using the Argon2 algorithm with
    configurable parameters for optimal security and performance.
    """

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize Argon2 password hasher with configuration.

        Args:
            config: Security configuration settings
        """
        self._config = config
        self._hasher = PasswordHasher(
            time_cost=config.argon2_time_cost,
            memory_cost=config.argon2_memory_cost,
            parallelism=config.argon2_parallelism,
            hash_len=config.argon2_hash_len,
            salt_len=config.argon2_salt_len,
        )

    def hash_password(self, password: str) -> PasswordHash:
        """Hash a plaintext password using Argon2.

        Args:
            password: Plaintext password to hash

        Returns:
            PasswordHash value object with Argon2 hash and metadata

        Raises:
            SecurityError: If hashing fails
        """
        if not password:
            raise SecurityError("Password cannot be empty")

        if len(password) < 8:
            raise SecurityError("Password must be at least 8 characters long")

        try:
            # Generate Argon2 hash
            hash_value = self._hasher.hash(password)

            logger.debug("Password hashed successfully using Argon2")

            return PasswordHash(
                hash_value=hash_value,
                algorithm="argon2",
                salt=None,  # Salt is embedded in Argon2 hash
                iterations=self._config.argon2_time_cost,
            )

        except HashingError as e:
            logger.error(f"Failed to hash password with Argon2: {e}")
            raise SecurityError(f"Password hashing failed: {e}") from e

    def verify_password(self, password: str, password_hash: PasswordHash) -> bool:
        """Verify a password against its Argon2 hash.

        Args:
            password: Plaintext password to verify
            password_hash: PasswordHash value object to verify against

        Returns:
            True if password matches, False otherwise

        Raises:
            SecurityError: If verification fails due to invalid hash
        """
        if not password:
            return False

        if password_hash.algorithm != "argon2":
            raise SecurityError(
                f"Unsupported hash algorithm: {password_hash.algorithm}"
            )

        try:
            # Verify password against Argon2 hash
            self._hasher.verify(password_hash.hash_value, password)
            logger.debug("Password verified successfully")
            return True

        except VerifyMismatchError:
            logger.debug("Password verification failed: mismatch")
            return False

        except (InvalidHashError, VerificationError) as e:
            logger.error(f"Password verification error: {e}")
            raise SecurityError(f"Password verification failed: {e}") from e

    def needs_rehash(self, password_hash: PasswordHash) -> bool:
        """Check if an Argon2 password hash needs to be rehashed.

        Args:
            password_hash: PasswordHash value object to check

        Returns:
            True if rehashing is recommended, False otherwise
        """
        if password_hash.algorithm != "argon2":
            return True  # Different algorithm, needs rehash

        try:
            # Check if hash parameters match current configuration
            return self._hasher.check_needs_rehash(password_hash.hash_value)

        except Exception as e:
            logger.warning(f"Could not check rehash status: {e}")
            return True  # Conservative approach: rehash if unsure


class JWTTokenService(TokenServiceInterface):
    """JWT-based token service implementation.

    Provides JWT token generation, validation, and management with
    support for access tokens, refresh tokens, and token revocation.
    """

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize JWT token service with configuration.

        Args:
            config: Security configuration settings
        """
        self._config = config
        self._revoked_tokens: set[str] = set()  # In-memory revocation list

    def generate_access_token(
        self,
        user_id: str,
        email: str,
        roles: list[str],
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """Generate a JWT access token for a user.

        Args:
            user_id: User ID
            email: User email
            roles: List of user roles
            additional_claims: Optional additional JWT claims

        Returns:
            JWT access token string

        Raises:
            SecurityError: If token generation fails
        """
        try:
            now = datetime.utcnow()
            expiration = now + timedelta(
                minutes=self._config.jwt_access_token_expire_minutes
            )

            # Build JWT claims
            claims = {
                "sub": user_id,  # Subject (user ID)
                "email": email,
                "roles": roles,
                "iat": now,  # Issued at
                "exp": expiration,  # Expiration
                "type": "access",
                "jti": f"access_{user_id}_{int(now.timestamp())}",  # JWT ID
            }

            # Add additional claims if provided
            if additional_claims:
                claims.update(additional_claims)

            # Generate JWT token
            token = jwt.encode(
                claims,
                self._config.jwt_secret_key,
                algorithm=self._config.jwt_algorithm,
            )

            logger.debug(f"Generated access token for user {user_id}")
            return token

        except Exception as e:
            logger.error(f"Failed to generate access token: {e}")
            raise SecurityError(f"Token generation failed: {e}") from e

    def generate_refresh_token(
        self,
        user_id: str,
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """Generate a JWT refresh token for a user.

        Args:
            user_id: User ID
            additional_claims: Optional additional JWT claims

        Returns:
            JWT refresh token string

        Raises:
            SecurityError: If token generation fails
        """
        try:
            now = datetime.utcnow()
            expiration = now + timedelta(
                days=self._config.jwt_refresh_token_expire_days
            )

            # Build JWT claims for refresh token
            claims = {
                "sub": user_id,  # Subject (user ID)
                "iat": now,  # Issued at
                "exp": expiration,  # Expiration
                "type": "refresh",
                "jti": f"refresh_{user_id}_{int(now.timestamp())}",  # JWT ID
            }

            # Add additional claims if provided
            if additional_claims:
                claims.update(additional_claims)

            # Generate JWT token
            token = jwt.encode(
                claims,
                self._config.jwt_secret_key,
                algorithm=self._config.jwt_algorithm,
            )

            logger.debug(f"Generated refresh token for user {user_id}")
            return token

        except Exception as e:
            logger.error(f"Failed to generate refresh token: {e}")
            raise SecurityError(f"Refresh token generation failed: {e}") from e

    def validate_token(self, token: str) -> dict[str, Any]:
        """Validate and decode a JWT token.

        Args:
            token: JWT token string to validate

        Returns:
            Decoded token claims

        Raises:
            SecurityError: If token is invalid or expired
        """
        if not token:
            raise SecurityError("Token cannot be empty")

        # Check if token is revoked
        if token in self._revoked_tokens:
            raise SecurityError("Token has been revoked")

        try:
            # Decode and validate JWT token
            claims = jwt.decode(
                token,
                self._config.jwt_secret_key,
                algorithms=[self._config.jwt_algorithm],
            )

            logger.debug(f"Token validated successfully for user {claims.get('sub')}")
            return claims

        except jwt.ExpiredSignatureError:
            logger.debug("Token validation failed: expired")
            raise SecurityError("Token has expired") from None

        except jwt.InvalidTokenError as e:
            logger.debug(f"Token validation failed: {e}")
            raise SecurityError(f"Invalid token: {e}") from e

    def refresh_access_token(self, refresh_token: str) -> str:
        """Generate a new access token using a refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New JWT access token string

        Raises:
            SecurityError: If refresh token is invalid or expired
        """
        # Validate refresh token
        claims = self.validate_token(refresh_token)

        # Check if it's actually a refresh token
        if claims.get("type") != "refresh":
            raise SecurityError("Invalid token type for refresh operation")

        user_id = claims.get("sub")
        if not user_id:
            raise SecurityError("Invalid refresh token: missing user ID")

        # Note: In a real implementation, you would fetch user data
        # from the database to get current email and roles
        # For this example, we'll use placeholder values
        email = "user@example.com"  # Fetch from database
        roles = ["user"]  # Fetch from database

        # Generate new access token
        return self.generate_access_token(user_id, email, roles)

    def revoke_token(self, token: str) -> bool:
        """Revoke a JWT token.

        Args:
            token: JWT token to revoke

        Returns:
            True if token was revoked successfully, False otherwise
        """
        try:
            # Add token to revocation list
            self._revoked_tokens.add(token)
            logger.debug("Token revoked successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False

    def is_token_revoked(self, token: str) -> bool:
        """Check if a token is revoked.

        Args:
            token: JWT token to check

        Returns:
            True if token is revoked, False otherwise
        """
        return token in self._revoked_tokens

    def cleanup_revoked_tokens(self) -> int:
        """Clean up expired revoked tokens.

        Returns:
            Number of tokens cleaned up
        """
        # In a real implementation, you would check expiration times
        # and remove expired tokens from the revocation list
        initial_count = len(self._revoked_tokens)

        # For this example, we'll just clear all revoked tokens
        # In production, implement proper expiration checking
        self._revoked_tokens.clear()

        cleaned_count = initial_count - len(self._revoked_tokens)
        logger.info(f"Cleaned up {cleaned_count} revoked tokens")
        return cleaned_count


class SecurityService:
    """High-level security service combining password hashing and token management.

    Provides a unified interface for all security operations in the Identity module
    including authentication, authorization, and session management.
    """

    def __init__(
        self,
        password_hasher: PasswordHasherInterface,
        token_service: TokenServiceInterface,
        config: SecurityConfig,
    ) -> None:
        """Initialize security service with dependencies.

        Args:
            password_hasher: Password hashing implementation
            token_service: Token management implementation
            config: Security configuration
        """
        self._password_hasher = password_hasher
        self._token_service = token_service
        self._config = config

    # Password operations

    def hash_password(self, password: str) -> PasswordHash:
        """Hash a password securely.

        Args:
            password: Plaintext password to hash

        Returns:
            PasswordHash value object

        Raises:
            SecurityError: If password is invalid or hashing fails
        """
        return self._password_hasher.hash_password(password)

    def verify_password(self, password: str, password_hash: PasswordHash) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plaintext password to verify
            password_hash: PasswordHash to verify against

        Returns:
            True if password matches, False otherwise
        """
        return self._password_hasher.verify_password(password, password_hash)

    def needs_password_rehash(self, password_hash: PasswordHash) -> bool:
        """Check if a password hash needs to be updated.

        Args:
            password_hash: PasswordHash to check

        Returns:
            True if rehashing is recommended, False otherwise
        """
        return self._password_hasher.needs_rehash(password_hash)

    # Token operations

    def generate_tokens(
        self,
        user_id: str,
        email: str,
        roles: list[str],
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> dict[str, str]:
        """Generate both access and refresh tokens for a user.

        Args:
            user_id: User ID
            email: User email
            roles: List of user roles
            additional_claims: Optional additional JWT claims

        Returns:
            Dictionary containing access_token and refresh_token

        Raises:
            SecurityError: If token generation fails
        """
        access_token = self._token_service.generate_access_token(
            user_id, email, roles, additional_claims
        )
        refresh_token = self._token_service.generate_refresh_token(
            user_id, additional_claims
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    def validate_access_token(self, token: str) -> dict[str, Any]:
        """Validate an access token.

        Args:
            token: JWT access token to validate

        Returns:
            Decoded token claims

        Raises:
            SecurityError: If token is invalid, expired, or not an access token
        """
        claims = self._token_service.validate_token(token)

        if claims.get("type") != "access":
            raise SecurityError("Invalid token type: expected access token")

        return claims

    def refresh_tokens(self, refresh_token: str) -> dict[str, str]:
        """Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            Dictionary containing new access_token and refresh_token

        Raises:
            SecurityError: If refresh token is invalid or expired
        """
        # Generate new access token
        new_access_token = self._token_service.refresh_access_token(refresh_token)

        # Generate new refresh token (rotate refresh tokens for security)
        refresh_claims = self._token_service.validate_token(refresh_token)
        user_id = refresh_claims.get("sub")
        new_refresh_token = self._token_service.generate_refresh_token(user_id)

        # Revoke old refresh token
        self._token_service.revoke_token(refresh_token)

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        }

    def revoke_token(self, token: str) -> bool:
        """Revoke a token.

        Args:
            token: JWT token to revoke

        Returns:
            True if token was revoked successfully, False otherwise
        """
        return self._token_service.revoke_token(token)

    def logout_user(self, access_token: str, refresh_token: str) -> bool:
        """Logout a user by revoking their tokens.

        Args:
            access_token: User's access token
            refresh_token: User's refresh token

        Returns:
            True if logout was successful, False otherwise
        """
        access_revoked = self._token_service.revoke_token(access_token)
        refresh_revoked = self._token_service.revoke_token(refresh_token)

        return access_revoked and refresh_revoked

    # Security validation

    def validate_password_strength(self, password: str) -> dict[str, Any]:
        """Validate password strength against security requirements.

        Args:
            password: Password to validate

        Returns:
            Dictionary containing validation results
        """
        result = {
            "is_valid": True,
            "errors": [],
            "score": 0,
            "suggestions": [],
        }

        # Length check
        if len(password) < 8:
            result["is_valid"] = False
            result["errors"].append("Password must be at least 8 characters long")
        else:
            result["score"] += 1

        # Character variety checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        if not has_lower:
            result["suggestions"].append("Include lowercase letters")
        else:
            result["score"] += 1

        if not has_upper:
            result["suggestions"].append("Include uppercase letters")
        else:
            result["score"] += 1

        if not has_digit:
            result["suggestions"].append("Include numbers")
        else:
            result["score"] += 1

        if not has_special:
            result["suggestions"].append("Include special characters")
        else:
            result["score"] += 1

        # Common password checks (simplified)
        common_passwords = ["password", "123456", "qwerty", "admin"]
        if password.lower() in common_passwords:
            result["is_valid"] = False
            result["errors"].append("Password is too common")

        return result

    # Health check

    def health_check(self) -> dict[str, Any]:
        """Perform security service health check.

        Returns:
            Health check results
        """
        try:
            # Test password hashing
            test_password = "test_password_123"
            test_hash = self._password_hasher.hash_password(test_password)
            hash_verify = self._password_hasher.verify_password(
                test_password, test_hash
            )

            if not hash_verify:
                return {
                    "status": "unhealthy",
                    "error": "Password hashing verification failed",
                }

            # Test token generation and validation
            test_tokens = self.generate_tokens(
                "test_user", "test@example.com", ["test"]
            )
            test_claims = self.validate_access_token(test_tokens["access_token"])

            if test_claims.get("sub") != "test_user":
                return {"status": "unhealthy", "error": "Token validation failed"}

            return {
                "status": "healthy",
                "password_algorithm": self._config.password_hash_algorithm,
                "jwt_algorithm": self._config.jwt_algorithm,
            }

        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
