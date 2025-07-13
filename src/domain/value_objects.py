"""Domain Value Objects for Identity Module.

This module contains immutable value objects that encapsulate domain concepts
without identity. All value objects are validated upon creation and provide
rich behavior for domain operations.
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Optional
from uuid import UUID


@dataclass(frozen=True)
class Email:
    """Email value object with validation and normalization.

    Represents a valid email address with proper validation and normalization.
    Immutable once created.
    """

    value: str = field()

    # Email validation regex pattern
    _EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    def __post_init__(self) -> None:
        """Validate and normalize email upon creation."""
        if not self.value:
            raise ValueError("Email cannot be empty")

        normalized = self.value.strip().lower()
        if not self._EMAIL_PATTERN.match(normalized):
            raise ValueError(f"Invalid email format: {self.value}")

        # Use object.__setattr__ since the class is frozen
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        """Return string representation of the email."""
        return self.value

    @property
    def domain(self) -> str:
        """Extract the domain part of the email."""
        return self.value.split("@")[1]

    @property
    def local_part(self) -> str:
        """Extract the local part (username) of the email."""
        return self.value.split("@")[0]

    def is_same_domain(self, other: "Email") -> bool:
        """Check if this email has the same domain as another."""
        return self.domain == other.domain


@dataclass(frozen=True)
class PasswordHash:
    """Password hash value object with security validation.

    Represents a securely hashed password with metadata about the hashing
    algorithm and parameters used.
    """

    hash_value: str = field()
    algorithm: str = field(default="bcrypt")
    salt: Optional[str] = field(default=None)
    iterations: Optional[int] = field(default=None)

    def __post_init__(self) -> None:
        """Validate password hash upon creation."""
        if not self.hash_value:
            raise ValueError("Password hash cannot be empty")

        if len(self.hash_value) < 32:
            raise ValueError("Password hash appears to be too short")

        if self.algorithm not in ("bcrypt", "scrypt", "argon2", "pbkdf2"):
            raise ValueError(f"Unsupported hashing algorithm: {self.algorithm}")

    def __str__(self) -> str:
        """Return masked representation for security."""
        return (
            f"PasswordHash(algorithm={self.algorithm}, length={len(self.hash_value)})"
        )

    @property
    def is_bcrypt(self) -> bool:
        """Check if this is a bcrypt hash."""
        return self.algorithm == "bcrypt"

    @property
    def is_strong_algorithm(self) -> bool:
        """Check if using a strong hashing algorithm."""
        return self.algorithm in ("bcrypt", "scrypt", "argon2")

    @classmethod
    def from_plaintext(cls, password: str, algorithm: str = "bcrypt") -> "PasswordHash":
        """Create a password hash from plaintext (for testing purposes).

        Note: In production, password hashing should be done by a dedicated
        service with proper security measures.
        """
        if not password:
            raise ValueError("Password cannot be empty")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        # Simple hash for demonstration (use proper bcrypt in production)
        hash_value = hashlib.sha256(password.encode()).hexdigest()

        return cls(hash_value=hash_value, algorithm=algorithm)


@dataclass(frozen=True)
class AuditInfo:
    """Audit information value object.

    Captures who performed an action and when, providing a complete audit trail
    for domain operations.
    """

    created_by: UUID = field()
    created_at: datetime = field()
    modified_by: Optional[UUID] = field(default=None)
    modified_at: Optional[datetime] = field(default=None)

    def __post_init__(self) -> None:
        """Validate audit information upon creation."""
        if self.created_at > datetime.utcnow():
            raise ValueError("Creation time cannot be in the future")

        if self.modified_at and self.modified_at < self.created_at:
            raise ValueError("Modification time cannot be before creation time")

        if self.modified_at and not self.modified_by:
            raise ValueError("Modified by is required when modification time is set")

    def __str__(self) -> str:
        """Return string representation of audit info."""
        if self.modified_at:
            return f"Created by {self.created_by} at {self.created_at}, modified by {self.modified_by} at {self.modified_at}"
        return f"Created by {self.created_by} at {self.created_at}"

    @property
    def is_modified(self) -> bool:
        """Check if the entity has been modified."""
        return self.modified_at is not None

    @property
    def last_modified_by(self) -> UUID:
        """Get the user who last modified the entity."""
        return self.modified_by if self.modified_by else self.created_by

    @property
    def last_modified_at(self) -> datetime:
        """Get the last modification timestamp."""
        return self.modified_at if self.modified_at else self.created_at

    def with_modification(
        self, modified_by: UUID, modified_at: Optional[datetime] = None
    ) -> "AuditInfo":
        """Create a new AuditInfo with modification details."""
        modification_time = modified_at or datetime.utcnow()

        return AuditInfo(
            created_by=self.created_by,
            created_at=self.created_at,
            modified_by=modified_by,
            modified_at=modification_time,
        )


@dataclass(frozen=True)
class UserId:
    """User identifier value object.

    Strongly-typed identifier for User entities to prevent mixing with other IDs.
    """

    value: UUID = field()

    def __post_init__(self) -> None:
        """Validate user ID upon creation."""
        if not isinstance(self.value, UUID):
            raise ValueError("User ID must be a valid UUID")

    def __str__(self) -> str:
        """Return string representation of the user ID."""
        return str(self.value)

    @classmethod
    def generate(cls) -> "UserId":
        """Generate a new random user ID."""
        from uuid import uuid4

        return cls(value=uuid4())


@dataclass(frozen=True)
class RoleId:
    """Role identifier value object.

    Strongly-typed identifier for Role entities to prevent mixing with other IDs.
    """

    value: UUID = field()

    def __post_init__(self) -> None:
        """Validate role ID upon creation."""
        if not isinstance(self.value, UUID):
            raise ValueError("Role ID must be a valid UUID")

    def __str__(self) -> str:
        """Return string representation of the role ID."""
        return str(self.value)

    @classmethod
    def generate(cls) -> "RoleId":
        """Generate a new random role ID."""
        from uuid import uuid4

        return cls(value=uuid4())


@dataclass(frozen=True)
class PermissionId:
    """Permission identifier value object.

    Strongly-typed identifier for Permission entities to prevent mixing with other IDs.
    """

    value: UUID = field()

    def __post_init__(self) -> None:
        """Validate permission ID upon creation."""
        if not isinstance(self.value, UUID):
            raise ValueError("Permission ID must be a valid UUID")

    def __str__(self) -> str:
        """Return string representation of the permission ID."""
        return str(self.value)

    @classmethod
    def generate(cls) -> "PermissionId":
        """Generate a new random permission ID."""
        from uuid import uuid4

        return cls(value=uuid4())
