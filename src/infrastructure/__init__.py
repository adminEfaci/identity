"""Infrastructure Layer for Identity Module.

This module provides concrete implementations of domain repository interfaces
and infrastructure services including database access, caching, messaging,
and security features.

The infrastructure layer follows the Dependency Inversion Principle by
implementing domain interfaces without the domain layer depending on
infrastructure details.
"""

from .cache import CacheService, RedisCache
from .database import DatabaseManager, SessionManager
from .messaging import CeleryMessageBus, MessageBus
from .repositories import (
    SqlAlchemyPermissionRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemyUserRepository,
)
from .security import (
    Argon2PasswordHasher,
    JWTTokenService,
    SecurityService,
)

__all__ = [
    # Cache
    "RedisCache",
    "CacheService",
    # Database
    "DatabaseManager",
    "SessionManager",
    # Messaging
    "MessageBus",
    "CeleryMessageBus",
    # Repositories
    "SqlAlchemyUserRepository",
    "SqlAlchemyRoleRepository",
    "SqlAlchemyPermissionRepository",
    # Security
    "Argon2PasswordHasher",
    "JWTTokenService",
    "SecurityService",
]
