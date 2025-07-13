"""Identity Domain Package.

Contains all domain-specific components following DDD principles.
"""

# Entities
from .entities import Permission, Role, User

# Enums
from .enums import AuditAction, PermissionScope, RoleType, UserStatus

# Events
from .events import (
    DomainEvent,
    UserCreated,
    UserDeleted,
    UserModified,
    UserPasswordChanged,
    UserRoleAssigned,
    UserRoleRemoved,
    UserStatusChanged,
)

# Exceptions
from .exceptions import (
    BusinessRuleViolationError,
    ConcurrencyError,
    DomainError,
    InactiveUserError,
    InsufficientPermissionsError,
    InvalidEmailError,
    PermissionAlreadyExistsError,
    PermissionDomainError,
    PermissionNotFoundError,
    RoleAlreadyExistsError,
    RoleAssignmentError,
    RoleDomainError,
    RoleNotFoundError,
    SystemRoleModificationError,
    UserAlreadyExistsError,
    UserDomainError,
    UserNotFoundError,
    UserStatusError,
    ValidationError,
    WeakPasswordError,
)

# Repositories
from .repositories import (
    DuplicateEntityError,
    EntityNotFoundError,
    PermissionRepository,
    RepositoryError,
    RoleRepository,
    UserRepository,
)

# Services
from .services import (
    AuthorizationService,
    PermissionDomainService,
    RoleDomainService,
    UserDomainService,
)

# Value Objects
from .value_objects import AuditInfo, Email, PasswordHash, PermissionId, RoleId, UserId

__all__ = [
    # Entities
    "User",
    "Role",
    "Permission",
    # Value Objects
    "Email",
    "PasswordHash",
    "AuditInfo",
    "UserId",
    "RoleId",
    "PermissionId",
    # Enums
    "UserStatus",
    "AuditAction",
    "PermissionScope",
    "RoleType",
    # Events
    "DomainEvent",
    "UserCreated",
    "UserModified",
    "UserDeleted",
    "UserRoleAssigned",
    "UserRoleRemoved",
    "UserPasswordChanged",
    "UserStatusChanged",
    # Repositories
    "UserRepository",
    "RoleRepository",
    "PermissionRepository",
    "RepositoryError",
    "DuplicateEntityError",
    "EntityNotFoundError",
    # Services
    "UserDomainService",
    "RoleDomainService",
    "PermissionDomainService",
    "AuthorizationService",
    # Exceptions
    "DomainError",
    "ValidationError",
    "BusinessRuleViolationError",
    "UserDomainError",
    "InvalidEmailError",
    "WeakPasswordError",
    "UserAlreadyExistsError",
    "UserNotFoundError",
    "UserStatusError",
    "InactiveUserError",
    "RoleDomainError",
    "RoleNotFoundError",
    "RoleAlreadyExistsError",
    "SystemRoleModificationError",
    "RoleAssignmentError",
    "PermissionDomainError",
    "PermissionNotFoundError",
    "PermissionAlreadyExistsError",
    "InsufficientPermissionsError",
    "ConcurrencyError",
]
