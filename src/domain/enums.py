"""Domain Enums for Identity Module.

This module contains all enumeration types used throughout the Identity domain.
"""

from enum import Enum
from typing import Final


class UserStatus(Enum):
    """User account status enumeration.

    Defines the possible states of a user account within the system.
    """

    ACTIVE: Final[str] = "active"
    INACTIVE: Final[str] = "inactive"
    SUSPENDED: Final[str] = "suspended"
    PENDING_VERIFICATION: Final[str] = "pending_verification"
    LOCKED: Final[str] = "locked"
    DELETED: Final[str] = "deleted"

    def __str__(self) -> str:
        """Return string representation of the status."""
        return self.value

    @property
    def is_active(self) -> bool:
        """Check if the status represents an active user."""
        return self == UserStatus.ACTIVE

    @property
    def can_login(self) -> bool:
        """Check if user with this status can login."""
        return self in (UserStatus.ACTIVE,)

    @property
    def requires_verification(self) -> bool:
        """Check if the status requires email verification."""
        return self == UserStatus.PENDING_VERIFICATION


class AuditAction(Enum):
    """Audit action enumeration.

    Defines the types of actions that can be audited in the system.
    """

    CREATE: Final[str] = "create"
    UPDATE: Final[str] = "update"
    DELETE: Final[str] = "delete"
    LOGIN: Final[str] = "login"
    LOGOUT: Final[str] = "logout"
    PASSWORD_CHANGE: Final[str] = "password_change"
    ROLE_ASSIGNED: Final[str] = "role_assigned"
    ROLE_REMOVED: Final[str] = "role_removed"
    PERMISSION_GRANTED: Final[str] = "permission_granted"
    PERMISSION_REVOKED: Final[str] = "permission_revoked"
    ACCOUNT_LOCKED: Final[str] = "account_locked"
    ACCOUNT_UNLOCKED: Final[str] = "account_unlocked"

    def __str__(self) -> str:
        """Return string representation of the action."""
        return self.value

    @property
    def is_security_action(self) -> bool:
        """Check if the action is security-related."""
        return self in (
            AuditAction.LOGIN,
            AuditAction.LOGOUT,
            AuditAction.PASSWORD_CHANGE,
            AuditAction.ACCOUNT_LOCKED,
            AuditAction.ACCOUNT_UNLOCKED,
        )

    @property
    def is_permission_action(self) -> bool:
        """Check if the action is permission-related."""
        return self in (
            AuditAction.ROLE_ASSIGNED,
            AuditAction.ROLE_REMOVED,
            AuditAction.PERMISSION_GRANTED,
            AuditAction.PERMISSION_REVOKED,
        )


class PermissionScope(Enum):
    """Permission scope enumeration.

    Defines the scope levels for permissions within the system.
    """

    GLOBAL: Final[str] = "global"
    ORGANIZATION: Final[str] = "organization"
    PROJECT: Final[str] = "project"
    RESOURCE: Final[str] = "resource"

    def __str__(self) -> str:
        """Return string representation of the scope."""
        return self.value

    @property
    def hierarchy_level(self) -> int:
        """Return the hierarchy level of the scope (lower = broader)."""
        hierarchy = {
            PermissionScope.GLOBAL: 0,
            PermissionScope.ORGANIZATION: 1,
            PermissionScope.PROJECT: 2,
            PermissionScope.RESOURCE: 3,
        }
        return hierarchy[self]

    def can_inherit_from(self, other: "PermissionScope") -> bool:
        """Check if this scope can inherit permissions from another scope."""
        return other.hierarchy_level <= self.hierarchy_level


class RoleType(Enum):
    """Role type enumeration.

    Defines the different types of roles in the system.
    """

    SYSTEM: Final[str] = "system"
    CUSTOM: Final[str] = "custom"
    INHERITED: Final[str] = "inherited"

    def __str__(self) -> str:
        """Return string representation of the role type."""
        return self.value

    @property
    def is_modifiable(self) -> bool:
        """Check if roles of this type can be modified."""
        return self != RoleType.SYSTEM

    @property
    def can_be_deleted(self) -> bool:
        """Check if roles of this type can be deleted."""
        return self == RoleType.CUSTOM
