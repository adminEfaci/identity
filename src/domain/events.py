"""Domain Events for Identity Module.

This module contains domain events that represent significant business events
within the Identity domain. Events follow the DDD pattern and can be used
for event sourcing, integration with other bounded contexts, and audit trails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from .value_objects import Email, RoleId, UserId

from .enums import UserStatus


@dataclass(frozen=True)
class UserCreated:
    """Event raised when a new user is created.

    Contains all relevant information about the user creation including
    initial status, email, and audit information.
    """

    event_id: UUID = field()
    aggregate_id: UUID = field()
    occurred_at: datetime = field()
    user_id: UserId = field()
    email: Email = field()
    status: UserStatus = field()
    created_by: UUID = field()
    event_version: int = field(default=1)
    correlation_id: UUID | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    initial_roles: frozenset[RoleId] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate user created event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if self.event_version < 1:
            raise ValueError("Event version must be positive")

        # Ensure aggregate_id matches user_id
        if self.aggregate_id != self.user_id.value:
            raise ValueError("Aggregate ID must match User ID")

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id),
            "occurred_at": self.occurred_at.isoformat(),
            "event_version": self.event_version,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "user_id": str(self.user_id),
            "email": str(self.email),
            "status": str(self.status),
            "created_by": str(self.created_by),
            "initial_roles": [str(role_id) for role_id in self.initial_roles],
        }


@dataclass(frozen=True)
class UserModified:
    """Event raised when a user is modified.

    Contains information about what changed and who made the change.
    Supports partial updates by only including changed fields.
    """

    event_id: UUID = field()
    aggregate_id: UUID = field()
    occurred_at: datetime = field()
    user_id: UserId = field()
    modified_by: UUID = field()
    changes: dict[str, Any] = field()
    event_version: int = field(default=1)
    correlation_id: UUID | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    previous_values: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate user modified event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if self.event_version < 1:
            raise ValueError("Event version must be positive")

        # Ensure aggregate_id matches user_id
        if self.aggregate_id != self.user_id.value:
            raise ValueError("Aggregate ID must match User ID")

        if not self.changes:
            raise ValueError("Changes cannot be empty")

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    @property
    def changed_fields(self) -> frozenset[str]:
        """Get the set of fields that were changed."""
        return frozenset(self.changes.keys())

    def has_field_changed(self, field_name: str) -> bool:
        """Check if a specific field was changed."""
        return field_name in self.changes

    def get_previous_value(self, field_name: str) -> Any:
        """Get the previous value of a field."""
        return self.previous_values.get(field_name)

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id),
            "occurred_at": self.occurred_at.isoformat(),
            "event_version": self.event_version,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "user_id": str(self.user_id),
            "modified_by": str(self.modified_by),
            "changes": self.changes,
            "previous_values": self.previous_values,
        }


@dataclass(frozen=True)
class UserDeleted:
    """Event raised when a user is deleted.

    Contains information about the deleted user and who performed the deletion.
    May include soft delete information.
    """

    event_id: UUID = field()
    aggregate_id: UUID = field()
    occurred_at: datetime = field()
    user_id: UserId = field()
    deleted_by: UUID = field()
    email: Email = field()
    event_version: int = field(default=1)
    correlation_id: UUID | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    soft_delete: bool = field(default=True)
    deletion_reason: str | None = field(default=None)

    def __post_init__(self) -> None:
        """Validate user deleted event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if self.event_version < 1:
            raise ValueError("Event version must be positive")

        # Ensure aggregate_id matches user_id
        if self.aggregate_id != self.user_id.value:
            raise ValueError("Aggregate ID must match User ID")

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id),
            "occurred_at": self.occurred_at.isoformat(),
            "event_version": self.event_version,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "user_id": str(self.user_id),
            "deleted_by": str(self.deleted_by),
            "email": str(self.email),
            "soft_delete": self.soft_delete,
            "deletion_reason": self.deletion_reason,
        }


@dataclass(frozen=True)
class UserRoleAssigned:
    """Event raised when a role is assigned to a user.

    Contains information about the role assignment including who performed
    the assignment and any relevant context.
    """

    event_id: UUID = field()
    aggregate_id: UUID = field()
    occurred_at: datetime = field()
    user_id: UserId = field()
    role_id: RoleId = field()
    assigned_by: UUID = field()
    event_version: int = field(default=1)
    correlation_id: UUID | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    assignment_context: str | None = field(default=None)

    def __post_init__(self) -> None:
        """Validate user role assigned event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if self.event_version < 1:
            raise ValueError("Event version must be positive")

        # Ensure aggregate_id matches user_id
        if self.aggregate_id != self.user_id.value:
            raise ValueError("Aggregate ID must match User ID")

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id),
            "occurred_at": self.occurred_at.isoformat(),
            "event_version": self.event_version,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "user_id": str(self.user_id),
            "role_id": str(self.role_id),
            "assigned_by": str(self.assigned_by),
            "assignment_context": self.assignment_context,
        }


@dataclass(frozen=True)
class UserRoleRemoved:
    """Event raised when a role is removed from a user.

    Contains information about the role removal including who performed
    the removal and any relevant context.
    """

    event_id: UUID = field()
    aggregate_id: UUID = field()
    occurred_at: datetime = field()
    user_id: UserId = field()
    role_id: RoleId = field()
    removed_by: UUID = field()
    event_version: int = field(default=1)
    correlation_id: UUID | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    removal_reason: str | None = field(default=None)

    def __post_init__(self) -> None:
        """Validate user role removed event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if self.event_version < 1:
            raise ValueError("Event version must be positive")

        # Ensure aggregate_id matches user_id
        if self.aggregate_id != self.user_id.value:
            raise ValueError("Aggregate ID must match User ID")

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id),
            "occurred_at": self.occurred_at.isoformat(),
            "event_version": self.event_version,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "user_id": str(self.user_id),
            "role_id": str(self.role_id),
            "removed_by": str(self.removed_by),
            "removal_reason": self.removal_reason,
        }


@dataclass(frozen=True)
class UserPasswordChanged:
    """Event raised when a user's password is changed.

    Contains security-relevant information about the password change
    without exposing sensitive data.
    """

    event_id: UUID = field()
    aggregate_id: UUID = field()
    occurred_at: datetime = field()
    user_id: UserId = field()
    changed_by: UUID = field()
    is_self_change: bool = field()
    event_version: int = field(default=1)
    correlation_id: UUID | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    password_strength_score: int | None = field(default=None)

    def __post_init__(self) -> None:
        """Validate user password changed event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if self.event_version < 1:
            raise ValueError("Event version must be positive")

        # Ensure aggregate_id matches user_id
        if self.aggregate_id != self.user_id.value:
            raise ValueError("Aggregate ID must match User ID")

        if self.password_strength_score is not None and not (
            0 <= self.password_strength_score <= 100
        ):
            raise ValueError("Password strength score must be between 0 and 100")

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id),
            "occurred_at": self.occurred_at.isoformat(),
            "event_version": self.event_version,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "user_id": str(self.user_id),
            "changed_by": str(self.changed_by),
            "is_self_change": self.is_self_change,
            "password_strength_score": self.password_strength_score,
        }


@dataclass(frozen=True)
class UserStatusChanged:
    """Event raised when a user's status changes.

    Contains information about the status change including previous and
    new status values.
    """

    event_id: UUID = field()
    aggregate_id: UUID = field()
    occurred_at: datetime = field()
    user_id: UserId = field()
    previous_status: UserStatus = field()
    new_status: UserStatus = field()
    changed_by: UUID = field()
    event_version: int = field(default=1)
    correlation_id: UUID | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    reason: str | None = field(default=None)

    def __post_init__(self) -> None:
        """Validate user status changed event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if self.event_version < 1:
            raise ValueError("Event version must be positive")

        # Ensure aggregate_id matches user_id
        if self.aggregate_id != self.user_id.value:
            raise ValueError("Aggregate ID must match User ID")

        if self.previous_status == self.new_status:
            raise ValueError("Previous and new status cannot be the same")

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    @property
    def is_activation(self) -> bool:
        """Check if this is a user activation."""
        return (
            self.previous_status != UserStatus.ACTIVE
            and self.new_status == UserStatus.ACTIVE
        )

    @property
    def is_deactivation(self) -> bool:
        """Check if this is a user deactivation."""
        return (
            self.previous_status == UserStatus.ACTIVE
            and self.new_status != UserStatus.ACTIVE
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id),
            "occurred_at": self.occurred_at.isoformat(),
            "event_version": self.event_version,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "user_id": str(self.user_id),
            "previous_status": str(self.previous_status),
            "new_status": str(self.new_status),
            "changed_by": str(self.changed_by),
            "reason": self.reason,
        }


# Type alias for all domain events
DomainEvent = (
    UserCreated
    | UserModified
    | UserDeleted
    | UserRoleAssigned
    | UserRoleRemoved
    | UserPasswordChanged
    | UserStatusChanged
)
