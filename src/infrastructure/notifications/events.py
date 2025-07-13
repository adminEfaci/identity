"""Notification Events for Identity Module.

This module defines notification events that are sent to external systems
and users to inform them about important user lifecycle events.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from ...domain.enums import UserStatus
from ...domain.value_objects import Email, UserId


class NotificationPriority(Enum):
    """Priority levels for notifications."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class NotificationChannel(Enum):
    """Available notification channels."""

    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    PUSH = "push"


@dataclass(frozen=True)
class NotificationEvent(ABC):
    """Base class for all notification events.

    Provides common fields and methods for notification events
    that are sent to external systems and users.
    """

    notification_id: UUID = field(default_factory=uuid4)
    event_id: UUID = field()
    user_id: UserId = field()
    occurred_at: datetime = field()
    priority: NotificationPriority = field(default=NotificationPriority.NORMAL)
    channels: frozenset[NotificationChannel] = field(
        default_factory=lambda: frozenset([NotificationChannel.EMAIL])
    )
    correlation_id: Optional[UUID] = field(default=None)
    locale: str = field(default="en")
    template_name: Optional[str] = field(default=None)

    def __post_init__(self) -> None:
        """Validate notification event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Event occurrence time cannot be in the future")

        if not self.channels:
            raise ValueError("At least one notification channel must be specified")

    @property
    @abstractmethod
    def event_type(self) -> str:
        """Get the notification event type name."""
        pass

    @abstractmethod
    def get_subject(self) -> str:
        """Get the notification subject/title."""
        pass

    @abstractmethod
    def get_message(self) -> str:
        """Get the notification message content."""
        pass

    @abstractmethod
    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        pass

    def to_dict(self) -> dict[str, Any]:
        """Convert notification event to dictionary representation."""
        return {
            "notification_id": str(self.notification_id),
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "user_id": str(self.user_id),
            "occurred_at": self.occurred_at.isoformat(),
            "priority": self.priority.value,
            "channels": [channel.value for channel in self.channels],
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "locale": self.locale,
            "template_name": self.template_name,
            "subject": self.get_subject(),
            "message": self.get_message(),
            "template_data": self.get_template_data(),
        }


@dataclass(frozen=True)
class UserCreatedNotification(NotificationEvent):
    """Notification sent when a new user is created."""

    email: Email = field()
    first_name: str = field()
    last_name: str = field()
    username: str = field()
    welcome_message: Optional[str] = field(default=None)
    activation_required: bool = field(default=False)
    activation_link: Optional[str] = field(default=None)

    @property
    def event_type(self) -> str:
        """Get the notification event type name."""
        return "UserCreatedNotification"

    def get_subject(self) -> str:
        """Get the notification subject/title."""
        return f"Welcome to our platform, {self.first_name}!"

    def get_message(self) -> str:
        """Get the notification message content."""
        base_message = (
            f"Hello {self.first_name} {self.last_name},\n\n"
            f"Welcome! Your account has been successfully created with username: {self.username}\n\n"
        )

        if self.activation_required and self.activation_link:
            base_message += (
                f"Please activate your account by clicking the following link:\n"
                f"{self.activation_link}\n\n"
            )

        if self.welcome_message:
            base_message += f"{self.welcome_message}\n\n"

        base_message += "Thank you for joining us!"

        return base_message

    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        return {
            "user_id": str(self.user_id),
            "email": str(self.email),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "username": self.username,
            "welcome_message": self.welcome_message,
            "activation_required": self.activation_required,
            "activation_link": self.activation_link,
            "full_name": f"{self.first_name} {self.last_name}",
        }


@dataclass(frozen=True)
class UserModifiedNotification(NotificationEvent):
    """Notification sent when a user's information is modified."""

    email: Email = field()
    first_name: str = field()
    last_name: str = field()
    changes: dict[str, Any] = field()
    modified_by: str = field()
    requires_verification: bool = field(default=False)
    verification_link: Optional[str] = field(default=None)

    @property
    def event_type(self) -> str:
        """Get the notification event type name."""
        return "UserModifiedNotification"

    def get_subject(self) -> str:
        """Get the notification subject/title."""
        return "Your account information has been updated"

    def get_message(self) -> str:
        """Get the notification message content."""
        changes_text = ", ".join(self.changes.keys())
        message = (
            f"Hello {self.first_name} {self.last_name},\n\n"
            f"Your account information has been updated. "
            f"The following fields were changed: {changes_text}\n\n"
            f"Modified by: {self.modified_by}\n\n"
        )

        if self.requires_verification and self.verification_link:
            message += (
                f"Please verify these changes by clicking the following link:\n"
                f"{self.verification_link}\n\n"
            )

        message += "If you did not make these changes, please contact support immediately."

        return message

    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        return {
            "user_id": str(self.user_id),
            "email": str(self.email),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "changes": self.changes,
            "modified_by": self.modified_by,
            "requires_verification": self.requires_verification,
            "verification_link": self.verification_link,
            "full_name": f"{self.first_name} {self.last_name}",
            "changes_summary": ", ".join(self.changes.keys()),
        }


@dataclass(frozen=True)
class UserDeletedNotification(NotificationEvent):
    """Notification sent when a user account is deleted."""

    email: Email = field()
    first_name: str = field()
    last_name: str = field()
    deleted_by: str = field()
    deletion_reason: Optional[str] = field(default=None)
    soft_delete: bool = field(default=True)
    data_retention_days: Optional[int] = field(default=None)

    @property
    def event_type(self) -> str:
        """Get the notification event type name."""
        return "UserDeletedNotification"

    def get_subject(self) -> str:
        """Get the notification subject/title."""
        return "Your account has been deleted"

    def get_message(self) -> str:
        """Get the notification message content."""
        message = (
            f"Hello {self.first_name} {self.last_name},\n\n"
            f"Your account has been {'deactivated' if self.soft_delete else 'permanently deleted'}.\n\n"
            f"Deleted by: {self.deleted_by}\n\n"
        )

        if self.deletion_reason:
            message += f"Reason: {self.deletion_reason}\n\n"

        if self.soft_delete and self.data_retention_days:
            message += (
                f"Your data will be retained for {self.data_retention_days} days. "
                f"During this time, you may contact support to restore your account.\n\n"
            )

        message += "Thank you for using our service."

        return message

    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        return {
            "user_id": str(self.user_id),
            "email": str(self.email),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "deleted_by": self.deleted_by,
            "deletion_reason": self.deletion_reason,
            "soft_delete": self.soft_delete,
            "data_retention_days": self.data_retention_days,
            "full_name": f"{self.first_name} {self.last_name}",
        }


@dataclass(frozen=True)
class UserPasswordChangedNotification(NotificationEvent):
    """Notification sent when a user's password is changed."""

    email: Email = field()
    first_name: str = field()
    last_name: str = field()
    changed_by: str = field()
    is_self_change: bool = field()
    ip_address: Optional[str] = field(default=None)
    user_agent: Optional[str] = field(default=None)

    @property
    def event_type(self) -> str:
        """Get the notification event type name."""
        return "UserPasswordChangedNotification"

    def get_subject(self) -> str:
        """Get the notification subject/title."""
        return "Your password has been changed"

    def get_message(self) -> str:
        """Get the notification message content."""
        message = (
            f"Hello {self.first_name} {self.last_name},\n\n"
            f"Your password has been successfully changed.\n\n"
            f"Changed by: {self.changed_by}\n"
            f"Self-initiated: {'Yes' if self.is_self_change else 'No'}\n"
        )

        if self.ip_address:
            message += f"IP Address: {self.ip_address}\n"

        if self.user_agent:
            message += f"Browser/Device: {self.user_agent}\n"

        message += (
            "\nIf you did not make this change, please contact support immediately "
            "and consider updating your security settings."
        )

        return message

    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        return {
            "user_id": str(self.user_id),
            "email": str(self.email),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "changed_by": self.changed_by,
            "is_self_change": self.is_self_change,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "full_name": f"{self.first_name} {self.last_name}",
        }


@dataclass(frozen=True)
class UserRoleAssignedNotification(NotificationEvent):
    """Notification sent when a role is assigned to a user."""

    email: Email = field()
    first_name: str = field()
    last_name: str = field()
    role_name: str = field()
    assigned_by: str = field()
    permissions_summary: Optional[str] = field(default=None)

    @property
    def event_type(self) -> str:
        """Get the notification event type name."""
        return "UserRoleAssignedNotification"

    def get_subject(self) -> str:
        """Get the notification subject/title."""
        return f"New role assigned: {self.role_name}"

    def get_message(self) -> str:
        """Get the notification message content."""
        message = (
            f"Hello {self.first_name} {self.last_name},\n\n"
            f"You have been assigned the role: {self.role_name}\n\n"
            f"Assigned by: {self.assigned_by}\n\n"
        )

        if self.permissions_summary:
            message += f"This role grants you the following permissions:\n{self.permissions_summary}\n\n"

        message += "Please review your new permissions and contact support if you have any questions."

        return message

    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        return {
            "user_id": str(self.user_id),
            "email": str(self.email),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role_name": self.role_name,
            "assigned_by": self.assigned_by,
            "permissions_summary": self.permissions_summary,
            "full_name": f"{self.first_name} {self.last_name}",
        }


@dataclass(frozen=True)
class UserRoleRemovedNotification(NotificationEvent):
    """Notification sent when a role is removed from a user."""

    email: Email = field()
    first_name: str = field()
    last_name: str = field()
    role_name: str = field()
    removed_by: str = field()
    removal_reason: Optional[str] = field(default=None)

    @property
    def event_type(self) -> str:
        """Get the notification event type name."""
        return "UserRoleRemovedNotification"

    def get_subject(self) -> str:
        """Get the notification subject/title."""
        return f"Role removed: {self.role_name}"

    def get_message(self) -> str:
        """Get the notification message content."""
        message = (
            f"Hello {self.first_name} {self.last_name},\n\n"
            f"The role '{self.role_name}' has been removed from your account.\n\n"
            f"Removed by: {self.removed_by}\n\n"
        )

        if self.removal_reason:
            message += f"Reason: {self.removal_reason}\n\n"

        message += "Your account permissions have been updated accordingly. Contact support if you have any questions."

        return message

    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        return {
            "user_id": str(self.user_id),
            "email": str(self.email),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role_name": self.role_name,
            "removed_by": self.removed_by,
            "removal_reason": self.removal_reason,
            "full_name": f"{self.first_name} {self.last_name}",
        }


@dataclass(frozen=True)
class UserStatusChangedNotification(NotificationEvent):
    """Notification sent when a user's status changes."""

    email: Email = field()
    first_name: str = field()
    last_name: str = field()
    previous_status: UserStatus = field()
    new_status: UserStatus = field()
    changed_by: str = field()
    reason: Optional[str] = field(default=None)

    @property
    def event_type(self) -> str:
        """Get the notification event type name."""
        return "UserStatusChangedNotification"

    def get_subject(self) -> str:
        """Get the notification subject/title."""
        return f"Account status changed to {self.new_status.value}"

    def get_message(self) -> str:
        """Get the notification message content."""
        message = (
            f"Hello {self.first_name} {self.last_name},\n\n"
            f"Your account status has been changed from {self.previous_status.value} to {self.new_status.value}.\n\n"
            f"Changed by: {self.changed_by}\n\n"
        )

        if self.reason:
            message += f"Reason: {self.reason}\n\n"

        if self.new_status == UserStatus.ACTIVE:
            message += "Your account is now active and you can use all features."
        elif self.new_status == UserStatus.INACTIVE:
            message += "Your account has been deactivated. Contact support for assistance."
        elif self.new_status == UserStatus.SUSPENDED:
            message += "Your account has been suspended. Please contact support."

        return message

    def get_template_data(self) -> dict[str, Any]:
        """Get data for template rendering."""
        return {
            "user_id": str(self.user_id),
            "email": str(self.email),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "previous_status": self.previous_status.value,
            "new_status": self.new_status.value,
            "changed_by": self.changed_by,
            "reason": self.reason,
            "full_name": f"{self.first_name} {self.last_name}",
        }
