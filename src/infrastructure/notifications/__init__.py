"""Notification Infrastructure for Identity Module.

This package provides notification event processing, storage, and delivery
capabilities for notifying external systems and users about user lifecycle events.
"""

from .config import NotificationConfig
from .events import (
    NotificationEvent,
    UserCreatedNotification,
    UserDeletedNotification,
    UserModifiedNotification,
    UserPasswordChangedNotification,
    UserRoleAssignedNotification,
    UserRoleRemovedNotification,
    UserStatusChangedNotification,
)
from .handlers import (
    EmailNotificationHandler,
    NotificationHandler,
    SlackNotificationHandler,
    WebhookNotificationHandler,
)
from .processors import NotificationEventProcessor
from .service import NotificationService

__all__ = [
    "NotificationConfig",
    "NotificationEvent",
    "UserCreatedNotification",
    "UserDeletedNotification",
    "UserModifiedNotification",
    "UserPasswordChangedNotification",
    "UserRoleAssignedNotification",
    "UserRoleRemovedNotification",
    "UserStatusChangedNotification",
    "NotificationHandler",
    "EmailNotificationHandler",
    "SlackNotificationHandler",
    "WebhookNotificationHandler",
    "NotificationEventProcessor",
    "NotificationService",
]
