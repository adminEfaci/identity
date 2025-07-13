"""Notification Service for Identity Module.

This module provides a high-level service for managing notifications,
including creating notification events from domain events and orchestrating
their delivery through the notification system.
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from ...domain.events import (
    DomainEvent,
    UserCreated,
    UserDeleted,
    UserModified,
    UserPasswordChanged,
    UserRoleAssigned,
    UserRoleRemoved,
    UserStatusChanged,
)
from ...domain.value_objects import Email, UserId
from .config import NotificationConfig
from .events import (
    NotificationChannel,
    NotificationEvent,
    NotificationPriority,
    UserCreatedNotification,
    UserDeletedNotification,
    UserModifiedNotification,
    UserPasswordChangedNotification,
    UserRoleAssignedNotification,
    UserRoleRemovedNotification,
    UserStatusChangedNotification,
)
from .processors import NotificationEventProcessor

logger = logging.getLogger(__name__)


class NotificationService:
    """High-level service for managing user notifications.

    Provides methods for creating notification events from domain events
    and orchestrating their delivery through the notification system.
    """

    def __init__(
        self,
        config: NotificationConfig,
        processor: Optional[NotificationEventProcessor] = None,
    ) -> None:
        """Initialize notification service.

        Args:
            config: Notification configuration
            processor: Optional notification event processor (will create if not provided)
        """
        self.config = config
        self.processor = processor or NotificationEventProcessor(config)

    async def handle_domain_event(self, domain_event: DomainEvent) -> bool:
        """Handle a domain event by creating and sending appropriate notifications.

        Args:
            domain_event: Domain event to handle

        Returns:
            True if notifications were created and sent successfully
        """
        if not self.config.enabled:
            logger.debug("Notifications disabled, skipping domain event handling")
            return False

        try:
            notification_events = await self._create_notifications_from_domain_event(
                domain_event
            )

            if not notification_events:
                logger.debug(
                    f"No notifications created for domain event {domain_event.event_type}"
                )
                return True

            # Process all notification events
            results = []
            for notification in notification_events:
                success = await self.processor.process_notification(notification)
                results.append(success)

            success_count = sum(results)
            logger.info(
                f"Processed {success_count}/{len(notification_events)} notifications "
                f"for domain event {domain_event.event_type}"
            )

            return success_count > 0

        except Exception as e:
            logger.error(f"Error handling domain event {domain_event.event_type}: {e}")
            return False

    async def _create_notifications_from_domain_event(
        self, domain_event: DomainEvent
    ) -> list[NotificationEvent]:
        """Create notification events from a domain event.

        Args:
            domain_event: Domain event to convert

        Returns:
            List of notification events to send
        """
        notifications = []

        if isinstance(domain_event, UserCreated):
            notifications.extend(await self._create_user_created_notifications(domain_event))
        elif isinstance(domain_event, UserModified):
            notifications.extend(await self._create_user_modified_notifications(domain_event))
        elif isinstance(domain_event, UserDeleted):
            notifications.extend(await self._create_user_deleted_notifications(domain_event))
        elif isinstance(domain_event, UserPasswordChanged):
            notifications.extend(await self._create_user_password_changed_notifications(domain_event))
        elif isinstance(domain_event, UserRoleAssigned):
            notifications.extend(await self._create_user_role_assigned_notifications(domain_event))
        elif isinstance(domain_event, UserRoleRemoved):
            notifications.extend(await self._create_user_role_removed_notifications(domain_event))
        elif isinstance(domain_event, UserStatusChanged):
            notifications.extend(await self._create_user_status_changed_notifications(domain_event))
        else:
            logger.debug(f"No notification mapping for domain event {domain_event.event_type}")

        return notifications

    async def _create_user_created_notifications(
        self, domain_event: UserCreated
    ) -> list[NotificationEvent]:
        """Create notifications for user creation event.

        Args:
            domain_event: UserCreated domain event

        Returns:
            List of notification events
        """
        # In a real implementation, we'd fetch user details from repository
        # For now, we'll create a basic notification with available data

        notifications = []

        # User welcome notification
        user_notification = UserCreatedNotification(
            event_id=domain_event.event_id,
            user_id=domain_event.user_id,
            occurred_at=domain_event.occurred_at,
            email=domain_event.email,
            first_name="User",  # Would fetch from user repository
            last_name="",
            username="user",  # Would fetch from user repository
            priority=NotificationPriority.NORMAL,
            channels=frozenset([NotificationChannel.EMAIL]),
            correlation_id=domain_event.correlation_id,
            welcome_message="Welcome to our platform! We're excited to have you join us.",
            activation_required=False,
        )
        notifications.append(user_notification)

        # Admin notification if enabled
        if self.config.admin_notification_enabled and self.config.admin_email_addresses:
            for admin_email in self.config.admin_email_addresses:
                admin_notification = UserCreatedNotification(
                    event_id=domain_event.event_id,
                    user_id=domain_event.user_id,
                    occurred_at=domain_event.occurred_at,
                    email=Email(admin_email),
                    first_name="Admin",
                    last_name="",
                    username="admin",
                    priority=NotificationPriority.LOW,
                    channels=frozenset([NotificationChannel.EMAIL, NotificationChannel.SLACK]),
                    correlation_id=domain_event.correlation_id,
                    welcome_message=f"New user created: {domain_event.email}",
                )
                notifications.append(admin_notification)

        return notifications

    async def _create_user_modified_notifications(
        self, domain_event: UserModified
    ) -> list[NotificationEvent]:
        """Create notifications for user modification event.

        Args:
            domain_event: UserModified domain event

        Returns:
            List of notification events
        """
        notifications = []

        # Check if notification-worthy changes were made
        significant_changes = {"email", "username", "status"}
        if not any(change in domain_event.changes for change in significant_changes):
            logger.debug("No significant changes detected, skipping user modification notification")
            return notifications

        # User notification about changes
        user_notification = UserModifiedNotification(
            event_id=domain_event.event_id,
            user_id=domain_event.user_id,
            occurred_at=domain_event.occurred_at,
            email=Email("user@example.com"),  # Would fetch from user repository
            first_name="User",  # Would fetch from user repository
            last_name="",
            changes=domain_event.changes,
            modified_by=str(domain_event.modified_by),
            priority=NotificationPriority.HIGH if "email" in domain_event.changes else NotificationPriority.NORMAL,
            channels=frozenset([NotificationChannel.EMAIL]),
            correlation_id=domain_event.correlation_id,
            requires_verification="email" in domain_event.changes,
        )
        notifications.append(user_notification)

        return notifications

    async def _create_user_deleted_notifications(
        self, domain_event: UserDeleted
    ) -> list[NotificationEvent]:
        """Create notifications for user deletion event.

        Args:
            domain_event: UserDeleted domain event

        Returns:
            List of notification events
        """
        notifications = []

        # User goodbye notification
        user_notification = UserDeletedNotification(
            event_id=domain_event.event_id,
            user_id=domain_event.user_id,
            occurred_at=domain_event.occurred_at,
            email=domain_event.email,
            first_name="User",  # Would fetch from user repository
            last_name="",
            deleted_by=str(domain_event.deleted_by),
            priority=NotificationPriority.HIGH,
            channels=frozenset([NotificationChannel.EMAIL]),
            correlation_id=domain_event.correlation_id,
            deletion_reason=domain_event.deletion_reason,
            soft_delete=domain_event.soft_delete,
            data_retention_days=30 if domain_event.soft_delete else None,
        )
        notifications.append(user_notification)

        return notifications

    async def _create_user_password_changed_notifications(
        self, domain_event: UserPasswordChanged
    ) -> list[NotificationEvent]:
        """Create notifications for password change event.

        Args:
            domain_event: UserPasswordChanged domain event

        Returns:
            List of notification events
        """
        notifications = []

        # Security notification about password change
        user_notification = UserPasswordChangedNotification(
            event_id=domain_event.event_id,
            user_id=domain_event.user_id,
            occurred_at=domain_event.occurred_at,
            email=Email("user@example.com"),  # Would fetch from user repository
            first_name="User",  # Would fetch from user repository
            last_name="",
            changed_by=str(domain_event.changed_by),
            is_self_change=domain_event.is_self_change,
            priority=NotificationPriority.HIGH,
            channels=frozenset([NotificationChannel.EMAIL]),
            correlation_id=domain_event.correlation_id,
        )
        notifications.append(user_notification)

        return notifications

    async def _create_user_role_assigned_notifications(
        self, domain_event: UserRoleAssigned
    ) -> list[NotificationEvent]:
        """Create notifications for role assignment event.

        Args:
            domain_event: UserRoleAssigned domain event

        Returns:
            List of notification events
        """
        notifications = []

        # Role assignment notification
        user_notification = UserRoleAssignedNotification(
            event_id=domain_event.event_id,
            user_id=domain_event.user_id,
            occurred_at=domain_event.occurred_at,
            email=Email("user@example.com"),  # Would fetch from user repository
            first_name="User",  # Would fetch from user repository
            last_name="",
            role_name=str(domain_event.role_id),  # Would fetch role name from repository
            assigned_by=str(domain_event.assigned_by),
            priority=NotificationPriority.NORMAL,
            channels=frozenset([NotificationChannel.EMAIL]),
            correlation_id=domain_event.correlation_id,
        )
        notifications.append(user_notification)

        return notifications

    async def _create_user_role_removed_notifications(
        self, domain_event: UserRoleRemoved
    ) -> list[NotificationEvent]:
        """Create notifications for role removal event.

        Args:
            domain_event: UserRoleRemoved domain event

        Returns:
            List of notification events
        """
        notifications = []

        # Role removal notification
        user_notification = UserRoleRemovedNotification(
            event_id=domain_event.event_id,
            user_id=domain_event.user_id,
            occurred_at=domain_event.occurred_at,
            email=Email("user@example.com"),  # Would fetch from user repository
            first_name="User",  # Would fetch from user repository
            last_name="",
            role_name=str(domain_event.role_id),  # Would fetch role name from repository
            removed_by=str(domain_event.removed_by),
            priority=NotificationPriority.NORMAL,
            channels=frozenset([NotificationChannel.EMAIL]),
            correlation_id=domain_event.correlation_id,
            removal_reason=domain_event.removal_reason,
        )
        notifications.append(user_notification)

        return notifications

    async def _create_user_status_changed_notifications(
        self, domain_event: UserStatusChanged
    ) -> list[NotificationEvent]:
        """Create notifications for status change event.

        Args:
            domain_event: UserStatusChanged domain event

        Returns:
            List of notification events
        """
        notifications = []

        # Status change notification
        user_notification = UserStatusChangedNotification(
            event_id=domain_event.event_id,
            user_id=domain_event.user_id,
            occurred_at=domain_event.occurred_at,
            email=Email("user@example.com"),  # Would fetch from user repository
            first_name="User",  # Would fetch from user repository
            last_name="",
            previous_status=domain_event.previous_status,
            new_status=domain_event.new_status,
            changed_by=str(domain_event.changed_by),
            priority=NotificationPriority.HIGH,
            channels=frozenset([NotificationChannel.EMAIL]),
            correlation_id=domain_event.correlation_id,
            reason=domain_event.reason,
        )
        notifications.append(user_notification)

        return notifications

    async def send_custom_notification(
        self,
        user_id: UserId,
        subject: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        channels: Optional[list[NotificationChannel]] = None,
    ) -> bool:
        """Send a custom notification to a user.

        Args:
            user_id: Target user ID
            subject: Notification subject
            message: Notification message
            priority: Notification priority
            channels: Delivery channels (defaults to email)

        Returns:
            True if notification was sent successfully
        """
        if channels is None:
            channels = [NotificationChannel.EMAIL]

        # Create a simple custom notification
        # In a real implementation, this would be a dedicated custom notification class
        from .events import UserCreatedNotification  # Reuse for simplicity

        custom_notification = UserCreatedNotification(
            event_id=uuid4(),
            user_id=user_id,
            occurred_at=datetime.utcnow(),
            email=Email("user@example.com"),  # Would fetch from user repository
            first_name="User",  # Would fetch from user repository
            last_name="",
            username="user",
            priority=priority,
            channels=frozenset(channels),
            welcome_message=message,
        )

        return await self.processor.process_notification(custom_notification)

    def get_service_status(self) -> dict[str, any]:
        """Get status information about the notification service.

        Returns:
            Dictionary with service status information
        """
        return {
            "enabled": self.config.enabled,
            "processor_status": self.processor.get_handler_status(),
            "config": {
                "async_processing": self.config.async_processing,
                "max_retry_attempts": self.config.max_retry_attempts,
                "enabled_channels": self.config.get_enabled_channels(),
                "admin_notifications_enabled": self.config.admin_notification_enabled,
                "user_preferences_allowed": self.config.allow_user_preferences,
            },
        }
