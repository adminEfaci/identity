"""Notification Event Processors for Identity Module.

This module provides the main processor for handling notification events,
managing delivery through multiple channels, and handling failures/retries.
"""

import logging
from typing import Any

from .config import NotificationConfig
from .events import NotificationEvent
from .handlers import (
    EmailNotificationHandler,
    NotificationHandler,
    SlackNotificationHandler,
    WebhookNotificationHandler,
)

logger = logging.getLogger(__name__)


class NotificationEventProcessor:
    """Main processor for handling notification events.

    Manages the routing and delivery of notification events through
    multiple channels with appropriate error handling and retry logic.
    """

    def __init__(self, config: NotificationConfig) -> None:
        """Initialize notification event processor.

        Args:
            config: Notification configuration
        """
        self.config = config
        self._handlers: list[NotificationHandler] = []
        self._initialize_handlers()

    def _initialize_handlers(self) -> None:
        """Initialize notification handlers based on configuration."""
        if self.config.email_enabled:
            self._handlers.append(EmailNotificationHandler(self.config))
            logger.info("Email notification handler initialized")

        if self.config.slack_enabled:
            self._handlers.append(SlackNotificationHandler(self.config))
            logger.info("Slack notification handler initialized")

        if self.config.webhook_enabled:
            self._handlers.append(WebhookNotificationHandler(self.config))
            logger.info("Webhook notification handler initialized")

        if not self._handlers:
            logger.warning("No notification handlers are enabled")

    async def process_notification(self, notification: NotificationEvent) -> bool:
        """Process a notification event through all applicable handlers.

        Args:
            notification: Notification event to process

        Returns:
            True if notification was processed successfully by at least one handler
        """
        if not self.config.enabled:
            logger.debug("Notifications are disabled, skipping processing")
            return False

        logger.info(
            f"Processing notification {notification.notification_id} "
            f"of type {notification.event_type} for user {notification.user_id}"
        )

        # Find applicable handlers
        applicable_handlers = [
            handler for handler in self._handlers
            if handler.can_handle(notification)
        ]

        if not applicable_handlers:
            logger.warning(
                f"No handlers found for notification {notification.notification_id} "
                f"with channels: {[ch.value for ch in notification.channels]}"
            )
            return False

        # Send through all applicable handlers
        results = []
        for handler in applicable_handlers:
            try:
                success = await handler.send_notification(notification)
                results.append(success)

                if success:
                    logger.info(
                        f"Notification {notification.notification_id} "
                        f"sent successfully via {handler.__class__.__name__}"
                    )
                else:
                    logger.error(
                        f"Failed to send notification {notification.notification_id} "
                        f"via {handler.__class__.__name__}"
                    )
            except Exception as e:
                logger.error(
                    f"Error processing notification {notification.notification_id} "
                    f"with {handler.__class__.__name__}: {e}"
                )
                results.append(False)

        # Return True if at least one handler succeeded
        success_count = sum(results)
        total_handlers = len(applicable_handlers)

        logger.info(
            f"Notification {notification.notification_id} processed: "
            f"{success_count}/{total_handlers} handlers succeeded"
        )

        return success_count > 0

    async def process_batch_notifications(
        self, notifications: list[NotificationEvent]
    ) -> dict[str, bool]:
        """Process multiple notifications in batch.

        Args:
            notifications: List of notification events to process

        Returns:
            Dictionary mapping notification IDs to success status
        """
        if not self.config.enabled:
            logger.debug("Notifications are disabled, skipping batch processing")
            return {str(notif.notification_id): False for notif in notifications}

        logger.info(f"Processing batch of {len(notifications)} notifications")

        results = {}
        for notification in notifications:
            try:
                success = await self.process_notification(notification)
                results[str(notification.notification_id)] = success
            except Exception as e:
                logger.error(
                    f"Error processing notification {notification.notification_id} "
                    f"in batch: {e}"
                )
                results[str(notification.notification_id)] = False

        successful_count = sum(results.values())
        logger.info(
            f"Batch processing completed: {successful_count}/{len(notifications)} "
            f"notifications processed successfully"
        )

        return results

    def get_handler_status(self) -> dict[str, Any]:
        """Get status information about all notification handlers.

        Returns:
            Dictionary with handler status information
        """
        status = {
            "enabled": self.config.enabled,
            "total_handlers": len(self._handlers),
            "handlers": []
        }

        for handler in self._handlers:
            handler_info = {
                "name": handler.__class__.__name__,
                "enabled": True,  # If handler exists, it's enabled
            }

            # Add handler-specific status information
            if isinstance(handler, EmailNotificationHandler):
                handler_info.update({
                    "type": "email",
                    "from_address": self.config.email_from_address,
                    "smtp_configured": self.config.smtp_host is not None,
                })
            elif isinstance(handler, SlackNotificationHandler):
                handler_info.update({
                    "type": "slack",
                    "webhook_configured": self.config.slack_webhook_url is not None,
                    "default_channel": self.config.slack_default_channel,
                })
            elif isinstance(handler, WebhookNotificationHandler):
                handler_info.update({
                    "type": "webhook",
                    "webhook_count": len(self.config.webhook_urls),
                    "include_sensitive_data": self.config.webhook_include_sensitive_data,
                })

            status["handlers"].append(handler_info)

        return status

    def add_handler(self, handler: NotificationHandler) -> None:
        """Add a custom notification handler.

        Args:
            handler: Notification handler to add
        """
        self._handlers.append(handler)
        logger.info(f"Added custom notification handler: {handler.__class__.__name__}")

    def remove_handler(self, handler_class: type) -> bool:
        """Remove a notification handler by class type.

        Args:
            handler_class: Class type of handler to remove

        Returns:
            True if handler was found and removed, False otherwise
        """
        original_count = len(self._handlers)
        self._handlers = [h for h in self._handlers if not isinstance(h, handler_class)]
        removed_count = original_count - len(self._handlers)

        if removed_count > 0:
            logger.info(f"Removed {removed_count} handler(s) of type {handler_class.__name__}")
            return True
        else:
            logger.warning(f"No handlers of type {handler_class.__name__} found to remove")
            return False
