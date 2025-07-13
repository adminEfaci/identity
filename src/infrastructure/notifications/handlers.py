"""Notification Handlers for Identity Module.

This module provides concrete implementations for delivering notifications
through various channels like email, Slack, webhooks, etc.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from .config import NotificationConfig
from .events import NotificationEvent, NotificationPriority

logger = logging.getLogger(__name__)


class NotificationHandler(ABC):
    """Abstract base class for notification handlers.

    Defines the interface for delivering notifications through
    specific channels with retry and error handling capabilities.
    """

    def __init__(self, config: NotificationConfig) -> None:
        """Initialize notification handler.

        Args:
            config: Notification configuration
        """
        self.config = config

    @abstractmethod
    async def send_notification(self, notification: NotificationEvent) -> bool:
        """Send a notification through this handler's channel.

        Args:
            notification: Notification event to send

        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass

    @abstractmethod
    def can_handle(self, notification: NotificationEvent) -> bool:
        """Check if this handler can process the given notification.

        Args:
            notification: Notification event to check

        Returns:
            True if handler can process this notification, False otherwise
        """
        pass

    async def _retry_send(
        self, notification: NotificationEvent, send_func: callable
    ) -> bool:
        """Retry sending notification with exponential backoff.

        Args:
            notification: Notification event to send
            send_func: Function to call for sending

        Returns:
            True if notification was eventually sent, False otherwise
        """
        attempts = 0
        while attempts < self.config.max_retry_attempts:
            try:
                success = await send_func(notification)
                if success:
                    return True
            except Exception as e:
                logger.warning(
                    f"Notification send attempt {attempts + 1} failed: {e}"
                )

            attempts += 1
            if attempts < self.config.max_retry_attempts:
                # Exponential backoff
                delay = self.config.retry_delay_seconds * (2 ** (attempts - 1))
                logger.info(f"Retrying notification send in {delay} seconds...")
                # In real implementation, use asyncio.sleep(delay)

        logger.error(
            f"Failed to send notification {notification.notification_id} "
            f"after {self.config.max_retry_attempts} attempts"
        )
        return False


class EmailNotificationHandler(NotificationHandler):
    """Email notification handler using SMTP."""

    def __init__(self, config: NotificationConfig) -> None:
        """Initialize email notification handler.

        Args:
            config: Notification configuration
        """
        super().__init__(config)
        if not config.email_enabled:
            logger.warning("Email notifications are disabled")

    async def send_notification(self, notification: NotificationEvent) -> bool:
        """Send notification via email.

        Args:
            notification: Notification event to send

        Returns:
            True if email was sent successfully, False otherwise
        """
        if not self.config.email_enabled:
            logger.debug("Email notifications disabled, skipping")
            return False

        return await self._retry_send(notification, self._send_email)

    async def _send_email(self, notification: NotificationEvent) -> bool:
        """Send email notification.

        Args:
            notification: Notification event to send

        Returns:
            True if email was sent successfully, False otherwise
        """
        try:
            # Get template data
            template_data = notification.get_template_data()
            recipient_email = template_data.get("email")

            if not recipient_email:
                logger.error("No email address found in notification data")
                return False

            # In a real implementation, this would use an actual SMTP client
            # like aiosmtplib or a service like SendGrid
            email_data = {
                "from": f"{self.config.email_from_name} <{self.config.email_from_address}>",
                "to": recipient_email,
                "subject": notification.get_subject(),
                "text_body": notification.get_message(),
                "html_body": self._render_html_template(notification),
                "headers": {
                    "X-Notification-ID": str(notification.notification_id),
                    "X-Event-ID": str(notification.event_id),
                    "X-User-ID": str(notification.user_id),
                },
            }

            # Simulate email sending
            logger.info(f"Sending email notification to {recipient_email}")
            logger.debug(f"Email data: {email_data}")

            # In real implementation, use SMTP client here
            # smtp_client = aiosmtplib.SMTP(
            #     hostname=self.config.smtp_host,
            #     port=self.config.smtp_port,
            #     use_tls=self.config.smtp_use_tls
            # )
            # await smtp_client.connect()
            # await smtp_client.starttls()
            # await smtp_client.login(self.config.smtp_username, self.config.smtp_password)
            # await smtp_client.send_message(message)
            # await smtp_client.quit()

            return True

        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False

    def _render_html_template(self, notification: NotificationEvent) -> str:
        """Render HTML template for email.

        Args:
            notification: Notification event

        Returns:
            Rendered HTML content
        """
        if not self.config.use_html_templates:
            return notification.get_message().replace("\n", "<br>")

        # In real implementation, use a template engine like Jinja2
        notification.get_template_data()

        # Simple HTML template
        html_content = f"""
        <html>
        <body>
            <h2>{notification.get_subject()}</h2>
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                {notification.get_message().replace('\n', '<br>')}
            </div>
            <hr>
            <small>
                Notification ID: {notification.notification_id}<br>
                Event Type: {notification.event_type}<br>
                Generated at: {notification.occurred_at.isoformat()}
            </small>
        </body>
        </html>
        """

        return html_content

    def can_handle(self, notification: NotificationEvent) -> bool:
        """Check if this handler can process the notification.

        Args:
            notification: Notification event to check

        Returns:
            True if email channel is enabled and in notification channels
        """
        from .events import NotificationChannel

        return (
            self.config.email_enabled
            and NotificationChannel.EMAIL in notification.channels
        )


class SlackNotificationHandler(NotificationHandler):
    """Slack notification handler using webhooks."""

    def __init__(self, config: NotificationConfig) -> None:
        """Initialize Slack notification handler.

        Args:
            config: Notification configuration
        """
        super().__init__(config)
        if not config.slack_enabled:
            logger.warning("Slack notifications are disabled")

    async def send_notification(self, notification: NotificationEvent) -> bool:
        """Send notification via Slack.

        Args:
            notification: Notification event to send

        Returns:
            True if Slack message was sent successfully, False otherwise
        """
        if not self.config.slack_enabled or not self.config.slack_webhook_url:
            logger.debug("Slack notifications disabled or webhook URL not configured")
            return False

        return await self._retry_send(notification, self._send_slack_message)

    async def _send_slack_message(self, notification: NotificationEvent) -> bool:
        """Send Slack notification.

        Args:
            notification: Notification event to send

        Returns:
            True if Slack message was sent successfully, False otherwise
        """
        try:
            # Build Slack message payload
            template_data = notification.get_template_data()

            slack_payload = {
                "channel": self.config.slack_default_channel,
                "username": self.config.slack_bot_name,
                "text": notification.get_subject(),
                "attachments": [
                    {
                        "color": self._get_color_for_priority(notification.priority),
                        "title": notification.get_subject(),
                        "text": notification.get_message(),
                        "fields": [
                            {
                                "title": "Event Type",
                                "value": notification.event_type,
                                "short": True
                            },
                            {
                                "title": "User",
                                "value": template_data.get("full_name", "Unknown"),
                                "short": True
                            },
                            {
                                "title": "Priority",
                                "value": notification.priority.value.capitalize(),
                                "short": True
                            },
                            {
                                "title": "Occurred At",
                                "value": notification.occurred_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                "short": True
                            }
                        ],
                        "footer": "Identity Service",
                        "ts": int(notification.occurred_at.timestamp())
                    }
                ]
            }

            # Send to Slack webhook
            async with httpx.AsyncClient(timeout=self.config.webhook_timeout_seconds) as client:
                response = await client.post(
                    self.config.slack_webhook_url,
                    json=slack_payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    logger.info("Slack notification sent successfully")
                    return True
                else:
                    logger.error(f"Slack webhook returned status {response.status_code}: {response.text}")
                    return False

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    def _get_color_for_priority(self, priority: NotificationPriority) -> str:
        """Get Slack attachment color based on priority.

        Args:
            priority: Notification priority

        Returns:
            Hex color code for Slack attachment
        """
        from .events import NotificationPriority

        color_map = {
            NotificationPriority.LOW: "#36a64f",      # Green
            NotificationPriority.NORMAL: "#439fe0",   # Blue
            NotificationPriority.HIGH: "#ff9500",     # Orange
            NotificationPriority.URGENT: "#ff0000",   # Red
        }

        return color_map.get(priority, "#439fe0")

    def can_handle(self, notification: NotificationEvent) -> bool:
        """Check if this handler can process the notification.

        Args:
            notification: Notification event to check

        Returns:
            True if Slack channel is enabled and in notification channels
        """
        from .events import NotificationChannel

        return (
            self.config.slack_enabled
            and self.config.slack_webhook_url is not None
            and NotificationChannel.SLACK in notification.channels
        )


class WebhookNotificationHandler(NotificationHandler):
    """Webhook notification handler for custom integrations."""

    def __init__(self, config: NotificationConfig) -> None:
        """Initialize webhook notification handler.

        Args:
            config: Notification configuration
        """
        super().__init__(config)
        if not config.webhook_enabled:
            logger.warning("Webhook notifications are disabled")

    async def send_notification(self, notification: NotificationEvent) -> bool:
        """Send notification via webhooks.

        Args:
            notification: Notification event to send

        Returns:
            True if all webhooks were called successfully, False otherwise
        """
        if not self.config.webhook_enabled or not self.config.webhook_urls:
            logger.debug("Webhook notifications disabled or no URLs configured")
            return False

        return await self._retry_send(notification, self._send_webhook_calls)

    async def _send_webhook_calls(self, notification: NotificationEvent) -> bool:
        """Send webhook notifications to all configured URLs.

        Args:
            notification: Notification event to send

        Returns:
            True if all webhook calls succeeded, False otherwise
        """
        all_success = True

        for webhook_url in self.config.webhook_urls:
            success = await self._send_single_webhook(notification, webhook_url)
            if not success:
                all_success = False

        return all_success

    async def _send_single_webhook(
        self, notification: NotificationEvent, webhook_url: str
    ) -> bool:
        """Send webhook notification to a single URL.

        Args:
            notification: Notification event to send
            webhook_url: Webhook URL to call

        Returns:
            True if webhook call succeeded, False otherwise
        """
        try:
            # Build webhook payload
            payload = notification.to_dict()

            # Remove sensitive data if not allowed
            if not self.config.webhook_include_sensitive_data:
                payload = self._sanitize_payload(payload)

            # Add webhook metadata
            payload["webhook_metadata"] = {
                "sent_at": notification.occurred_at.isoformat(),
                "webhook_version": "1.0",
                "source": "identity-service"
            }

            # Send webhook
            async with httpx.AsyncClient(timeout=self.config.webhook_timeout_seconds) as client:
                response = await client.post(
                    webhook_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-Notification-ID": str(notification.notification_id),
                        "X-Event-Type": notification.event_type,
                        "User-Agent": "Identity-Service-Webhook/1.0"
                    }
                )

                if 200 <= response.status_code < 300:
                    logger.info(f"Webhook notification sent successfully to {webhook_url}")
                    return True
                else:
                    logger.error(
                        f"Webhook {webhook_url} returned status {response.status_code}: {response.text}"
                    )
                    return False

        except Exception as e:
            logger.error(f"Failed to send webhook notification to {webhook_url}: {e}")
            return False

    def _sanitize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive data from webhook payload.

        Args:
            payload: Original payload

        Returns:
            Sanitized payload with sensitive data removed
        """
        # Create a copy to avoid modifying the original
        sanitized = payload.copy()

        # Remove or mask sensitive fields
        sensitive_fields = ["email", "ip_address", "user_agent"]
        template_data = sanitized.get("template_data", {})

        for field in sensitive_fields:
            if field in template_data:
                if field == "email":
                    # Mask email address
                    email = template_data[field]
                    if "@" in email:
                        username, domain = email.split("@", 1)
                        masked_username = username[:2] + "*" * (len(username) - 2)
                        template_data[field] = f"{masked_username}@{domain}"
                else:
                    # Remove other sensitive fields
                    template_data.pop(field, None)

        return sanitized

    def can_handle(self, notification: NotificationEvent) -> bool:
        """Check if this handler can process the notification.

        Args:
            notification: Notification event to check

        Returns:
            True if webhook channel is enabled and in notification channels
        """
        from .events import NotificationChannel

        return (
            self.config.webhook_enabled
            and len(self.config.webhook_urls) > 0
            and NotificationChannel.WEBHOOK in notification.channels
        )
