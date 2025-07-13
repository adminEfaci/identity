"""Notification Configuration for Identity Module.

This module defines configuration settings for the notification system,
including delivery methods, retry policies, and template settings.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class NotificationConfig:
    """Configuration for notification system.

    Controls how notifications are processed, delivered, and managed
    across different channels and delivery methods.
    """

    enabled: bool = field(default=True)
    async_processing: bool = field(default=True)
    max_retry_attempts: int = field(default=3)
    retry_delay_seconds: int = field(default=30)
    delivery_timeout_seconds: int = field(default=60)

    # Email configuration
    email_enabled: bool = field(default=True)
    email_from_address: str = field(default="noreply@identity.local")
    email_from_name: str = field(default="Identity Service")
    smtp_host: Optional[str] = field(default=None)
    smtp_port: int = field(default=587)
    smtp_username: Optional[str] = field(default=None)
    smtp_password: Optional[str] = field(default=None)
    smtp_use_tls: bool = field(default=True)

    # Slack configuration
    slack_enabled: bool = field(default=False)
    slack_webhook_url: Optional[str] = field(default=None)
    slack_default_channel: str = field(default="#notifications")
    slack_bot_name: str = field(default="Identity Bot")

    # Webhook configuration
    webhook_enabled: bool = field(default=False)
    webhook_urls: list[str] = field(default_factory=list)
    webhook_timeout_seconds: int = field(default=30)
    webhook_include_sensitive_data: bool = field(default=False)

    # Template configuration
    template_base_path: str = field(default="templates/notifications")
    use_html_templates: bool = field(default=True)
    default_locale: str = field(default="en")

    # Admin notification settings
    admin_notification_enabled: bool = field(default=True)
    admin_email_addresses: list[str] = field(default_factory=list)
    admin_slack_channel: Optional[str] = field(default=None)

    # User notification preferences
    allow_user_preferences: bool = field(default=True)
    default_user_notifications_enabled: bool = field(default=True)
    user_notification_channels: list[str] = field(
        default_factory=lambda: ["email"]
    )

    # Batch processing
    batch_processing_enabled: bool = field(default=False)
    batch_size: int = field(default=10)
    batch_processing_interval_seconds: int = field(default=300)

    # Rate limiting
    rate_limiting_enabled: bool = field(default=True)
    max_notifications_per_user_per_hour: int = field(default=10)
    max_notifications_per_user_per_day: int = field(default=50)

    def __post_init__(self) -> None:
        """Validate notification configuration."""
        if self.max_retry_attempts < 0:
            raise ValueError("Max retry attempts must be non-negative")

        if self.retry_delay_seconds < 0:
            raise ValueError("Retry delay must be non-negative")

        if self.delivery_timeout_seconds <= 0:
            raise ValueError("Delivery timeout must be positive")

        if self.smtp_port <= 0 or self.smtp_port > 65535:
            raise ValueError("SMTP port must be between 1 and 65535")

        if self.webhook_timeout_seconds <= 0:
            raise ValueError("Webhook timeout must be positive")

        if self.batch_size <= 0:
            raise ValueError("Batch size must be positive")

        if self.batch_processing_interval_seconds <= 0:
            raise ValueError("Batch processing interval must be positive")

        if self.max_notifications_per_user_per_hour < 0:
            raise ValueError("Max notifications per user per hour must be non-negative")

        if self.max_notifications_per_user_per_day < 0:
            raise ValueError("Max notifications per user per day must be non-negative")

    def get_enabled_channels(self) -> list[str]:
        """Get list of enabled notification channels.

        Returns:
            List of enabled channel names
        """
        channels = []

        if self.email_enabled:
            channels.append("email")

        if self.slack_enabled:
            channels.append("slack")

        if self.webhook_enabled:
            channels.append("webhook")

        return channels

    def is_channel_enabled(self, channel: str) -> bool:
        """Check if a specific notification channel is enabled.

        Args:
            channel: Channel name to check

        Returns:
            True if channel is enabled, False otherwise
        """
        channel_mappings = {
            "email": self.email_enabled,
            "slack": self.slack_enabled,
            "webhook": self.webhook_enabled,
        }

        return channel_mappings.get(channel, False)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary representation.

        Returns:
            Dictionary representation of the configuration
        """
        return {
            "enabled": self.enabled,
            "async_processing": self.async_processing,
            "max_retry_attempts": self.max_retry_attempts,
            "retry_delay_seconds": self.retry_delay_seconds,
            "delivery_timeout_seconds": self.delivery_timeout_seconds,
            "email_enabled": self.email_enabled,
            "email_from_address": self.email_from_address,
            "email_from_name": self.email_from_name,
            "slack_enabled": self.slack_enabled,
            "slack_default_channel": self.slack_default_channel,
            "slack_bot_name": self.slack_bot_name,
            "webhook_enabled": self.webhook_enabled,
            "webhook_timeout_seconds": self.webhook_timeout_seconds,
            "webhook_include_sensitive_data": self.webhook_include_sensitive_data,
            "template_base_path": self.template_base_path,
            "use_html_templates": self.use_html_templates,
            "default_locale": self.default_locale,
            "admin_notification_enabled": self.admin_notification_enabled,
            "allow_user_preferences": self.allow_user_preferences,
            "default_user_notifications_enabled": self.default_user_notifications_enabled,
            "user_notification_channels": self.user_notification_channels,
            "batch_processing_enabled": self.batch_processing_enabled,
            "batch_size": self.batch_size,
            "batch_processing_interval_seconds": self.batch_processing_interval_seconds,
            "rate_limiting_enabled": self.rate_limiting_enabled,
            "max_notifications_per_user_per_hour": self.max_notifications_per_user_per_hour,
            "max_notifications_per_user_per_day": self.max_notifications_per_user_per_day,
        }
