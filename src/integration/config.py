"""Configuration for cross-module integration.

This module defines configuration classes for managing integration
between the identity-module and the main application's identity system.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class IntegrationConfig:
    """Configuration for identity module integration."""

    # Main app integration settings
    main_app_enabled: bool = True
    main_app_identity_module_path: str = "app.modules.identity"

    # Event integration settings
    event_integration_enabled: bool = True
    event_bus_type: str = "internal"  # "internal", "rabbitmq", "kafka"
    event_bus_url: Optional[str] = None

    # Audit integration settings
    audit_integration_enabled: bool = True
    audit_cross_module: bool = True

    # Notification integration settings
    notification_integration_enabled: bool = True
    notification_cross_module: bool = True

    # Role synchronization settings
    role_sync_enabled: bool = True
    role_sync_bidirectional: bool = False
    role_prefix_external: str = "external_"

    # Token integration settings
    token_sharing_enabled: bool = True
    token_validation_cross_module: bool = True

    # MFA integration settings
    mfa_integration_enabled: bool = True
    mfa_fallback_to_main_app: bool = True

    # Security settings
    security_event_sharing: bool = True
    failed_login_threshold: int = 5

    # Performance settings
    cache_integration_results: bool = True
    cache_ttl_seconds: int = 300
    async_processing: bool = True

    # Fallback settings
    fallback_to_main_app: bool = True
    timeout_seconds: int = 30

    # Additional configuration
    additional_settings: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if self.event_bus_type not in ["internal", "rabbitmq", "kafka"]:
            raise ValueError(f"Invalid event_bus_type: {self.event_bus_type}")

        if self.event_bus_type in ["rabbitmq", "kafka"] and not self.event_bus_url:
            raise ValueError(f"event_bus_url is required for {self.event_bus_type}")

        if self.failed_login_threshold < 1:
            raise ValueError("failed_login_threshold must be positive")

        if self.cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds must be non-negative")

        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")

        logger.info("Integration configuration validated successfully")

    @classmethod
    def from_env(cls) -> "IntegrationConfig":
        """Create configuration from environment variables."""
        import os

        return cls(
            main_app_enabled=os.getenv("IDENTITY_MAIN_APP_ENABLED", "true").lower() == "true",
            main_app_identity_module_path=os.getenv(
                "IDENTITY_MAIN_APP_MODULE_PATH",
                "app.modules.identity"
            ),
            event_integration_enabled=os.getenv(
                "IDENTITY_EVENT_INTEGRATION_ENABLED", "true"
            ).lower() == "true",
            event_bus_type=os.getenv("IDENTITY_EVENT_BUS_TYPE", "internal"),
            event_bus_url=os.getenv("IDENTITY_EVENT_BUS_URL"),
            audit_integration_enabled=os.getenv(
                "IDENTITY_AUDIT_INTEGRATION_ENABLED", "true"
            ).lower() == "true",
            audit_cross_module=os.getenv(
                "IDENTITY_AUDIT_CROSS_MODULE", "true"
            ).lower() == "true",
            notification_integration_enabled=os.getenv(
                "IDENTITY_NOTIFICATION_INTEGRATION_ENABLED", "true"
            ).lower() == "true",
            notification_cross_module=os.getenv(
                "IDENTITY_NOTIFICATION_CROSS_MODULE", "true"
            ).lower() == "true",
            role_sync_enabled=os.getenv(
                "IDENTITY_ROLE_SYNC_ENABLED", "true"
            ).lower() == "true",
            role_sync_bidirectional=os.getenv(
                "IDENTITY_ROLE_SYNC_BIDIRECTIONAL", "false"
            ).lower() == "true",
            role_prefix_external=os.getenv("IDENTITY_ROLE_PREFIX_EXTERNAL", "external_"),
            token_sharing_enabled=os.getenv(
                "IDENTITY_TOKEN_SHARING_ENABLED", "true"
            ).lower() == "true",
            token_validation_cross_module=os.getenv(
                "IDENTITY_TOKEN_VALIDATION_CROSS_MODULE", "true"
            ).lower() == "true",
            mfa_integration_enabled=os.getenv(
                "IDENTITY_MFA_INTEGRATION_ENABLED", "true"
            ).lower() == "true",
            mfa_fallback_to_main_app=os.getenv(
                "IDENTITY_MFA_FALLBACK_TO_MAIN_APP", "true"
            ).lower() == "true",
            security_event_sharing=os.getenv(
                "IDENTITY_SECURITY_EVENT_SHARING", "true"
            ).lower() == "true",
            failed_login_threshold=int(os.getenv("IDENTITY_FAILED_LOGIN_THRESHOLD", "5")),
            cache_integration_results=os.getenv(
                "IDENTITY_CACHE_INTEGRATION_RESULTS", "true"
            ).lower() == "true",
            cache_ttl_seconds=int(os.getenv("IDENTITY_CACHE_TTL_SECONDS", "300")),
            async_processing=os.getenv(
                "IDENTITY_ASYNC_PROCESSING", "true"
            ).lower() == "true",
            fallback_to_main_app=os.getenv(
                "IDENTITY_FALLBACK_TO_MAIN_APP", "true"
            ).lower() == "true",
            timeout_seconds=int(os.getenv("IDENTITY_TIMEOUT_SECONDS", "30")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "main_app_enabled": self.main_app_enabled,
            "main_app_identity_module_path": self.main_app_identity_module_path,
            "event_integration_enabled": self.event_integration_enabled,
            "event_bus_type": self.event_bus_type,
            "event_bus_url": self.event_bus_url,
            "audit_integration_enabled": self.audit_integration_enabled,
            "audit_cross_module": self.audit_cross_module,
            "notification_integration_enabled": self.notification_integration_enabled,
            "notification_cross_module": self.notification_cross_module,
            "role_sync_enabled": self.role_sync_enabled,
            "role_sync_bidirectional": self.role_sync_bidirectional,
            "role_prefix_external": self.role_prefix_external,
            "token_sharing_enabled": self.token_sharing_enabled,
            "token_validation_cross_module": self.token_validation_cross_module,
            "mfa_integration_enabled": self.mfa_integration_enabled,
            "mfa_fallback_to_main_app": self.mfa_fallback_to_main_app,
            "security_event_sharing": self.security_event_sharing,
            "failed_login_threshold": self.failed_login_threshold,
            "cache_integration_results": self.cache_integration_results,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "async_processing": self.async_processing,
            "fallback_to_main_app": self.fallback_to_main_app,
            "timeout_seconds": self.timeout_seconds,
            **self.additional_settings,
        }

    def update(self, **kwargs: Any) -> None:
        """Update configuration with new values."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                self.additional_settings[key] = value

        # Re-validate after update
        self.__post_init__()


@dataclass
class EventIntegrationConfig:
    """Configuration for event-based integration."""

    # Event routing settings
    route_to_main_app: bool = True
    route_to_audit_module: bool = True
    route_to_notification_module: bool = True

    # Event filtering
    filter_user_events: bool = False
    filter_mfa_events: bool = False
    filter_rbac_events: bool = False
    filter_security_events: bool = False

    # Event transformation
    transform_events: bool = True
    event_schema_version: str = "1.0"

    # Retry and error handling
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    dead_letter_queue_enabled: bool = True

    # Batch processing
    batch_size: int = 10
    batch_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        """Validate event integration configuration."""
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")

        if self.retry_delay_seconds < 0:
            raise ValueError("retry_delay_seconds must be non-negative")

        if self.batch_size < 1:
            raise ValueError("batch_size must be positive")

        if self.batch_timeout_seconds < 0:
            raise ValueError("batch_timeout_seconds must be non-negative")


@dataclass
class SecurityIntegrationConfig:
    """Configuration for security-related integration."""

    # Cross-module security checks
    validate_tokens_across_modules: bool = True
    share_session_state: bool = True
    sync_security_policies: bool = True

    # MFA integration
    unified_mfa_enforcement: bool = True
    mfa_challenge_cross_module: bool = True

    # Risk assessment
    aggregate_risk_scores: bool = True
    cross_module_risk_factors: bool = True

    # Incident response
    coordinate_incident_response: bool = True
    share_threat_intelligence: bool = True

    def __post_init__(self) -> None:
        """Validate security integration configuration."""
        logger.info("Security integration configuration validated")


def create_default_integration_config() -> IntegrationConfig:
    """Create default integration configuration.

    Returns:
        Default integration configuration
    """
    return IntegrationConfig()


def create_integration_config_from_dict(config_dict: dict[str, Any]) -> IntegrationConfig:
    """Create integration configuration from dictionary.

    Args:
        config_dict: Configuration dictionary

    Returns:
        Integration configuration instance
    """
    # Extract known fields
    known_fields = {
        field.name for field in IntegrationConfig.__dataclass_fields__.values()
        if field.name != "additional_settings"
    }

    config_args = {}
    additional_settings = {}

    for key, value in config_dict.items():
        if key in known_fields:
            config_args[key] = value
        else:
            additional_settings[key] = value

    if additional_settings:
        config_args["additional_settings"] = additional_settings

    return IntegrationConfig(**config_args)


# Global configuration instance
_integration_config: Optional[IntegrationConfig] = None


def get_integration_config() -> IntegrationConfig:
    """Get global integration configuration.

    Returns:
        Global integration configuration instance
    """
    global _integration_config

    if _integration_config is None:
        _integration_config = IntegrationConfig.from_env()

    return _integration_config


def set_integration_config(config: IntegrationConfig) -> None:
    """Set global integration configuration.

    Args:
        config: Integration configuration to set globally
    """
    global _integration_config
    _integration_config = config
    logger.info("Global integration configuration updated")
