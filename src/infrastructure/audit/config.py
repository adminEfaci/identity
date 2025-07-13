"""Audit Configuration for Identity Module.

This module provides configuration settings for audit event processing,
storage, and retention policies.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditConfig:
    """Configuration for audit event processing and storage.
    
    This configuration controls how audit events are processed, stored,
    and retained within the identity module.
    """

    # Event processing settings
    enabled: bool = field(default=True)
    """Whether audit event processing is enabled"""

    async_processing: bool = field(default=True)
    """Whether to process audit events asynchronously via Celery"""

    # Storage settings
    store_domain_events: bool = field(default=True)
    """Whether to store domain events (UserCreated, UserModified, UserDeleted)"""

    store_api_requests: bool = field(default=True)
    """Whether to store API request/response audit events"""

    store_graphql_operations: bool = field(default=True)
    """Whether to store GraphQL operation audit events"""

    # Queue and routing settings
    audit_queue_name: str = field(default="identity_audit")
    """Name of the Celery queue for audit event processing"""

    audit_routing_key: str = field(default="identity.audit")
    """Base routing key for audit events"""

    domain_event_routing_key: str = field(default="identity.audit.domain")
    """Routing key for domain events"""

    api_request_routing_key: str = field(default="identity.audit.api")
    """Routing key for API request audit events"""

    graphql_operation_routing_key: str = field(default="identity.audit.graphql")
    """Routing key for GraphQL operation audit events"""

    # Retry and error handling
    max_retries: int = field(default=3)
    """Maximum number of retries for failed audit event processing"""

    retry_delay: int = field(default=60)
    """Delay in seconds between retry attempts"""

    dead_letter_queue: str = field(default="identity_audit_dlq")
    """Dead letter queue for failed audit events"""

    # Event filtering
    exclude_health_checks: bool = field(default=True)
    """Whether to exclude health check endpoints from audit logging"""

    exclude_static_content: bool = field(default=True)
    """Whether to exclude static content requests from audit logging"""

    exclude_paths: frozenset[str] = field(default_factory=lambda: frozenset([
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
        "/robots.txt",
    ]))
    """Paths to exclude from audit logging"""

    # Data retention
    retention_days: Optional[int] = field(default=90)
    """Number of days to retain audit events (None for no retention limit)"""

    batch_size: int = field(default=100)
    """Batch size for processing audit events"""

    # Security and privacy
    mask_sensitive_data: bool = field(default=True)
    """Whether to mask sensitive data in audit events"""

    sensitive_fields: frozenset[str] = field(default_factory=lambda: frozenset([
        "password",
        "token",
        "secret",
        "key",
        "authorization",
        "cookie",
    ]))
    """Field names considered sensitive and should be masked"""

    max_payload_size: int = field(default=10240)  # 10KB
    """Maximum size of request/response payload to log (in bytes)"""

    # Logging and monitoring
    log_level: str = field(default="INFO")
    """Log level for audit event processing"""

    enable_metrics: bool = field(default=True)
    """Whether to emit metrics for audit event processing"""

    def __post_init__(self) -> None:
        """Validate audit configuration."""
        if self.retention_days is not None and self.retention_days < 1:
            raise ValueError("Retention days must be positive or None")

        if self.max_retries < 0:
            raise ValueError("Max retries must be non-negative")

        if self.retry_delay < 0:
            raise ValueError("Retry delay must be non-negative")

        if self.batch_size < 1:
            raise ValueError("Batch size must be positive")

        if self.max_payload_size < 0:
            raise ValueError("Max payload size must be non-negative")

    @classmethod
    def create_default(cls) -> "AuditConfig":
        """Create default audit configuration.
        
        Returns:
            Default audit configuration with recommended settings
        """
        return cls()

    @classmethod
    def create_minimal(cls) -> "AuditConfig":
        """Create minimal audit configuration for development.
        
        Returns:
            Minimal audit configuration with reduced functionality
        """
        return cls(
            async_processing=False,
            store_api_requests=False,
            store_graphql_operations=False,
            enable_metrics=False,
            retention_days=7,
        )

    @classmethod
    def create_production(cls) -> "AuditConfig":
        """Create production audit configuration.
        
        Returns:
            Production audit configuration with full functionality
        """
        return cls(
            enabled=True,
            async_processing=True,
            store_domain_events=True,
            store_api_requests=True,
            store_graphql_operations=True,
            max_retries=5,
            retry_delay=30,
            retention_days=365,  # 1 year retention
            enable_metrics=True,
            mask_sensitive_data=True,
        )

    def is_path_excluded(self, path: str) -> bool:
        """Check if a request path should be excluded from audit logging.
        
        Args:
            path: HTTP request path
            
        Returns:
            True if the path should be excluded from audit logging
        """
        # Check exact matches
        if path in self.exclude_paths:
            return True

        # Check health checks
        if self.exclude_health_checks and path in {"/health", "/healthz", "/ping"}:
            return True

        # Check static content
        if self.exclude_static_content:
            static_extensions = {".css", ".js", ".png", ".jpg", ".ico", ".svg"}
            if any(path.endswith(ext) for ext in static_extensions):
                return True

        return False

    def should_mask_field(self, field_name: str) -> bool:
        """Check if a field should be masked for security reasons.
        
        Args:
            field_name: Name of the field to check
            
        Returns:
            True if the field should be masked
        """
        if not self.mask_sensitive_data:
            return False

        field_lower = field_name.lower()
        return any(sensitive in field_lower for sensitive in self.sensitive_fields)
