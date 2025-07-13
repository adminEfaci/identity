"""GraphQL Audit Middleware for Strawberry GraphQL.

This module provides middleware for auditing GraphQL operations including
queries, mutations, and subscriptions with user context and timing information.
"""

import logging
import time
from typing import Any, Optional
from uuid import uuid4

from strawberry.extensions import SchemaExtension
from strawberry.types import ExecutionResult, Info

from ...infrastructure.audit.config import AuditConfig
from ...infrastructure.messaging import MessageBus

logger = logging.getLogger(__name__)


class GraphQLAuditExtension(SchemaExtension):
    """GraphQL Audit Extension for Strawberry GraphQL.

    Captures GraphQL operations for audit logging including user context,
    operation details, and timing information.
    """

    def __init__(
        self,
        message_bus: MessageBus,
        audit_config: AuditConfig,
    ) -> None:
        """Initialize GraphQL audit extension.

        Args:
            message_bus: Message bus for publishing audit events
            audit_config: Audit configuration settings
        """
        self._message_bus = message_bus
        self._audit_config = audit_config
        self._start_time: Optional[float] = None
        self._correlation_id: Optional[str] = None

    def on_operation(self) -> None:
        """Called when a GraphQL operation starts."""
        if self._audit_config.enabled and self._audit_config.store_graphql_operations:
            self._start_time = time.time()
            self._correlation_id = str(uuid4())

    def on_validate(self) -> None:
        """Called when GraphQL validation starts."""
        # We don't need to do anything special for validation
        pass

    def on_execute(self) -> None:
        """Called when GraphQL execution starts."""
        # We don't need to do anything special for execution start
        pass

    def on_request_end(self) -> None:
        """Called when the GraphQL request completes."""
        # This is where we would typically capture and publish the audit event
        # However, we need access to the execution context which isn't available here
        pass


class GraphQLAuditProcessor:
    """Processor for handling GraphQL audit events.

    This class provides methods to capture and process GraphQL operations
    for audit logging purposes.
    """

    def __init__(
        self,
        message_bus: MessageBus,
        audit_config: AuditConfig,
    ) -> None:
        """Initialize GraphQL audit processor.

        Args:
            message_bus: Message bus for publishing audit events
            audit_config: Audit configuration settings
        """
        self._message_bus = message_bus
        self._audit_config = audit_config

    async def process_operation(
        self,
        info: Info,
        result: ExecutionResult,
        start_time: float,
        operation_name: Optional[str] = None,
        operation_type: str = "query",
        query: Optional[str] = None,
        variables: Optional[dict[str, Any]] = None,
    ) -> None:
        """Process a GraphQL operation for audit logging.

        Args:
            info: GraphQL resolver info
            result: GraphQL execution result
            start_time: When the operation started
            operation_name: Name of the operation
            operation_type: Type of operation (query, mutation, subscription)
            query: GraphQL query string
            variables: GraphQL variables
        """
        if not self._audit_config.enabled or not self._audit_config.store_graphql_operations:
            return

        try:
            # Calculate operation duration
            duration_ms = (time.time() - start_time) * 1000

            # Extract user information from context
            user_info = self._extract_user_info(info)

            # Extract client information
            client_info = self._extract_client_info(info)

            # Process errors if any
            errors = None
            if result.errors:
                errors = [
                    {
                        "message": str(error),
                        "path": error.path if hasattr(error, "path") else None,
                        "locations": [
                            {"line": loc.line, "column": loc.column}
                            for loc in (error.locations or [])
                            if hasattr(error, "locations")
                        ],
                    }
                    for error in result.errors
                ]

            # Sanitize variables
            sanitized_variables = self._sanitize_data(variables) if variables else None

            # Truncate query if it's too long
            truncated_query = self._truncate_string(query or "", 2000)

            # Generate correlation ID
            correlation_id = str(uuid4())

            # Publish audit event asynchronously
            if self._audit_config.async_processing:
                task_id = await self._message_bus.publish_audit_graphql_operation(
                    operation_name=operation_name,
                    operation_type=operation_type,
                    query=truncated_query,
                    variables=sanitized_variables,
                    occurred_at=time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime(start_time)),
                    user_id=user_info.get("user_id"),
                    session_id=user_info.get("session_id"),
                    ip_address=client_info.get("ip_address"),
                    user_agent=client_info.get("user_agent"),
                    errors=errors,
                    duration_ms=duration_ms,
                    correlation_id=correlation_id,
                )

                if task_id:
                    logger.debug(
                        f"Published GraphQL audit event for {operation_type} "
                        f"{operation_name or 'unnamed'} with task ID {task_id}"
                    )
                else:
                    logger.warning(
                        f"Failed to publish GraphQL audit event for {operation_type} "
                        f"{operation_name or 'unnamed'}"
                    )
            else:
                # For synchronous processing, we would process immediately
                logger.debug(
                    f"GraphQL audit event for {operation_type} "
                    f"{operation_name or 'unnamed'} (sync mode)"
                )

        except Exception as e:
            logger.error(f"Error processing GraphQL audit event: {e}")

    def _extract_user_info(self, info: Info) -> dict[str, Optional[str]]:
        """Extract user information from GraphQL context.

        Args:
            info: GraphQL resolver info

        Returns:
            Dictionary containing user information
        """
        user_info = {
            "user_id": None,
            "user_email": None,
            "session_id": None,
        }

        # Try to get user information from context
        # This assumes the context has been populated by authentication middleware
        request = getattr(info.context, "request", None)
        if request:
            user_info["user_id"] = getattr(request.state, "user_id", None)
            user_info["user_email"] = getattr(request.state, "user_email", None)
            # Session ID could be extracted from cookies or headers if needed

        return user_info

    def _extract_client_info(self, info: Info) -> dict[str, Optional[str]]:
        """Extract client information from GraphQL context.

        Args:
            info: GraphQL resolver info

        Returns:
            Dictionary containing client information
        """
        client_info = {
            "ip_address": None,
            "user_agent": None,
        }

        # Try to get client information from request
        request = getattr(info.context, "request", None)
        if request:
            client_info["ip_address"] = self._get_client_ip(request)
            client_info["user_agent"] = request.headers.get("user-agent")

        return client_info

    def _get_client_ip(self, request: Any) -> Optional[str]:
        """Extract client IP address from request headers.

        Args:
            request: HTTP request object

        Returns:
            Client IP address or None if not found
        """
        # Check various headers that may contain the real client IP
        ip_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Client-IP",
            "CF-Connecting-IP",  # Cloudflare
            "True-Client-IP",    # Akamai
        ]

        for header in ip_headers:
            ip = request.headers.get(header)
            if ip:
                # X-Forwarded-For can contain multiple IPs, take the first one
                return ip.split(",")[0].strip()

        # Fall back to direct client IP
        if hasattr(request, "client") and request.client:
            return request.client.host

        return None

    def _sanitize_data(self, data: Any) -> Any:
        """Sanitize data by masking sensitive fields.

        Args:
            data: Data to sanitize

        Returns:
            Sanitized data with sensitive fields masked
        """
        if not self._audit_config.mask_sensitive_data:
            return data

        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if self._audit_config.should_mask_field(key):
                    sanitized[key] = "***MASKED***"
                else:
                    sanitized[key] = self._sanitize_data(value)
            return sanitized

        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]

        else:
            return data

    def _truncate_string(self, text: str, max_length: int) -> str:
        """Truncate a string to a maximum length.

        Args:
            text: Text to truncate
            max_length: Maximum allowed length

        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text

        return text[:max_length - 3] + "..."


# Utility functions for GraphQL audit integration

async def audit_graphql_query(
    info: Info,
    result: ExecutionResult,
    audit_processor: GraphQLAuditProcessor,
    start_time: float,
    operation_name: Optional[str] = None,
    query: Optional[str] = None,
    variables: Optional[dict[str, Any]] = None,
) -> None:
    """Audit a GraphQL query operation.

    Args:
        info: GraphQL resolver info
        result: GraphQL execution result
        audit_processor: Audit processor instance
        start_time: When the operation started
        operation_name: Name of the operation
        query: GraphQL query string
        variables: GraphQL variables
    """
    await audit_processor.process_operation(
        info=info,
        result=result,
        start_time=start_time,
        operation_name=operation_name,
        operation_type="query",
        query=query,
        variables=variables,
    )


async def audit_graphql_mutation(
    info: Info,
    result: ExecutionResult,
    audit_processor: GraphQLAuditProcessor,
    start_time: float,
    operation_name: Optional[str] = None,
    query: Optional[str] = None,
    variables: Optional[dict[str, Any]] = None,
) -> None:
    """Audit a GraphQL mutation operation.

    Args:
        info: GraphQL resolver info
        result: GraphQL execution result
        audit_processor: Audit processor instance
        start_time: When the operation started
        operation_name: Name of the operation
        query: GraphQL query string
        variables: GraphQL variables
    """
    await audit_processor.process_operation(
        info=info,
        result=result,
        start_time=start_time,
        operation_name=operation_name,
        operation_type="mutation",
        query=query,
        variables=variables,
    )


async def audit_graphql_subscription(
    info: Info,
    result: ExecutionResult,
    audit_processor: GraphQLAuditProcessor,
    start_time: float,
    operation_name: Optional[str] = None,
    query: Optional[str] = None,
    variables: Optional[dict[str, Any]] = None,
) -> None:
    """Audit a GraphQL subscription operation.

    Args:
        info: GraphQL resolver info
        result: GraphQL execution result
        audit_processor: Audit processor instance
        start_time: When the operation started
        operation_name: Name of the operation
        query: GraphQL query string
        variables: GraphQL variables
    """
    await audit_processor.process_operation(
        info=info,
        result=result,
        start_time=start_time,
        operation_name=operation_name,
        operation_type="subscription",
        query=query,
        variables=variables,
    )
