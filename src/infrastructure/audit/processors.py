"""Audit Event Processors for Identity Module.

This module provides interfaces and implementations for processing
audit events, including domain events and API request/response logs.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from ...domain.events import DomainEvent
from .config import AuditConfig
from .event_store import AuditEvent, AuditEventStore

logger = logging.getLogger(__name__)


class AuditEventProcessor(ABC):
    """Abstract interface for audit event processing.

    Defines the contract for processing different types of audit events
    and storing them appropriately.
    """

    @abstractmethod
    async def process_domain_event(
        self,
        domain_event: DomainEvent,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Process a domain event for audit logging.

        Args:
            domain_event: The domain event to process
            user_id: ID of the user associated with this event
            session_id: Session ID associated with this event
            ip_address: IP address of the client
            user_agent: User agent of the client

        Returns:
            True if the event was processed successfully, False otherwise
        """
        pass

    @abstractmethod
    async def process_api_request(
        self,
        method: str,
        path: str,
        status_code: int,
        occurred_at: datetime,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_data: Optional[dict[str, Any]] = None,
        response_data: Optional[dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
        correlation_id: Optional[UUID] = None,
    ) -> bool:
        """Process an API request for audit logging.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            status_code: HTTP status code
            occurred_at: When the request occurred
            user_id: ID of the authenticated user
            session_id: Session ID
            ip_address: Client IP address
            user_agent: Client user agent
            request_data: Request payload data
            response_data: Response payload data
            duration_ms: Request duration in milliseconds
            correlation_id: Correlation ID for tracing

        Returns:
            True if the event was processed successfully, False otherwise
        """
        pass

    @abstractmethod
    async def process_graphql_operation(
        self,
        operation_name: Optional[str],
        operation_type: str,
        query: str,
        variables: Optional[dict[str, Any]],
        occurred_at: datetime,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        errors: Optional[list[dict[str, Any]]] = None,
        duration_ms: Optional[float] = None,
        correlation_id: Optional[UUID] = None,
    ) -> bool:
        """Process a GraphQL operation for audit logging.

        Args:
            operation_name: Name of the GraphQL operation
            operation_type: Type of operation (query, mutation, subscription)
            query: GraphQL query string
            variables: GraphQL variables
            occurred_at: When the operation occurred
            user_id: ID of the authenticated user
            session_id: Session ID
            ip_address: Client IP address
            user_agent: Client user agent
            errors: GraphQL errors if any
            duration_ms: Operation duration in milliseconds
            correlation_id: Correlation ID for tracing

        Returns:
            True if the event was processed successfully, False otherwise
        """
        pass


class DefaultAuditEventProcessor(AuditEventProcessor):
    """Default implementation of audit event processor.

    This processor handles the standard audit event processing workflow
    including data sanitization, event creation, and storage.
    """

    def __init__(
        self,
        event_store: AuditEventStore,
        config: AuditConfig,
    ) -> None:
        """Initialize the audit event processor.

        Args:
            event_store: Store for persisting audit events
            config: Audit configuration settings
        """
        self._event_store = event_store
        self._config = config

    async def process_domain_event(
        self,
        domain_event: DomainEvent,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Process a domain event for audit logging.

        Args:
            domain_event: The domain event to process
            user_id: ID of the user associated with this event
            session_id: Session ID associated with this event
            ip_address: IP address of the client
            user_agent: User agent of the client

        Returns:
            True if the event was processed successfully, False otherwise
        """
        if not self._config.enabled or not self._config.store_domain_events:
            return True

        try:
            # Create audit event from domain event
            audit_event = AuditEvent.from_domain_event(
                domain_event=domain_event,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            # Store the audit event
            success = await self._event_store.store_event(audit_event)

            if success:
                logger.debug(
                    f"Processed domain event audit: {domain_event.__class__.__name__} "
                    f"for user {user_id}"
                )
            else:
                logger.warning(
                    f"Failed to store domain event audit: {domain_event.__class__.__name__}"
                )

            return success

        except Exception as e:
            logger.error(f"Error processing domain event audit: {e}")
            return False

    async def process_api_request(
        self,
        method: str,
        path: str,
        status_code: int,
        occurred_at: datetime,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_data: Optional[dict[str, Any]] = None,
        response_data: Optional[dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
        correlation_id: Optional[UUID] = None,
    ) -> bool:
        """Process an API request for audit logging.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            status_code: HTTP status code
            occurred_at: When the request occurred
            user_id: ID of the authenticated user
            session_id: Session ID
            ip_address: Client IP address
            user_agent: Client user agent
            request_data: Request payload data
            response_data: Response payload data
            duration_ms: Request duration in milliseconds
            correlation_id: Correlation ID for tracing

        Returns:
            True if the event was processed successfully, False otherwise
        """
        if not self._config.enabled or not self._config.store_api_requests:
            return True

        # Check if path should be excluded
        if self._config.is_path_excluded(path):
            return True

        try:
            # Sanitize request and response data
            sanitized_request_data = self._sanitize_data(request_data) if request_data else None
            sanitized_response_data = self._sanitize_data(response_data) if response_data else None

            # Truncate large payloads
            sanitized_request_data = self._truncate_payload(sanitized_request_data)
            sanitized_response_data = self._truncate_payload(sanitized_response_data)

            # Create audit event from API request
            audit_event = AuditEvent.from_api_request(
                method=method,
                path=path,
                status_code=status_code,
                occurred_at=occurred_at,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_data=sanitized_request_data,
                response_data=sanitized_response_data,
                duration_ms=duration_ms,
                correlation_id=correlation_id,
            )

            # Store the audit event
            success = await self._event_store.store_event(audit_event)

            if success:
                logger.debug(
                    f"Processed API request audit: {method} {path} "
                    f"({status_code}) for user {user_id}"
                )
            else:
                logger.warning(
                    f"Failed to store API request audit: {method} {path}"
                )

            return success

        except Exception as e:
            logger.error(f"Error processing API request audit: {e}")
            return False

    async def process_graphql_operation(
        self,
        operation_name: Optional[str],
        operation_type: str,
        query: str,
        variables: Optional[dict[str, Any]],
        occurred_at: datetime,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        errors: Optional[list[dict[str, Any]]] = None,
        duration_ms: Optional[float] = None,
        correlation_id: Optional[UUID] = None,
    ) -> bool:
        """Process a GraphQL operation for audit logging.

        Args:
            operation_name: Name of the GraphQL operation
            operation_type: Type of operation (query, mutation, subscription)
            query: GraphQL query string
            variables: GraphQL variables
            occurred_at: When the operation occurred
            user_id: ID of the authenticated user
            session_id: Session ID
            ip_address: Client IP address
            user_agent: Client user agent
            errors: GraphQL errors if any
            duration_ms: Operation duration in milliseconds
            correlation_id: Correlation ID for tracing

        Returns:
            True if the event was processed successfully, False otherwise
        """
        if not self._config.enabled or not self._config.store_graphql_operations:
            return True

        try:
            # Sanitize variables and truncate query if needed
            sanitized_variables = self._sanitize_data(variables) if variables else None
            truncated_query = self._truncate_string(query, 2000)  # Limit query length

            # Create audit event from GraphQL operation
            audit_event = AuditEvent.from_graphql_operation(
                operation_name=operation_name,
                operation_type=operation_type,
                query=truncated_query,
                variables=sanitized_variables,
                occurred_at=occurred_at,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                errors=errors,
                duration_ms=duration_ms,
                correlation_id=correlation_id,
            )

            # Store the audit event
            success = await self._event_store.store_event(audit_event)

            if success:
                logger.debug(
                    f"Processed GraphQL operation audit: {operation_type} "
                    f"{operation_name or 'unnamed'} for user {user_id}"
                )
            else:
                logger.warning(
                    f"Failed to store GraphQL operation audit: {operation_name}"
                )

            return success

        except Exception as e:
            logger.error(f"Error processing GraphQL operation audit: {e}")
            return False

    def _sanitize_data(self, data: Any) -> Any:
        """Sanitize data by masking sensitive fields.

        Args:
            data: Data to sanitize

        Returns:
            Sanitized data with sensitive fields masked
        """
        if not self._config.mask_sensitive_data:
            return data

        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if self._config.should_mask_field(key):
                    sanitized[key] = "***MASKED***"
                else:
                    sanitized[key] = self._sanitize_data(value)
            return sanitized

        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]

        else:
            return data

    def _truncate_payload(self, data: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        """Truncate payload data if it exceeds the maximum size.

        Args:
            data: Payload data to check

        Returns:
            Truncated payload data or None if input was None
        """
        if data is None:
            return None

        # Convert to string to check size
        import json
        try:
            data_str = json.dumps(data, default=str)
            if len(data_str.encode('utf-8')) > self._config.max_payload_size:
                return {
                    "truncated": True,
                    "original_size": len(data_str.encode('utf-8')),
                    "max_size": self._config.max_payload_size,
                    "message": "Payload truncated due to size limit",
                }
        except (TypeError, ValueError):
            # If we can't serialize, just return a summary
            return {
                "truncated": True,
                "type": str(type(data)),
                "message": "Payload truncated - unable to serialize",
            }

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

    async def cleanup_expired_events(self) -> int:
        """Clean up expired audit events based on retention policy.

        Returns:
            Number of events cleaned up
        """
        if not self._config.retention_days:
            return 0

        try:
            from datetime import timedelta
            cutoff_time = datetime.utcnow() - timedelta(days=self._config.retention_days)
            deleted_count = await self._event_store.delete_events_older_than(cutoff_time)

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} expired audit events")

            return deleted_count

        except Exception as e:
            logger.error(f"Error cleaning up expired audit events: {e}")
            return 0
