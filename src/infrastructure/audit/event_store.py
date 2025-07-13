"""Audit Event Store for Identity Module.

This module provides interfaces and implementations for persisting
audit events, including domain events and API request/response logs.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4

from ...domain.events import DomainEvent

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditEvent:
    """Base audit event for all audit logging.

    This represents a processed audit event that can be stored
    and retrieved from the audit event store.
    """

    id: UUID
    """Unique identifier for this audit event"""

    event_type: str
    """Type of the audit event (e.g., 'domain_event', 'api_request')"""

    occurred_at: datetime
    """When the original event occurred"""

    recorded_at: datetime
    """When this audit event was recorded"""

    source: str
    """Source of the event (e.g., 'identity_module', 'rest_api')"""

    user_id: Optional[str] = None
    """ID of the user associated with this event"""

    session_id: Optional[str] = None
    """Session ID associated with this event"""

    ip_address: Optional[str] = None
    """IP address of the client that triggered this event"""

    user_agent: Optional[str] = None
    """User agent of the client that triggered this event"""

    correlation_id: Optional[UUID] = None
    """Correlation ID for tracing related events"""

    data: dict[str, Any] = None
    """Event-specific data"""

    def __post_init__(self) -> None:
        """Validate audit event."""
        if self.occurred_at > datetime.utcnow():
            raise ValueError("Occurred time cannot be in the future")

        if self.recorded_at < self.occurred_at:
            raise ValueError("Recorded time cannot be before occurred time")

    def to_dict(self) -> dict[str, Any]:
        """Convert audit event to dictionary representation.

        Returns:
            Dictionary representation of the audit event
        """
        result = asdict(self)

        # Convert UUID and datetime objects to strings for JSON serialization
        result["id"] = str(self.id)
        result["occurred_at"] = self.occurred_at.isoformat()
        result["recorded_at"] = self.recorded_at.isoformat()

        if self.correlation_id:
            result["correlation_id"] = str(self.correlation_id)

        return result

    @classmethod
    def from_domain_event(
        cls,
        domain_event: DomainEvent,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "AuditEvent":
        """Create audit event from domain event.

        Args:
            domain_event: The domain event to convert
            user_id: ID of the user associated with this event
            session_id: Session ID associated with this event
            ip_address: IP address of the client
            user_agent: User agent of the client

        Returns:
            Audit event representing the domain event
        """
        return cls(
            id=uuid4(),
            event_type="domain_event",
            occurred_at=domain_event.occurred_at,
            recorded_at=datetime.utcnow(),
            source="identity_module",
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            correlation_id=domain_event.correlation_id,
            data={
                "domain_event_type": domain_event.__class__.__name__,
                "aggregate_id": str(domain_event.aggregate_id),
                "event_version": domain_event.event_version,
                "causation_id": str(domain_event.causation_id) if domain_event.causation_id else None,
                "event_data": domain_event.to_dict(),
            },
        )

    @classmethod
    def from_api_request(
        cls,
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
    ) -> "AuditEvent":
        """Create audit event from API request.

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
            Audit event representing the API request
        """
        return cls(
            id=uuid4(),
            event_type="api_request",
            occurred_at=occurred_at,
            recorded_at=datetime.utcnow(),
            source="rest_api",
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            correlation_id=correlation_id,
            data={
                "method": method,
                "path": path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "request_data": request_data,
                "response_data": response_data,
            },
        )

    @classmethod
    def from_graphql_operation(
        cls,
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
    ) -> "AuditEvent":
        """Create audit event from GraphQL operation.

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
            Audit event representing the GraphQL operation
        """
        return cls(
            id=uuid4(),
            event_type="graphql_operation",
            occurred_at=occurred_at,
            recorded_at=datetime.utcnow(),
            source="graphql_api",
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            correlation_id=correlation_id,
            data={
                "operation_name": operation_name,
                "operation_type": operation_type,
                "query": query,
                "variables": variables,
                "errors": errors,
                "duration_ms": duration_ms,
            },
        )


class AuditEventStore(ABC):
    """Abstract interface for audit event storage.

    Defines the contract for storing and retrieving audit events
    from persistent storage.
    """

    @abstractmethod
    async def store_event(self, event: AuditEvent) -> bool:
        """Store an audit event.

        Args:
            event: The audit event to store

        Returns:
            True if the event was stored successfully, False otherwise
        """
        pass

    @abstractmethod
    async def store_events(self, events: list[AuditEvent]) -> int:
        """Store multiple audit events in a batch.

        Args:
            events: List of audit events to store

        Returns:
            Number of events successfully stored
        """
        pass

    @abstractmethod
    async def get_event(self, event_id: UUID) -> Optional[AuditEvent]:
        """Retrieve an audit event by ID.

        Args:
            event_id: ID of the event to retrieve

        Returns:
            The audit event if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_events_by_user(
        self,
        user_id: str,
        limit: int = 100,
        offset: int = 0,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[AuditEvent]:
        """Retrieve audit events for a specific user.

        Args:
            user_id: ID of the user
            limit: Maximum number of events to return
            offset: Number of events to skip
            start_time: Start of time range filter
            end_time: End of time range filter

        Returns:
            List of audit events for the user
        """
        pass

    @abstractmethod
    async def get_events_by_correlation_id(
        self, correlation_id: UUID
    ) -> list[AuditEvent]:
        """Retrieve audit events by correlation ID.

        Args:
            correlation_id: Correlation ID to search for

        Returns:
            List of audit events with the given correlation ID
        """
        pass

    @abstractmethod
    async def delete_events_older_than(self, cutoff_time: datetime) -> int:
        """Delete audit events older than the specified time.

        Args:
            cutoff_time: Events older than this time will be deleted

        Returns:
            Number of events deleted
        """
        pass


class InMemoryAuditEventStore(AuditEventStore):
    """In-memory implementation of audit event store.

    This implementation stores audit events in memory and is suitable
    for testing and development environments. Events are not persisted
    across application restarts.
    """

    def __init__(self) -> None:
        """Initialize the in-memory audit event store."""
        self._events: dict[UUID, AuditEvent] = {}
        self._events_by_user: dict[str, list[AuditEvent]] = {}
        self._events_by_correlation: dict[UUID, list[AuditEvent]] = {}

    async def store_event(self, event: AuditEvent) -> bool:
        """Store an audit event in memory.

        Args:
            event: The audit event to store

        Returns:
            True if the event was stored successfully
        """
        try:
            self._events[event.id] = event

            # Index by user ID if available
            if event.user_id:
                if event.user_id not in self._events_by_user:
                    self._events_by_user[event.user_id] = []
                self._events_by_user[event.user_id].append(event)

            # Index by correlation ID if available
            if event.correlation_id:
                if event.correlation_id not in self._events_by_correlation:
                    self._events_by_correlation[event.correlation_id] = []
                self._events_by_correlation[event.correlation_id].append(event)

            logger.debug(f"Stored audit event {event.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to store audit event {event.id}: {e}")
            return False

    async def store_events(self, events: list[AuditEvent]) -> int:
        """Store multiple audit events in memory.

        Args:
            events: List of audit events to store

        Returns:
            Number of events successfully stored
        """
        stored_count = 0
        for event in events:
            if await self.store_event(event):
                stored_count += 1
        return stored_count

    async def get_event(self, event_id: UUID) -> Optional[AuditEvent]:
        """Retrieve an audit event by ID.

        Args:
            event_id: ID of the event to retrieve

        Returns:
            The audit event if found, None otherwise
        """
        return self._events.get(event_id)

    async def get_events_by_user(
        self,
        user_id: str,
        limit: int = 100,
        offset: int = 0,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[AuditEvent]:
        """Retrieve audit events for a specific user.

        Args:
            user_id: ID of the user
            limit: Maximum number of events to return
            offset: Number of events to skip
            start_time: Start of time range filter
            end_time: End of time range filter

        Returns:
            List of audit events for the user
        """
        events = self._events_by_user.get(user_id, [])

        # Apply time filters
        if start_time or end_time:
            filtered_events = []
            for event in events:
                if start_time and event.occurred_at < start_time:
                    continue
                if end_time and event.occurred_at > end_time:
                    continue
                filtered_events.append(event)
            events = filtered_events

        # Sort by occurred_at descending (newest first)
        events.sort(key=lambda e: e.occurred_at, reverse=True)

        # Apply pagination
        return events[offset:offset + limit]

    async def get_events_by_correlation_id(
        self, correlation_id: UUID
    ) -> list[AuditEvent]:
        """Retrieve audit events by correlation ID.

        Args:
            correlation_id: Correlation ID to search for

        Returns:
            List of audit events with the given correlation ID
        """
        events = self._events_by_correlation.get(correlation_id, [])
        # Sort by occurred_at ascending (chronological order)
        return sorted(events, key=lambda e: e.occurred_at)

    async def delete_events_older_than(self, cutoff_time: datetime) -> int:
        """Delete audit events older than the specified time.

        Args:
            cutoff_time: Events older than this time will be deleted

        Returns:
            Number of events deleted
        """
        events_to_delete = [
            event_id for event_id, event in self._events.items()
            if event.occurred_at < cutoff_time
        ]

        for event_id in events_to_delete:
            event = self._events[event_id]

            # Remove from main storage
            del self._events[event_id]

            # Remove from user index
            if event.user_id and event.user_id in self._events_by_user:
                self._events_by_user[event.user_id] = [
                    e for e in self._events_by_user[event.user_id]
                    if e.id != event_id
                ]
                if not self._events_by_user[event.user_id]:
                    del self._events_by_user[event.user_id]

            # Remove from correlation index
            if event.correlation_id and event.correlation_id in self._events_by_correlation:
                self._events_by_correlation[event.correlation_id] = [
                    e for e in self._events_by_correlation[event.correlation_id]
                    if e.id != event_id
                ]
                if not self._events_by_correlation[event.correlation_id]:
                    del self._events_by_correlation[event.correlation_id]

        logger.info(f"Deleted {len(events_to_delete)} audit events older than {cutoff_time}")
        return len(events_to_delete)

    def get_total_events(self) -> int:
        """Get the total number of stored events.

        Returns:
            Total number of events in storage
        """
        return len(self._events)

    def clear_all_events(self) -> None:
        """Clear all stored events (for testing purposes)."""
        self._events.clear()
        self._events_by_user.clear()
        self._events_by_correlation.clear()
