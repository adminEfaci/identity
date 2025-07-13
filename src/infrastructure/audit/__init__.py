"""Audit Infrastructure for Identity Module.

This package provides audit event processing, storage, and configuration
capabilities for tracking user operations and API requests/responses.
"""

from .config import AuditConfig
from .event_store import AuditEventStore, InMemoryAuditEventStore
from .processors import AuditEventProcessor, DefaultAuditEventProcessor

__all__ = [
    "AuditConfig",
    "AuditEventStore",
    "InMemoryAuditEventStore",
    "AuditEventProcessor",
    "DefaultAuditEventProcessor",
]
