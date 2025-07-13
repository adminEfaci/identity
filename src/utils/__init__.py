"""Utilities module for the identity service.

This module provides additional utility functions including:
- Error handling and exception management
- Data validation helpers
- General helper functions
"""

from .error_handling import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    ErrorCode,
    ErrorHandler,
    NotFoundError,
    RateLimitError,
    ServiceError,
    ValidationError,
    handle_exceptions,
)
from .helpers import CacheHelper, FileHelper, StringHelper, TimestampHelper, URLHelper
from .validation import (
    DataValidator,
    SchemaValidator,
    validate_json_schema,
    validate_model,
)

__all__ = [
    "ErrorHandler",
    "ErrorCode",
    "ServiceError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "handle_exceptions",
    "DataValidator",
    "SchemaValidator",
    "validate_json_schema",
    "validate_model",
    "TimestampHelper",
    "URLHelper",
    "StringHelper",
    "FileHelper",
    "CacheHelper",
]
