"""Error handling utilities for the identity service."""

import functools
import traceback
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field

from core.logging import get_logger

logger = get_logger(__name__)


class ErrorCode(str, Enum):
    """Standard error codes for the identity service."""

    # Authentication errors
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    MFA_REQUIRED = "MFA_REQUIRED"
    MFA_INVALID = "MFA_INVALID"

    # Authorization errors
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    ROLE_REQUIRED = "ROLE_REQUIRED"
    ACCESS_DENIED = "ACCESS_DENIED"

    # Validation errors
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_FORMAT = "INVALID_FORMAT"
    VALUE_TOO_LONG = "VALUE_TOO_LONG"
    VALUE_TOO_SHORT = "VALUE_TOO_SHORT"

    # Resource errors
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_ALREADY_EXISTS = "RESOURCE_ALREADY_EXISTS"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"

    # Rate limiting
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"

    # System errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    DATABASE_ERROR = "DATABASE_ERROR"
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"


class ErrorDetail(BaseModel):
    """Detailed error information."""

    code: ErrorCode = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    field: Optional[str] = Field(None, description="Field that caused the error")
    value: Optional[Any] = Field(None, description="Invalid value")
    context: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class ServiceError(Exception):
    """Base service error with structured information."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        status_code: int = 500,
        details: Optional[list[ErrorDetail]] = None,
        context: Optional[dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """Initialize service error.

        Args:
            message: Error message
            code: Error code
            status_code: HTTP status code
            details: List of error details
            context: Additional context
            cause: Original exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or []
        self.context = context or {}
        self.cause = cause
        self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert error to dictionary."""
        return {
            "error": {
                "code": self.code.value,
                "message": self.message,
                "status_code": self.status_code,
                "details": [detail.dict() for detail in self.details],
                "context": self.context,
                "timestamp": self.timestamp.isoformat()
            }
        }

    def add_detail(self, detail: ErrorDetail) -> None:
        """Add error detail."""
        self.details.append(detail)

    def add_context(self, key: str, value: Any) -> None:
        """Add context information."""
        self.context[key] = value


class ValidationError(ServiceError):
    """Validation error."""

    def __init__(
        self,
        message: str = "Validation failed",
        field: Optional[str] = None,
        value: Optional[Any] = None,
        details: Optional[list[ErrorDetail]] = None,
        context: Optional[dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            code=ErrorCode.INVALID_INPUT,
            status_code=400,
            details=details,
            context=context
        )

        if field:
            self.add_detail(ErrorDetail(
                code=ErrorCode.INVALID_INPUT,
                message=message,
                field=field,
                value=value
            ))


class AuthenticationError(ServiceError):
    """Authentication error."""

    def __init__(
        self,
        message: str = "Authentication failed",
        code: ErrorCode = ErrorCode.INVALID_CREDENTIALS,
        details: Optional[list[ErrorDetail]] = None,
        context: Optional[dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=401,
            details=details,
            context=context
        )


class AuthorizationError(ServiceError):
    """Authorization error."""

    def __init__(
        self,
        message: str = "Access denied",
        code: ErrorCode = ErrorCode.ACCESS_DENIED,
        details: Optional[list[ErrorDetail]] = None,
        context: Optional[dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=403,
            details=details,
            context=context
        )


class NotFoundError(ServiceError):
    """Resource not found error."""

    def __init__(
        self,
        message: str = "Resource not found",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        context: Optional[dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            code=ErrorCode.RESOURCE_NOT_FOUND,
            status_code=404,
            context=context
        )

        if resource_type:
            self.add_context("resource_type", resource_type)
        if resource_id:
            self.add_context("resource_id", resource_id)


class ConflictError(ServiceError):
    """Resource conflict error."""

    def __init__(
        self,
        message: str = "Resource conflict",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        context: Optional[dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            code=ErrorCode.RESOURCE_CONFLICT,
            status_code=409,
            context=context
        )

        if resource_type:
            self.add_context("resource_type", resource_type)
        if resource_id:
            self.add_context("resource_id", resource_id)


class RateLimitError(ServiceError):
    """Rate limit exceeded error."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        context: Optional[dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            code=ErrorCode.RATE_LIMIT_EXCEEDED,
            status_code=429,
            context=context
        )

        if retry_after:
            self.add_context("retry_after", retry_after)
        if limit:
            self.add_context("limit", limit)
        if window:
            self.add_context("window", window)


class ErrorHandler:
    """Centralized error handling and logging."""

    def __init__(self, include_stack_trace: bool = False):
        """Initialize error handler.

        Args:
            include_stack_trace: Whether to include stack traces in error logs
        """
        self.include_stack_trace = include_stack_trace

    def handle_error(
        self,
        error: Exception,
        context: Optional[dict[str, Any]] = None,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> ServiceError:
        """Handle and log an error.

        Args:
            error: Exception to handle
            context: Additional context
            user_id: User ID for logging
            request_id: Request ID for logging

        Returns:
            ServiceError instance
        """
        # If it's already a ServiceError, just log and return
        if isinstance(error, ServiceError):
            self._log_service_error(error, user_id, request_id)
            return error

        # Convert other exceptions to ServiceError
        service_error = self._convert_to_service_error(error, context)
        self._log_service_error(service_error, user_id, request_id)

        return service_error

    def _convert_to_service_error(
        self,
        error: Exception,
        context: Optional[dict[str, Any]] = None
    ) -> ServiceError:
        """Convert exception to ServiceError."""
        error_message = str(error)
        error_context = context or {}

        # Add original exception type to context
        error_context["original_exception"] = type(error).__name__

        # Map common exceptions to appropriate ServiceErrors
        if isinstance(error, ValueError):
            return ValidationError(
                message=error_message,
                context=error_context
            )
        elif isinstance(error, PermissionError):
            return AuthorizationError(
                message=error_message,
                context=error_context
            )
        elif isinstance(error, FileNotFoundError):
            return NotFoundError(
                message=error_message,
                context=error_context
            )
        else:
            return ServiceError(
                message=error_message,
                code=ErrorCode.INTERNAL_ERROR,
                context=error_context,
                cause=error
            )

    def _log_service_error(
        self,
        error: ServiceError,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> None:
        """Log service error."""
        log_data = {
            "error_code": error.code.value,
            "status_code": error.status_code,
            "error_message": error.message,
            "error_context": error.context,
            "error_details_count": len(error.details)
        }

        if self.include_stack_trace and error.cause:
            log_data["stack_trace"] = traceback.format_exception(
                type(error.cause), error.cause, error.cause.__traceback__
            )

        # Log at appropriate level based on status code
        if error.status_code >= 500:
            logger.error(
                f"Service error: {error.message}",
                user_id=user_id,
                request_id=request_id,
                **log_data
            )
        elif error.status_code >= 400:
            logger.warning(
                f"Client error: {error.message}",
                user_id=user_id,
                request_id=request_id,
                **log_data
            )
        else:
            logger.info(
                f"Error handled: {error.message}",
                user_id=user_id,
                request_id=request_id,
                **log_data
            )


def handle_exceptions(
    error_handler: Optional[ErrorHandler] = None,
    reraise: bool = False,
    default_error: Optional[ServiceError] = None
):
    """Decorator to handle exceptions in functions.

    Args:
        error_handler: Error handler instance
        reraise: Whether to reraise the exception after handling
        default_error: Default error to return if handling fails

    Returns:
        Decorator function
    """
    if error_handler is None:
        error_handler = ErrorHandler()

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                service_error = error_handler.handle_error(e)

                if reraise:
                    raise service_error from e

                return default_error or service_error

        return wrapper
    return decorator


def create_validation_error(
    message: str,
    field: Optional[str] = None,
    value: Optional[Any] = None,
    code: ErrorCode = ErrorCode.INVALID_INPUT
) -> ValidationError:
    """Create a validation error with details.

    Args:
        message: Error message
        field: Field name that failed validation
        value: Invalid value
        code: Error code

    Returns:
        ValidationError instance
    """
    detail = ErrorDetail(
        code=code,
        message=message,
        field=field,
        value=value
    )

    return ValidationError(
        message=message,
        details=[detail]
    )


def create_multiple_validation_errors(
    errors: list[dict[str, Any]]
) -> ValidationError:
    """Create validation error with multiple details.

    Args:
        errors: List of error dictionaries

    Returns:
        ValidationError with multiple details
    """
    details = []

    for error_data in errors:
        detail = ErrorDetail(
            code=ErrorCode(error_data.get("code", ErrorCode.INVALID_INPUT)),
            message=error_data["message"],
            field=error_data.get("field"),
            value=error_data.get("value")
        )
        details.append(detail)

    return ValidationError(
        message=f"Validation failed with {len(details)} errors",
        details=details
    )
