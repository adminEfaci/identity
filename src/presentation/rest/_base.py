"""Base classes and utilities for REST API standardization.

This module provides base classes, decorators, and utilities to ensure
consistent API responses, error handling, pagination, and other common
functionality across all REST endpoints.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Generic, Optional, TypeVar, Union

from fastapi import HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, validator

T = TypeVar("T")


class ResponseStatus(str, Enum):
    """Standard response status values."""
    
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"


class PaginationParams(BaseModel):
    """Standard pagination parameters."""
    
    page: int = Field(default=1, ge=1, description="Page number (1-based)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")
    sort_by: Optional[str] = Field(default=None, description="Field to sort by")
    sort_order: Optional[str] = Field(default="asc", regex="^(asc|desc)$", description="Sort order")
    
    @property
    def offset(self) -> int:
        """Calculate offset for database queries."""
        return (self.page - 1) * self.page_size
    
    @property
    def limit(self) -> int:
        """Get limit for database queries."""
        return self.page_size


class BaseResponse(BaseModel):
    """Base response model for all API responses."""
    
    status: ResponseStatus = Field(description="Response status")
    message: str = Field(description="Human-readable message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    request_id: Optional[str] = Field(default=None, description="Request tracking ID")


class DataResponse(BaseResponse, Generic[T]):
    """Response model with data payload."""
    
    status: ResponseStatus = ResponseStatus.SUCCESS
    data: T = Field(description="Response data")


class PaginatedResponse(DataResponse[list[T]], Generic[T]):
    """Response model for paginated data."""
    
    pagination: dict[str, Any] = Field(description="Pagination metadata")
    
    @classmethod
    def create(
        cls,
        items: list[T],
        total: int,
        page: int,
        page_size: int,
        message: str = "Data retrieved successfully",
        request_id: Optional[str] = None,
    ) -> "PaginatedResponse[T]":
        """Create a paginated response with metadata."""
        total_pages = (total + page_size - 1) // page_size
        
        return cls(
            status=ResponseStatus.SUCCESS,
            message=message,
            data=items,
            request_id=request_id,
            pagination={
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1,
            },
        )


class ErrorDetail(BaseModel):
    """Detailed error information."""
    
    field: Optional[str] = Field(default=None, description="Field that caused the error")
    code: str = Field(description="Error code")
    message: str = Field(description="Error message")


class ErrorResponse(BaseResponse):
    """Standard error response model."""
    
    status: ResponseStatus = ResponseStatus.ERROR
    error_code: str = Field(description="Machine-readable error code")
    errors: Optional[list[ErrorDetail]] = Field(default=None, description="Detailed errors")
    trace_id: Optional[str] = Field(default=None, description="Error trace ID for debugging")


class ValidationErrorResponse(ErrorResponse):
    """Response for validation errors."""
    
    error_code: str = "VALIDATION_ERROR"
    errors: list[ErrorDetail] = Field(description="Validation errors")


class AdminMetadata(BaseModel):
    """Metadata for admin operations."""
    
    performed_by: str = Field(description="User who performed the action")
    performed_at: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")


class AuditableResponse(DataResponse[T], Generic[T]):
    """Response model for auditable operations."""
    
    audit: AdminMetadata = Field(description="Audit metadata")


def create_error_response(
    status_code: int,
    error_code: str,
    message: str,
    errors: Optional[list[ErrorDetail]] = None,
    trace_id: Optional[str] = None,
) -> JSONResponse:
    """Create a standardized error response."""
    error_response = ErrorResponse(
        status=ResponseStatus.ERROR,
        message=message,
        error_code=error_code,
        errors=errors,
        trace_id=trace_id,
    )
    
    return JSONResponse(
        status_code=status_code,
        content=error_response.dict(exclude_none=True),
    )


def get_pagination_params(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    sort_by: Optional[str] = Query(None, description="Field to sort by"),
    sort_order: str = Query("asc", regex="^(asc|desc)$", description="Sort order"),
) -> PaginationParams:
    """Dependency to get pagination parameters."""
    return PaginationParams(
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def get_request_id(request: Request) -> Optional[str]:
    """Extract request ID from headers or generate one."""
    return request.headers.get("X-Request-ID")


def get_client_info(request: Request) -> dict[str, Optional[str]]:
    """Extract client information from request."""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("User-Agent"),
    }


class APIRouter:
    """Enhanced API router with standardized responses."""
    
    def __init__(self, *args, **kwargs):
        """Initialize router with standard error handlers."""
        from fastapi import APIRouter as FastAPIRouter
        
        self.router = FastAPIRouter(*args, **kwargs)
        self._setup_error_handlers()
    
    def _setup_error_handlers(self):
        """Setup standard error handlers."""
        
        @self.router.exception_handler(ValidationError)
        async def validation_error_handler(request: Request, exc: ValidationError):
            """Handle validation errors."""
            errors = [
                ErrorDetail(
                    field=error.get("loc", [""])[0],
                    code="INVALID_VALUE",
                    message=error.get("msg", "Validation error"),
                )
                for error in exc.errors()
            ]
            
            return create_error_response(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                error_code="VALIDATION_ERROR",
                message="Request validation failed",
                errors=errors,
            )
        
        @self.router.exception_handler(HTTPException)
        async def http_exception_handler(request: Request, exc: HTTPException):
            """Handle HTTP exceptions with standard format."""
            return create_error_response(
                status_code=exc.status_code,
                error_code=exc.detail.get("code", "HTTP_ERROR") if isinstance(exc.detail, dict) else "HTTP_ERROR",
                message=exc.detail.get("message", str(exc.detail)) if isinstance(exc.detail, dict) else str(exc.detail),
            )
    
    def __getattr__(self, name):
        """Delegate to underlying router."""
        return getattr(self.router, name)


class BaseService:
    """Base service class with common functionality."""
    
    def __init__(self, logger=None):
        """Initialize base service."""
        import logging
        
        self.logger = logger or logging.getLogger(self.__class__.__name__)
    
    async def log_operation(
        self,
        operation: str,
        user_id: str,
        details: dict[str, Any],
        success: bool = True,
    ):
        """Log an operation for audit purposes."""
        log_entry = {
            "operation": operation,
            "user_id": user_id,
            "details": details,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if success:
            self.logger.info(f"Operation completed: {operation}", extra=log_entry)
        else:
            self.logger.error(f"Operation failed: {operation}", extra=log_entry)


# Standard error codes
class ErrorCodes:
    """Standard error codes for the application."""
    
    # Authentication & Authorization
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    
    # Resource errors
    NOT_FOUND = "NOT_FOUND"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    CONFLICT = "CONFLICT"
    
    # Validation errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_FIELD = "MISSING_FIELD"
    
    # System errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    
    # Business logic errors
    OPERATION_FAILED = "OPERATION_FAILED"
    INVALID_STATE = "INVALID_STATE"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"


# Common response messages
class ResponseMessages:
    """Standard response messages."""
    
    # Success messages
    CREATED = "Resource created successfully"
    UPDATED = "Resource updated successfully"
    DELETED = "Resource deleted successfully"
    RETRIEVED = "Resource retrieved successfully"
    OPERATION_SUCCESS = "Operation completed successfully"
    
    # Error messages
    NOT_FOUND = "Resource not found"
    UNAUTHORIZED = "Authentication required"
    FORBIDDEN = "Insufficient permissions"
    VALIDATION_FAILED = "Request validation failed"
    INTERNAL_ERROR = "An internal error occurred"