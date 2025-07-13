"""Admin audit log REST API endpoints.

This module provides endpoints for viewing and managing audit logs,
security events, and system activity tracking.
"""

from datetime import datetime, timedelta
from typing import Annotated, Optional, Any

from fastapi import Depends, Query, Path
from pydantic import BaseModel, Field

from ..._base import (
    APIRouter,
    DataResponse,
    PaginatedResponse,
    ResponseMessages,
    get_pagination_params,
    PaginationParams,
)
from ...middleware.auth import require_admin


# Models for audit logs
class AuditLogEntry(BaseModel):
    """Audit log entry model."""
    
    id: str = Field(description="Unique audit log ID")
    timestamp: datetime = Field(description="Event timestamp")
    event_type: str = Field(description="Type of event")
    event_category: str = Field(description="Event category")
    severity: str = Field(description="Event severity", example="info")
    user_id: Optional[str] = Field(default=None, description="User who triggered the event")
    user_email: Optional[str] = Field(default=None, description="User email")
    resource_type: Optional[str] = Field(default=None, description="Type of resource affected")
    resource_id: Optional[str] = Field(default=None, description="ID of resource affected")
    action: str = Field(description="Action performed")
    result: str = Field(description="Result of the action", example="success")
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")
    session_id: Optional[str] = Field(default=None, description="Session ID")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional event details")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")


class SecurityEvent(BaseModel):
    """Security-specific event model."""
    
    id: str = Field(description="Event ID")
    timestamp: datetime = Field(description="Event timestamp")
    event_type: str = Field(description="Security event type")
    threat_level: str = Field(description="Threat level", example="medium")
    user_id: Optional[str] = Field(default=None, description="Affected user")
    ip_address: str = Field(description="Source IP address")
    location: Optional[str] = Field(default=None, description="Geolocation")
    description: str = Field(description="Event description")
    automated_response: Optional[str] = Field(default=None, description="Automated action taken")
    requires_review: bool = Field(description="Needs manual review")
    reviewed: bool = Field(default=False, description="Has been reviewed")
    reviewed_by: Optional[str] = Field(default=None, description="Reviewer user ID")
    reviewed_at: Optional[datetime] = Field(default=None, description="Review timestamp")


class AuditLogStats(BaseModel):
    """Audit log statistics."""
    
    total_events: int = Field(description="Total number of events")
    events_by_type: dict[str, int] = Field(description="Event count by type")
    events_by_severity: dict[str, int] = Field(description="Event count by severity")
    events_by_result: dict[str, int] = Field(description="Event count by result")
    events_by_hour: list[dict[str, Any]] = Field(description="Events per hour")
    top_users: list[dict[str, Any]] = Field(description="Most active users")
    top_resources: list[dict[str, Any]] = Field(description="Most accessed resources")


class AuditLogExport(BaseModel):
    """Audit log export request."""
    
    format: str = Field(description="Export format", example="csv")
    date_from: datetime = Field(description="Start date")
    date_to: datetime = Field(description="End date")
    event_types: Optional[list[str]] = Field(default=None, description="Filter by event types")
    include_details: bool = Field(default=True, description="Include detailed information")


# Create router
router = APIRouter(prefix="/api/admin/audit", tags=["admin-audit"])


@router.get(
    "/logs",
    response_model=PaginatedResponse[AuditLogEntry],
    summary="Get audit logs",
    description="Retrieve audit logs with filtering and pagination",
)
async def get_audit_logs(
    current_user: Annotated[dict, Depends(require_admin)],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    event_category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID"),
    result: Optional[str] = Query(None, description="Filter by result"),
    date_from: Optional[datetime] = Query(None, description="Start date"),
    date_to: Optional[datetime] = Query(None, description="End date"),
) -> PaginatedResponse[AuditLogEntry]:
    """Retrieve audit logs with comprehensive filtering."""
    # Mock data
    logs = [
        AuditLogEntry(
            id=f"audit_{i}",
            timestamp=datetime.utcnow(),
            event_type="user_login" if i % 3 == 0 else "user_update",
            event_category="authentication" if i % 3 == 0 else "user_management",
            severity="info" if i % 4 != 0 else "warning",
            user_id=f"user{i % 10}",
            user_email=f"user{i % 10}@example.com",
            resource_type="user" if i % 2 == 0 else "session",
            resource_id=f"res_{i}",
            action="login" if i % 3 == 0 else "update",
            result="success" if i % 5 != 0 else "failure",
            ip_address=f"192.168.1.{i % 255}",
            user_agent="Mozilla/5.0",
            session_id=f"session_{i}",
            details={"method": "password", "attempts": 1},
            error_message=None if i % 5 != 0 else "Invalid credentials",
        )
        for i in range(1, 201)
    ]
    
    # Apply filters
    if event_type:
        logs = [log for log in logs if log.event_type == event_type]
    if severity:
        logs = [log for log in logs if log.severity == severity]
    if user_id:
        logs = [log for log in logs if log.user_id == user_id]
    if result:
        logs = [log for log in logs if log.result == result]
    
    # Paginate
    total = len(logs)
    start = pagination.offset
    end = start + pagination.limit
    
    return PaginatedResponse.create(
        items=logs[start:end],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        message="Audit logs retrieved successfully",
    )


@router.get(
    "/logs/{log_id}",
    response_model=DataResponse[AuditLogEntry],
    summary="Get audit log details",
    description="Get detailed information about a specific audit log entry",
)
async def get_audit_log_details(
    log_id: str = Path(description="Audit log ID"),
    current_user: dict = Depends(require_admin),
) -> DataResponse[AuditLogEntry]:
    """Get detailed audit log entry."""
    log = AuditLogEntry(
        id=log_id,
        timestamp=datetime.utcnow(),
        event_type="user_login",
        event_category="authentication",
        severity="info",
        user_id="user123",
        user_email="user123@example.com",
        resource_type="session",
        resource_id="session_456",
        action="login",
        result="success",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        session_id="session_456",
        details={
            "method": "password",
            "mfa_used": True,
            "location": "San Francisco, CA",
            "device": "Chrome on macOS",
        },
        error_message=None,
    )
    
    return DataResponse(
        status="success",
        message="Audit log entry retrieved successfully",
        data=log,
    )


@router.get(
    "/security-events",
    response_model=PaginatedResponse[SecurityEvent],
    summary="Get security events",
    description="Retrieve security-specific events and threats",
)
async def get_security_events(
    current_user: Annotated[dict, Depends(require_admin)],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
    threat_level: Optional[str] = Query(None, description="Filter by threat level"),
    requires_review: Optional[bool] = Query(None, description="Filter by review requirement"),
    reviewed: Optional[bool] = Query(None, description="Filter by review status"),
) -> PaginatedResponse[SecurityEvent]:
    """Retrieve security events."""
    # Mock data
    events = [
        SecurityEvent(
            id=f"sec_{i}",
            timestamp=datetime.utcnow(),
            event_type="suspicious_login" if i % 3 == 0 else "brute_force_attempt",
            threat_level="high" if i % 5 == 0 else "medium",
            user_id=f"user{i % 20}" if i % 2 == 0 else None,
            ip_address=f"192.168.1.{i % 255}",
            location="Unknown" if i % 3 == 0 else "San Francisco, CA",
            description=f"Security event {i} description",
            automated_response="Account locked" if i % 5 == 0 else None,
            requires_review=i % 3 == 0,
            reviewed=i % 4 == 0,
            reviewed_by="admin1" if i % 4 == 0 else None,
            reviewed_at=datetime.utcnow() if i % 4 == 0 else None,
        )
        for i in range(1, 51)
    ]
    
    # Apply filters
    if threat_level:
        events = [e for e in events if e.threat_level == threat_level]
    if requires_review is not None:
        events = [e for e in events if e.requires_review == requires_review]
    if reviewed is not None:
        events = [e for e in events if e.reviewed == reviewed]
    
    # Paginate
    total = len(events)
    start = pagination.offset
    end = start + pagination.limit
    
    return PaginatedResponse.create(
        items=events[start:end],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        message="Security events retrieved successfully",
    )


@router.post(
    "/security-events/{event_id}/review",
    response_model=DataResponse[SecurityEvent],
    summary="Review security event",
    description="Mark a security event as reviewed",
)
async def review_security_event(
    event_id: str = Path(description="Security event ID"),
    notes: str = Query(..., description="Review notes"),
    action_taken: Optional[str] = Query(None, description="Action taken"),
    current_user: dict = Depends(require_admin),
) -> DataResponse[SecurityEvent]:
    """Review a security event."""
    event = SecurityEvent(
        id=event_id,
        timestamp=datetime.utcnow(),
        event_type="suspicious_login",
        threat_level="high",
        user_id="user123",
        ip_address="192.168.1.100",
        location="Unknown",
        description="Multiple failed login attempts from unknown location",
        automated_response="Account locked",
        requires_review=True,
        reviewed=True,
        reviewed_by=current_user["user_id"],
        reviewed_at=datetime.utcnow(),
    )
    
    return DataResponse(
        status="success",
        message="Security event reviewed successfully",
        data=event,
    )


@router.get(
    "/statistics",
    response_model=DataResponse[AuditLogStats],
    summary="Get audit log statistics",
    description="Get aggregated statistics from audit logs",
)
async def get_audit_statistics(
    current_user: Annotated[dict, Depends(require_admin)],
    date_from: datetime = Query(..., description="Start date"),
    date_to: datetime = Query(..., description="End date"),
) -> DataResponse[AuditLogStats]:
    """Get audit log statistics."""
    stats = AuditLogStats(
        total_events=15420,
        events_by_type={
            "user_login": 5230,
            "user_logout": 4920,
            "user_update": 2150,
            "password_change": 890,
            "mfa_setup": 340,
            "role_assignment": 1890,
        },
        events_by_severity={
            "info": 12340,
            "warning": 2450,
            "error": 630,
        },
        events_by_result={
            "success": 14250,
            "failure": 1170,
        },
        events_by_hour=[
            {"hour": i, "count": 100 + (i * 10 % 50)} for i in range(24)
        ],
        top_users=[
            {"user_id": f"user{i}", "email": f"user{i}@example.com", "event_count": 500 - i * 50}
            for i in range(1, 6)
        ],
        top_resources=[
            {"resource_type": "user", "access_count": 8500},
            {"resource_type": "session", "access_count": 6900},
            {"resource_type": "role", "access_count": 2100},
        ],
    )
    
    return DataResponse(
        status="success",
        message="Audit statistics retrieved successfully",
        data=stats,
    )


@router.post(
    "/export",
    response_model=DataResponse[dict],
    summary="Export audit logs",
    description="Export audit logs in specified format",
)
async def export_audit_logs(
    export_request: AuditLogExport,
    current_user: dict = Depends(require_admin),
) -> DataResponse[dict]:
    """Export audit logs."""
    # Validate export format
    valid_formats = ["csv", "json", "excel", "pdf"]
    if export_request.format not in valid_formats:
        from ..._base import ErrorCodes, create_error_response
        return create_error_response(
            status_code=400,
            error_code=ErrorCodes.INVALID_INPUT,
            message=f"Invalid export format: {export_request.format}",
        )
    
    # Mock export initiation
    export_data = {
        "export_id": "export_123",
        "format": export_request.format,
        "status": "processing",
        "estimated_size_mb": 25.5,
        "estimated_time_seconds": 45,
        "download_url": None,  # Will be populated when ready
    }
    
    return DataResponse(
        status="success",
        message="Audit log export initiated",
        data=export_data,
    )


@router.get(
    "/export/{export_id}/status",
    response_model=DataResponse[dict],
    summary="Get export status",
    description="Check the status of an audit log export",
)
async def get_export_status(
    export_id: str = Path(description="Export ID"),
    current_user: dict = Depends(require_admin),
) -> DataResponse[dict]:
    """Get audit log export status."""
    status_data = {
        "export_id": export_id,
        "format": "csv",
        "status": "completed",
        "progress": 100,
        "file_size_mb": 24.8,
        "download_url": f"/api/admin/audit/export/{export_id}/download",
        "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
    }
    
    return DataResponse(
        status="success",
        message="Export status retrieved",
        data=status_data,
    )


@router.delete(
    "/logs",
    response_model=DataResponse[dict],
    summary="Purge old audit logs",
    description="Delete audit logs older than specified date",
)
async def purge_audit_logs(
    older_than: datetime = Query(..., description="Delete logs older than this date"),
    dry_run: bool = Query(True, description="Preview without deleting"),
    current_user: dict = Depends(require_admin),
) -> DataResponse[dict]:
    """Purge old audit logs."""
    # Check super admin permission
    if not dry_run and "super_admin" not in current_user.get("roles", []):
        from ..._base import ErrorCodes, create_error_response
        return create_error_response(
            status_code=403,
            error_code=ErrorCodes.FORBIDDEN,
            message="Super admin permission required for purging logs",
        )
    
    result = {
        "older_than": older_than.isoformat(),
        "dry_run": dry_run,
        "logs_to_delete": 4520,
        "size_to_free_mb": 180.5,
        "status": "preview" if dry_run else "purged",
    }
    
    return DataResponse(
        status="success",
        message=f"Audit logs {'preview' if dry_run else 'purged'} successfully",
        data=result,
    )