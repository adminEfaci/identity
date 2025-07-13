"""Admin dashboard REST API endpoints.

This module provides endpoints for the admin dashboard including
statistics, system health, recent activities, and overview data.
"""

from datetime import datetime, timedelta
from typing import Annotated, Any, Optional

from fastapi import Depends, Query
from pydantic import BaseModel, Field

from ..._base import (
    APIRouter,
    DataResponse,
    PaginatedResponse,
    ResponseMessages,
    get_pagination_params,
    PaginationParams,
)
from ...middleware.auth import require_auth, require_admin


# Models for dashboard data
class SystemStats(BaseModel):
    """System statistics model."""
    
    total_users: int = Field(description="Total number of users")
    active_users: int = Field(description="Number of active users")
    inactive_users: int = Field(description="Number of inactive users")
    users_with_mfa: int = Field(description="Users with MFA enabled")
    total_roles: int = Field(description="Total number of roles")
    total_permissions: int = Field(description="Total number of permissions")
    active_sessions: int = Field(description="Current active sessions")
    failed_login_attempts_24h: int = Field(description="Failed login attempts in last 24 hours")


class SystemHealth(BaseModel):
    """System health status model."""
    
    status: str = Field(description="Overall system status", example="healthy")
    database: dict[str, Any] = Field(description="Database health status")
    redis: dict[str, Any] = Field(description="Redis health status")
    rabbitmq: dict[str, Any] = Field(description="RabbitMQ health status")
    api_latency_ms: float = Field(description="Average API latency in milliseconds")
    error_rate: float = Field(description="Error rate percentage")
    uptime_seconds: int = Field(description="System uptime in seconds")


class ActivitySummary(BaseModel):
    """Recent activity summary."""
    
    timestamp: datetime = Field(description="Activity timestamp")
    activity_type: str = Field(description="Type of activity")
    user_id: str = Field(description="User who performed the activity")
    user_email: str = Field(description="User email")
    description: str = Field(description="Activity description")
    ip_address: Optional[str] = Field(default=None, description="IP address")
    status: str = Field(description="Activity status", example="success")


class UserGrowth(BaseModel):
    """User growth statistics."""
    
    date: str = Field(description="Date in YYYY-MM-DD format")
    new_users: int = Field(description="New users registered")
    active_users: int = Field(description="Active users on this date")
    total_users: int = Field(description="Total users by this date")


class DashboardOverview(BaseModel):
    """Complete dashboard overview."""
    
    stats: SystemStats = Field(description="System statistics")
    health: SystemHealth = Field(description="System health status")
    recent_activities: list[ActivitySummary] = Field(description="Recent activities")
    user_growth_7d: list[UserGrowth] = Field(description="User growth for last 7 days")
    alerts: list[dict[str, Any]] = Field(description="System alerts and warnings")


# Create router
router = APIRouter(prefix="/api/admin/dashboard", tags=["admin-dashboard"])


@router.get(
    "/overview",
    response_model=DataResponse[DashboardOverview],
    summary="Get dashboard overview",
    description="Get complete admin dashboard overview including stats, health, and activities",
)
async def get_dashboard_overview(
    current_user: Annotated[dict, Depends(require_admin)],
) -> DataResponse[DashboardOverview]:
    """Get complete dashboard overview data."""
    # Mock data for demonstration
    overview = DashboardOverview(
        stats=SystemStats(
            total_users=1250,
            active_users=1100,
            inactive_users=150,
            users_with_mfa=450,
            total_roles=15,
            total_permissions=75,
            active_sessions=234,
            failed_login_attempts_24h=12,
        ),
        health=SystemHealth(
            status="healthy",
            database={"status": "connected", "latency_ms": 2.5, "connections": 45},
            redis={"status": "connected", "latency_ms": 0.8, "memory_usage_mb": 125},
            rabbitmq={"status": "connected", "queued_messages": 15, "consumers": 8},
            api_latency_ms=25.4,
            error_rate=0.02,
            uptime_seconds=864000,
        ),
        recent_activities=[
            ActivitySummary(
                timestamp=datetime.utcnow() - timedelta(minutes=5),
                activity_type="user_login",
                user_id="user123",
                user_email="user@example.com",
                description="User logged in successfully",
                ip_address="192.168.1.100",
                status="success",
            ),
        ],
        user_growth_7d=[
            UserGrowth(
                date=(datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d"),
                new_users=10 + i * 2,
                active_users=1000 + i * 5,
                total_users=1200 + i * 10,
            )
            for i in range(7, -1, -1)
        ],
        alerts=[
            {
                "id": "alert1",
                "severity": "warning",
                "message": "High number of failed login attempts detected",
                "timestamp": datetime.utcnow().isoformat(),
            }
        ],
    )
    
    return DataResponse(
        status="success",
        message="Dashboard overview retrieved successfully",
        data=overview,
    )


@router.get(
    "/stats",
    response_model=DataResponse[SystemStats],
    summary="Get system statistics",
    description="Get current system statistics",
)
async def get_system_stats(
    current_user: Annotated[dict, Depends(require_admin)],
) -> DataResponse[SystemStats]:
    """Get system statistics."""
    stats = SystemStats(
        total_users=1250,
        active_users=1100,
        inactive_users=150,
        users_with_mfa=450,
        total_roles=15,
        total_permissions=75,
        active_sessions=234,
        failed_login_attempts_24h=12,
    )
    
    return DataResponse(
        status="success",
        message="System statistics retrieved successfully",
        data=stats,
    )


@router.get(
    "/health",
    response_model=DataResponse[SystemHealth],
    summary="Get system health",
    description="Get current system health status",
)
async def get_system_health(
    current_user: Annotated[dict, Depends(require_admin)],
) -> DataResponse[SystemHealth]:
    """Get system health status."""
    health = SystemHealth(
        status="healthy",
        database={"status": "connected", "latency_ms": 2.5, "connections": 45},
        redis={"status": "connected", "latency_ms": 0.8, "memory_usage_mb": 125},
        rabbitmq={"status": "connected", "queued_messages": 15, "consumers": 8},
        api_latency_ms=25.4,
        error_rate=0.02,
        uptime_seconds=864000,
    )
    
    return DataResponse(
        status="success",
        message="System health retrieved successfully",
        data=health,
    )


@router.get(
    "/activities",
    response_model=PaginatedResponse[ActivitySummary],
    summary="Get recent activities",
    description="Get paginated list of recent system activities",
)
async def get_recent_activities(
    current_user: Annotated[dict, Depends(require_admin)],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
    activity_type: Optional[str] = Query(None, description="Filter by activity type"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    date_from: Optional[datetime] = Query(None, description="Filter activities from date"),
    date_to: Optional[datetime] = Query(None, description="Filter activities to date"),
) -> PaginatedResponse[ActivitySummary]:
    """Get recent system activities with filtering."""
    # Mock data
    activities = [
        ActivitySummary(
            timestamp=datetime.utcnow() - timedelta(minutes=i * 5),
            activity_type="user_login" if i % 2 == 0 else "user_update",
            user_id=f"user{i}",
            user_email=f"user{i}@example.com",
            description=f"Activity {i} description",
            ip_address=f"192.168.1.{100 + i}",
            status="success" if i % 3 != 0 else "failed",
        )
        for i in range(50)
    ]
    
    # Apply filters
    if activity_type:
        activities = [a for a in activities if a.activity_type == activity_type]
    if user_id:
        activities = [a for a in activities if a.user_id == user_id]
    if date_from:
        activities = [a for a in activities if a.timestamp >= date_from]
    if date_to:
        activities = [a for a in activities if a.timestamp <= date_to]
    
    # Paginate
    total = len(activities)
    start = pagination.offset
    end = start + pagination.limit
    paginated_activities = activities[start:end]
    
    return PaginatedResponse.create(
        items=paginated_activities,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        message="Activities retrieved successfully",
    )


@router.get(
    "/user-growth",
    response_model=DataResponse[list[UserGrowth]],
    summary="Get user growth statistics",
    description="Get user growth statistics for specified period",
)
async def get_user_growth(
    current_user: Annotated[dict, Depends(require_admin)],
    days: int = Query(30, ge=1, le=365, description="Number of days to retrieve"),
) -> DataResponse[list[UserGrowth]]:
    """Get user growth statistics."""
    growth_data = [
        UserGrowth(
            date=(datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d"),
            new_users=10 + (i % 5) * 2,
            active_users=1000 + (i % 10) * 5,
            total_users=1200 + i * 2,
        )
        for i in range(days, -1, -1)
    ]
    
    return DataResponse(
        status="success",
        message=f"User growth data for {days} days retrieved successfully",
        data=growth_data,
    )


@router.post(
    "/alerts/dismiss/{alert_id}",
    response_model=DataResponse[dict],
    summary="Dismiss an alert",
    description="Dismiss a system alert",
)
async def dismiss_alert(
    alert_id: str,
    current_user: Annotated[dict, Depends(require_admin)],
) -> DataResponse[dict]:
    """Dismiss a system alert."""
    return DataResponse(
        status="success",
        message="Alert dismissed successfully",
        data={"alert_id": alert_id, "dismissed_at": datetime.utcnow().isoformat()},
    )


@router.get(
    "/export",
    summary="Export dashboard data",
    description="Export dashboard data in specified format",
)
async def export_dashboard_data(
    current_user: Annotated[dict, Depends(require_admin)],
    format: str = Query("csv", regex="^(csv|json|excel)$", description="Export format"),
    include_stats: bool = Query(True, description="Include statistics"),
    include_activities: bool = Query(True, description="Include activities"),
    include_growth: bool = Query(True, description="Include growth data"),
):
    """Export dashboard data."""
    # This would generate and return the actual file
    return DataResponse(
        status="success",
        message=f"Dashboard data export initiated in {format} format",
        data={
            "export_id": "export123",
            "format": format,
            "status": "processing",
            "estimated_time_seconds": 30,
        },
    )