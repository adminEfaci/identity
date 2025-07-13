"""Admin system management REST API endpoints.

This module provides endpoints for system configuration, feature flags,
maintenance mode, backups, and other system-level administrative functions.
"""

from datetime import datetime, timedelta
from typing import Annotated, Optional, Any

from fastapi import Depends, Query, Body, Path
from pydantic import BaseModel, Field

from ..._base import (
    APIRouter,
    DataResponse,
    PaginatedResponse,
    ResponseMessages,
    AuditableResponse,
    AdminMetadata,
    ErrorCodes,
    create_error_response,
)
from ...middleware.auth import require_admin


# Models for system management
class SystemConfiguration(BaseModel):
    """System configuration model."""
    
    id: str = Field(description="Configuration ID")
    category: str = Field(description="Configuration category")
    key: str = Field(description="Configuration key")
    value: Any = Field(description="Configuration value")
    type: str = Field(description="Value type", example="string")
    description: str = Field(description="Configuration description")
    default_value: Any = Field(description="Default value")
    is_sensitive: bool = Field(description="Contains sensitive data")
    is_editable: bool = Field(description="Can be edited")
    last_modified: datetime = Field(description="Last modification timestamp")
    modified_by: Optional[str] = Field(default=None, description="Last modified by user")


class FeatureFlag(BaseModel):
    """Feature flag model."""
    
    id: str = Field(description="Feature flag ID")
    name: str = Field(description="Feature name")
    description: str = Field(description="Feature description")
    enabled: bool = Field(description="Feature enabled status")
    rollout_percentage: int = Field(description="Rollout percentage (0-100)")
    target_users: list[str] = Field(default_factory=list, description="Specific users")
    target_roles: list[str] = Field(default_factory=list, description="Target roles")
    conditions: dict[str, Any] = Field(default_factory=dict, description="Additional conditions")
    created_at: datetime = Field(description="Creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")


class MaintenanceMode(BaseModel):
    """Maintenance mode configuration."""
    
    enabled: bool = Field(description="Maintenance mode enabled")
    message: str = Field(description="Maintenance message")
    start_time: Optional[datetime] = Field(default=None, description="Maintenance start time")
    end_time: Optional[datetime] = Field(default=None, description="Estimated end time")
    allowed_ips: list[str] = Field(default_factory=list, description="IPs allowed during maintenance")
    allowed_users: list[str] = Field(default_factory=list, description="Users allowed during maintenance")


class BackupInfo(BaseModel):
    """Backup information model."""
    
    id: str = Field(description="Backup ID")
    type: str = Field(description="Backup type", example="full")
    status: str = Field(description="Backup status", example="completed")
    size_mb: float = Field(description="Backup size in MB")
    created_at: datetime = Field(description="Backup creation time")
    completed_at: Optional[datetime] = Field(default=None, description="Completion time")
    location: str = Field(description="Backup storage location")
    retention_days: int = Field(description="Retention period in days")
    includes: list[str] = Field(description="What's included in backup")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class SystemNotification(BaseModel):
    """System-wide notification model."""
    
    id: str = Field(description="Notification ID")
    type: str = Field(description="Notification type", example="info")
    title: str = Field(description="Notification title")
    message: str = Field(description="Notification message")
    active: bool = Field(description="Is notification active")
    priority: int = Field(description="Display priority")
    target_roles: list[str] = Field(default_factory=list, description="Target roles")
    dismissible: bool = Field(description="Can be dismissed by users")
    start_time: datetime = Field(description="Display start time")
    end_time: Optional[datetime] = Field(default=None, description="Display end time")


class CacheManagement(BaseModel):
    """Cache management information."""
    
    cache_type: str = Field(description="Cache type", example="redis")
    total_keys: int = Field(description="Total number of keys")
    memory_used_mb: float = Field(description="Memory used in MB")
    hit_rate: float = Field(description="Cache hit rate percentage")
    last_flush: Optional[datetime] = Field(default=None, description="Last cache flush time")
    patterns: list[dict[str, Any]] = Field(description="Key patterns and counts")


# Create router
router = APIRouter(prefix="/api/admin/system", tags=["admin-system"])


@router.get(
    "/configuration",
    response_model=PaginatedResponse[SystemConfiguration],
    summary="Get system configurations",
    description="Retrieve system configuration settings",
)
async def get_system_configurations(
    current_user: Annotated[dict, Depends(require_admin)],
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search in key/description"),
    show_sensitive: bool = Query(False, description="Include sensitive values"),
) -> PaginatedResponse[SystemConfiguration]:
    """Get system configuration settings."""
    # Mock configurations
    configs = [
        SystemConfiguration(
            id="config_1",
            category="security",
            key="password_min_length",
            value=12,
            type="integer",
            description="Minimum password length",
            default_value=8,
            is_sensitive=False,
            is_editable=True,
            last_modified=datetime.utcnow(),
            modified_by="admin1",
        ),
        SystemConfiguration(
            id="config_2",
            category="security",
            key="mfa_required",
            value=False,
            type="boolean",
            description="Require MFA for all users",
            default_value=False,
            is_sensitive=False,
            is_editable=True,
            last_modified=datetime.utcnow(),
            modified_by="admin1",
        ),
        SystemConfiguration(
            id="config_3",
            category="email",
            key="smtp_host",
            value="***" if not show_sensitive else "smtp.example.com",
            type="string",
            description="SMTP server host",
            default_value="localhost",
            is_sensitive=True,
            is_editable=True,
            last_modified=datetime.utcnow(),
            modified_by="admin2",
        ),
    ]
    
    # Apply filters
    if category:
        configs = [c for c in configs if c.category == category]
    if search:
        configs = [
            c for c in configs
            if search.lower() in c.key.lower() or search.lower() in c.description.lower()
        ]
    
    return PaginatedResponse.create(
        items=configs,
        total=len(configs),
        page=1,
        page_size=20,
        message="Configurations retrieved successfully",
    )


@router.put(
    "/configuration/{config_id}",
    response_model=AuditableResponse[SystemConfiguration],
    summary="Update system configuration",
    description="Update a system configuration value",
)
async def update_configuration(
    config_id: str = Path(description="Configuration ID"),
    value: Any = Body(..., description="New configuration value"),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[SystemConfiguration]:
    """Update system configuration."""
    # Mock update
    config = SystemConfiguration(
        id=config_id,
        category="security",
        key="password_min_length",
        value=value,
        type="integer",
        description="Minimum password length",
        default_value=8,
        is_sensitive=False,
        is_editable=True,
        last_modified=datetime.utcnow(),
        modified_by=current_user["user_id"],
    )
    
    return AuditableResponse(
        status="success",
        message="Configuration updated successfully",
        data=config,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.get(
    "/feature-flags",
    response_model=DataResponse[list[FeatureFlag]],
    summary="Get feature flags",
    description="Retrieve all feature flags",
)
async def get_feature_flags(
    current_user: Annotated[dict, Depends(require_admin)],
) -> DataResponse[list[FeatureFlag]]:
    """Get all feature flags."""
    flags = [
        FeatureFlag(
            id="flag_1",
            name="new_dashboard",
            description="Enable new admin dashboard UI",
            enabled=True,
            rollout_percentage=100,
            target_users=[],
            target_roles=["admin"],
            conditions={},
            created_at=datetime.utcnow() - timedelta(days=30),
            updated_at=datetime.utcnow(),
        ),
        FeatureFlag(
            id="flag_2",
            name="advanced_mfa",
            description="Enable advanced MFA options",
            enabled=True,
            rollout_percentage=50,
            target_users=["user123", "user456"],
            target_roles=[],
            conditions={"min_account_age_days": 30},
            created_at=datetime.utcnow() - timedelta(days=15),
            updated_at=datetime.utcnow(),
        ),
    ]
    
    return DataResponse(
        status="success",
        message="Feature flags retrieved successfully",
        data=flags,
    )


@router.put(
    "/feature-flags/{flag_id}",
    response_model=AuditableResponse[FeatureFlag],
    summary="Update feature flag",
    description="Update a feature flag configuration",
)
async def update_feature_flag(
    flag_id: str = Path(description="Feature flag ID"),
    flag_update: FeatureFlag = Body(...),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[FeatureFlag]:
    """Update feature flag."""
    flag_update.id = flag_id
    flag_update.updated_at = datetime.utcnow()
    
    return AuditableResponse(
        status="success",
        message="Feature flag updated successfully",
        data=flag_update,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.get(
    "/maintenance",
    response_model=DataResponse[MaintenanceMode],
    summary="Get maintenance mode status",
    description="Get current maintenance mode configuration",
)
async def get_maintenance_mode(
    current_user: Annotated[dict, Depends(require_admin)],
) -> DataResponse[MaintenanceMode]:
    """Get maintenance mode status."""
    maintenance = MaintenanceMode(
        enabled=False,
        message="System is under maintenance. Please try again later.",
        start_time=None,
        end_time=None,
        allowed_ips=["192.168.1.0/24"],
        allowed_users=["admin1", "admin2"],
    )
    
    return DataResponse(
        status="success",
        message="Maintenance mode status retrieved",
        data=maintenance,
    )


@router.put(
    "/maintenance",
    response_model=AuditableResponse[MaintenanceMode],
    summary="Update maintenance mode",
    description="Enable or disable maintenance mode",
)
async def update_maintenance_mode(
    maintenance_config: MaintenanceMode = Body(...),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[MaintenanceMode]:
    """Update maintenance mode."""
    return AuditableResponse(
        status="success",
        message=f"Maintenance mode {'enabled' if maintenance_config.enabled else 'disabled'}",
        data=maintenance_config,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.get(
    "/backups",
    response_model=PaginatedResponse[BackupInfo],
    summary="Get system backups",
    description="Retrieve list of system backups",
)
async def get_system_backups(
    current_user: Annotated[dict, Depends(require_admin)],
    backup_type: Optional[str] = Query(None, description="Filter by backup type"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> PaginatedResponse[BackupInfo]:
    """Get system backups."""
    backups = [
        BackupInfo(
            id=f"backup_{i}",
            type="full" if i % 3 == 0 else "incremental",
            status="completed",
            size_mb=1024.5 * (i % 5 + 1),
            created_at=datetime.utcnow() - timedelta(days=i),
            completed_at=datetime.utcnow() - timedelta(days=i, hours=-1),
            location="s3://backups/identity-module/",
            retention_days=30,
            includes=["database", "configurations", "audit_logs"],
            metadata={"compressed": True, "encrypted": True},
        )
        for i in range(1, 11)
    ]
    
    return PaginatedResponse.create(
        items=backups,
        total=len(backups),
        page=1,
        page_size=20,
        message="Backups retrieved successfully",
    )


@router.post(
    "/backups",
    response_model=DataResponse[BackupInfo],
    summary="Create system backup",
    description="Initiate a new system backup",
)
async def create_backup(
    backup_type: str = Query("full", regex="^(full|incremental|config)$"),
    include_audit_logs: bool = Query(True),
    current_user: dict = Depends(require_admin),
) -> DataResponse[BackupInfo]:
    """Create a new backup."""
    backup = BackupInfo(
        id="backup_new",
        type=backup_type,
        status="in_progress",
        size_mb=0,
        created_at=datetime.utcnow(),
        completed_at=None,
        location="s3://backups/identity-module/",
        retention_days=30,
        includes=["database", "configurations"] + (["audit_logs"] if include_audit_logs else []),
        metadata={"initiated_by": current_user["user_id"]},
    )
    
    return DataResponse(
        status="success",
        message="Backup initiated successfully",
        data=backup,
    )


@router.post(
    "/backups/{backup_id}/restore",
    response_model=AuditableResponse[dict],
    summary="Restore from backup",
    description="Restore system from a backup",
)
async def restore_backup(
    backup_id: str = Path(description="Backup ID"),
    confirm: bool = Query(False, description="Confirm restore operation"),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[dict]:
    """Restore from backup."""
    if not confirm:
        return create_error_response(
            status_code=400,
            error_code=ErrorCodes.INVALID_INPUT,
            message="Confirmation required for restore operation",
        )
    
    # Check super admin
    if "super_admin" not in current_user.get("roles", []):
        return create_error_response(
            status_code=403,
            error_code=ErrorCodes.FORBIDDEN,
            message="Super admin permission required for restore",
        )
    
    result = {
        "backup_id": backup_id,
        "restore_id": "restore_123",
        "status": "in_progress",
        "estimated_time_minutes": 15,
    }
    
    return AuditableResponse(
        status="success",
        message="Restore operation initiated",
        data=result,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@router.get(
    "/notifications",
    response_model=DataResponse[list[SystemNotification]],
    summary="Get system notifications",
    description="Get active system-wide notifications",
)
async def get_system_notifications(
    current_user: Annotated[dict, Depends(require_admin)],
    active_only: bool = Query(True, description="Show only active notifications"),
) -> DataResponse[list[SystemNotification]]:
    """Get system notifications."""
    notifications = [
        SystemNotification(
            id="notif_1",
            type="info",
            title="Scheduled Maintenance",
            message="System maintenance scheduled for Sunday 2AM-4AM UTC",
            active=True,
            priority=1,
            target_roles=[],
            dismissible=True,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(days=7),
        ),
    ]
    
    if active_only:
        notifications = [n for n in notifications if n.active]
    
    return DataResponse(
        status="success",
        message="Notifications retrieved successfully",
        data=notifications,
    )


@router.post(
    "/notifications",
    response_model=DataResponse[SystemNotification],
    summary="Create system notification",
    description="Create a new system-wide notification",
)
async def create_notification(
    notification: SystemNotification = Body(...),
    current_user: dict = Depends(require_admin),
) -> DataResponse[SystemNotification]:
    """Create system notification."""
    notification.id = f"notif_{datetime.utcnow().timestamp()}"
    
    return DataResponse(
        status="success",
        message="Notification created successfully",
        data=notification,
    )


@router.get(
    "/cache",
    response_model=DataResponse[CacheManagement],
    summary="Get cache statistics",
    description="Get cache usage and statistics",
)
async def get_cache_stats(
    current_user: Annotated[dict, Depends(require_admin)],
) -> DataResponse[CacheManagement]:
    """Get cache statistics."""
    cache_stats = CacheManagement(
        cache_type="redis",
        total_keys=15420,
        memory_used_mb=256.8,
        hit_rate=94.5,
        last_flush=datetime.utcnow() - timedelta(days=7),
        patterns=[
            {"pattern": "session:*", "count": 8500, "avg_ttl_seconds": 3600},
            {"pattern": "user:*", "count": 4200, "avg_ttl_seconds": 86400},
            {"pattern": "auth:*", "count": 2720, "avg_ttl_seconds": 1800},
        ],
    )
    
    return DataResponse(
        status="success",
        message="Cache statistics retrieved",
        data=cache_stats,
    )


@router.post(
    "/cache/flush",
    response_model=AuditableResponse[dict],
    summary="Flush cache",
    description="Flush cache by pattern or entirely",
)
async def flush_cache(
    pattern: Optional[str] = Query(None, description="Pattern to flush (e.g., 'session:*')"),
    confirm: bool = Query(False, description="Confirm flush operation"),
    current_user: dict = Depends(require_admin),
) -> AuditableResponse[dict]:
    """Flush cache."""
    if not confirm:
        return create_error_response(
            status_code=400,
            error_code=ErrorCodes.INVALID_INPUT,
            message="Confirmation required for cache flush",
        )
    
    result = {
        "pattern": pattern or "*",
        "keys_flushed": 2500 if pattern else 15420,
        "flushed_at": datetime.utcnow().isoformat(),
    }
    
    return AuditableResponse(
        status="success",
        message=f"Cache flushed successfully{f' for pattern {pattern}' if pattern else ''}",
        data=result,
        audit=AdminMetadata(
            performed_by=current_user["user_id"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )