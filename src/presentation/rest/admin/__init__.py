"""Admin API module.

This module contains all admin-related API endpoints including
dashboard, user management, system configuration, and audit logs.
"""

from .audit import router as audit_router
from .dashboard import router as dashboard_router
from .system import router as system_router
from .users import router as users_router

__all__ = [
    "dashboard_router",
    "users_router",
    "audit_router",
    "system_router",
]