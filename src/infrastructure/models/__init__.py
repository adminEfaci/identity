"""Import all SQLAlchemy models for Alembic migrations.

This module ensures all models are imported so Alembic can detect them
for auto-generating migrations.
"""

# Import Base first
from ..database import Base

# Import all domain models that should create database tables
# Note: You'll need to create SQLAlchemy models that correspond to your domain entities
# For now, these are placeholder imports - replace with actual model imports

# Example models (you'll need to implement these):
# from .user_model import UserModel
# from .role_model import RoleModel
# from .permission_model import PermissionModel
# from .audit_log_model import AuditLogModel
# from .mfa_config_model import MFAConfigModel

# Make sure all models are available for Alembic
__all__ = [
    "Base",
    # Add your model names here
]