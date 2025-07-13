"""Identity Module - Domain-Driven Design Implementation.

This module implements the Identity domain following DDD principles with:
- Entities: User, Role, Permission
- Value Objects: Email, PasswordHash, AuditInfo
- Enums: UserStatus, AuditAction
- Domain Events: UserCreated, UserModified, UserDeleted
- Repository Interfaces: UserRepository, RoleRepository, PermissionRepository
"""

__version__ = "1.0.0"
__author__ = "Identity Team"
