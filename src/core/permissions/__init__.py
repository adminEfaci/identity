"""Role-based access control (RBAC) utilities for the identity service."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, Field

from ..logging import get_logger

logger = get_logger(__name__)


class PermissionLevel(str, Enum):
    """Permission levels for fine-grained access control."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class Permission(BaseModel):
    """Permission model with resource and level."""

    resource: str = Field(..., description="Resource identifier")
    level: PermissionLevel = Field(..., description="Permission level")
    conditions: dict[str, str] = Field(default_factory=dict, description="Additional conditions")

    def __str__(self) -> str:
        """String representation of permission."""
        if self.conditions:
            conditions_str = ",".join(f"{k}={v}" for k, v in self.conditions.items())
            return f"{self.resource}:{self.level}:{conditions_str}"
        return f"{self.resource}:{self.level}"

    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """Create permission from string representation.

        Args:
            permission_str: String like "users:read" or "users:write:department=engineering"

        Returns:
            Permission instance
        """
        parts = permission_str.split(":")
        if len(parts) < 2:
            raise ValueError(f"Invalid permission string: {permission_str}")

        resource = parts[0]
        level = PermissionLevel(parts[1])

        conditions = {}
        if len(parts) > 2:
            for condition in parts[2].split(","):
                if "=" in condition:
                    key, value = condition.split("=", 1)
                    conditions[key] = value

        return cls(resource=resource, level=level, conditions=conditions)


class Role(BaseModel):
    """Role model with permissions and metadata."""

    name: str = Field(..., description="Role name")
    description: Optional[str] = Field(None, description="Role description")
    permissions: list[Permission] = Field(default_factory=list, description="Role permissions")
    parent_roles: list[str] = Field(default_factory=list, description="Parent roles for inheritance")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_system: bool = Field(default=False, description="System role flag")

    def add_permission(self, permission: Union[Permission, str]) -> None:
        """Add permission to role.

        Args:
            permission: Permission to add
        """
        if isinstance(permission, str):
            permission = Permission.from_string(permission)

        # Check if permission already exists
        for existing in self.permissions:
            if existing.resource == permission.resource and existing.level == permission.level:
                return

        self.permissions.append(permission)
        self.updated_at = datetime.now(timezone.utc)

    def remove_permission(self, resource: str, level: PermissionLevel) -> bool:
        """Remove permission from role.

        Args:
            resource: Resource identifier
            level: Permission level

        Returns:
            True if permission was removed
        """
        for i, permission in enumerate(self.permissions):
            if permission.resource == resource and permission.level == level:
                self.permissions.pop(i)
                self.updated_at = datetime.now(timezone.utc)
                return True
        return False

    def has_permission(self, resource: str, level: PermissionLevel) -> bool:
        """Check if role has specific permission.

        Args:
            resource: Resource identifier
            level: Permission level

        Returns:
            True if role has permission
        """
        for permission in self.permissions:
            if permission.resource == resource and permission.level == level:
                return True
        return False


class RBACManager:
    """Role-based access control manager."""

    def __init__(self):
        """Initialize RBAC manager."""
        self.roles: dict[str, Role] = {}
        self.user_roles: dict[str, set[str]] = {}
        self._initialize_system_roles()

    def _initialize_system_roles(self) -> None:
        """Initialize default system roles."""
        # Super admin role
        super_admin = Role(
            name="super_admin",
            description="Super administrator with full access",
            permissions=[
                Permission(resource="*", level=PermissionLevel.ADMIN)
            ],
            is_system=True
        )
        self.roles["super_admin"] = super_admin

        # Admin role
        admin = Role(
            name="admin",
            description="Administrator with broad access",
            permissions=[
                Permission(resource="users", level=PermissionLevel.ADMIN),
                Permission(resource="roles", level=PermissionLevel.ADMIN),
                Permission(resource="settings", level=PermissionLevel.WRITE),
                Permission(resource="audit", level=PermissionLevel.READ)
            ],
            is_system=True
        )
        self.roles["admin"] = admin

        # User manager role
        user_manager = Role(
            name="user_manager",
            description="User management permissions",
            permissions=[
                Permission(resource="users", level=PermissionLevel.WRITE),
                Permission(resource="users", level=PermissionLevel.READ),
                Permission(resource="audit", level=PermissionLevel.READ)
            ],
            is_system=True
        )
        self.roles["user_manager"] = user_manager

        # Regular user role
        user = Role(
            name="user",
            description="Regular user with basic permissions",
            permissions=[
                Permission(resource="profile", level=PermissionLevel.WRITE),
                Permission(resource="settings", level=PermissionLevel.READ)
            ],
            is_system=True
        )
        self.roles["user"] = user

        logger.info("System roles initialized")

    def create_role(
        self,
        name: str,
        description: Optional[str] = None,
        permissions: Optional[list[Union[Permission, str]]] = None,
        parent_roles: Optional[list[str]] = None
    ) -> Role:
        """Create a new role.

        Args:
            name: Role name
            description: Role description
            permissions: List of permissions
            parent_roles: Parent roles for inheritance

        Returns:
            Created role
        """
        if name in self.roles:
            raise ValueError(f"Role '{name}' already exists")

        role = Role(
            name=name,
            description=description,
            parent_roles=parent_roles or []
        )

        # Add permissions
        if permissions:
            for permission in permissions:
                role.add_permission(permission)

        self.roles[name] = role

        logger.info(
            "Role created",
            role_name=name,
            permissions_count=len(role.permissions)
        )

        return role

    def get_role(self, name: str) -> Optional[Role]:
        """Get role by name.

        Args:
            name: Role name

        Returns:
            Role or None if not found
        """
        return self.roles.get(name)

    def delete_role(self, name: str) -> bool:
        """Delete a role.

        Args:
            name: Role name

        Returns:
            True if role was deleted
        """
        role = self.roles.get(name)
        if not role:
            return False

        if role.is_system:
            raise ValueError(f"Cannot delete system role '{name}'")

        # Remove role from all users
        for user_id in list(self.user_roles.keys()):
            self.remove_user_role(user_id, name)

        del self.roles[name]

        logger.info("Role deleted", role_name=name)
        return True

    def assign_role(self, user_id: str, role_name: str) -> bool:
        """Assign role to user.

        Args:
            user_id: User identifier
            role_name: Role name

        Returns:
            True if role was assigned
        """
        if role_name not in self.roles:
            logger.warning("Attempted to assign non-existent role", role_name=role_name)
            return False

        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()

        if role_name in self.user_roles[user_id]:
            return True  # Already assigned

        self.user_roles[user_id].add(role_name)

        logger.info(
            "Role assigned to user",
            user_id=user_id,
            role_name=role_name
        )

        return True

    def remove_user_role(self, user_id: str, role_name: str) -> bool:
        """Remove role from user.

        Args:
            user_id: User identifier
            role_name: Role name

        Returns:
            True if role was removed
        """
        if user_id not in self.user_roles:
            return False

        if role_name in self.user_roles[user_id]:
            self.user_roles[user_id].remove(role_name)

            logger.info(
                "Role removed from user",
                user_id=user_id,
                role_name=role_name
            )

            return True

        return False

    def get_user_roles(self, user_id: str) -> list[str]:
        """Get all roles for a user.

        Args:
            user_id: User identifier

        Returns:
            List of role names
        """
        return list(self.user_roles.get(user_id, set()))

    def get_user_permissions(self, user_id: str) -> list[Permission]:
        """Get all effective permissions for a user.

        Args:
            user_id: User identifier

        Returns:
            List of permissions
        """
        permissions = []
        processed_roles = set()

        def collect_permissions(role_name: str):
            if role_name in processed_roles:
                return

            processed_roles.add(role_name)
            role = self.roles.get(role_name)

            if not role:
                return

            # Add role permissions
            permissions.extend(role.permissions)

            # Process parent roles
            for parent_role in role.parent_roles:
                collect_permissions(parent_role)

        # Collect permissions from all user roles
        user_roles = self.user_roles.get(user_id, set())
        for role_name in user_roles:
            collect_permissions(role_name)

        return permissions


class PermissionChecker:
    """Permission checking utilities."""

    def __init__(self, rbac_manager: RBACManager):
        """Initialize permission checker.

        Args:
            rbac_manager: RBAC manager instance
        """
        self.rbac_manager = rbac_manager

    def check_permission(
        self,
        user_id: str,
        resource: str,
        level: PermissionLevel,
        context: Optional[dict[str, str]] = None
    ) -> bool:
        """Check if user has permission for resource.

        Args:
            user_id: User identifier
            resource: Resource identifier
            level: Required permission level
            context: Additional context for condition checking

        Returns:
            True if user has permission
        """
        permissions = self.rbac_manager.get_user_permissions(user_id)

        for permission in permissions:
            if self._matches_permission(permission, resource, level, context):
                logger.debug(
                    "Permission granted",
                    user_id=user_id,
                    resource=resource,
                    permission_level=level.value
                )
                return True

        logger.warning(
            "Permission denied",
            user_id=user_id,
            resource=resource,
            permission_level=level.value
        )

        return False

    def _matches_permission(
        self,
        permission: Permission,
        resource: str,
        level: PermissionLevel,
        context: Optional[dict[str, str]] = None
    ) -> bool:
        """Check if permission matches requirements.

        Args:
            permission: Permission to check
            resource: Required resource
            level: Required permission level
            context: Additional context

        Returns:
            True if permission matches
        """
        # Check resource match (support wildcards)
        if permission.resource != "*" and permission.resource != resource:
            return False

        # Check permission level hierarchy
        level_hierarchy = {
            PermissionLevel.READ: 1,
            PermissionLevel.WRITE: 2,
            PermissionLevel.DELETE: 3,
            PermissionLevel.ADMIN: 4
        }

        if level_hierarchy[permission.level] < level_hierarchy[level]:
            return False

        # Check conditions
        if permission.conditions and context:
            for key, value in permission.conditions.items():
                if context.get(key) != value:
                    return False

        return True

    def require_permission(
        self,
        user_id: str,
        resource: str,
        level: PermissionLevel,
        context: Optional[dict[str, str]] = None
    ) -> None:
        """Require permission or raise exception.

        Args:
            user_id: User identifier
            resource: Resource identifier
            level: Required permission level
            context: Additional context

        Raises:
            PermissionError: If user doesn't have permission
        """
        if not self.check_permission(user_id, resource, level, context):
            raise PermissionError(
                f"User {user_id} does not have {level.value} permission for {resource}"
            )

    def require_role(self, user_id: str, role_name: str) -> None:
        """Require specific role or raise exception.

        Args:
            user_id: User identifier
            role_name: Required role name

        Raises:
            PermissionError: If user doesn't have role
        """
        user_roles = self.rbac_manager.get_user_roles(user_id)

        if role_name not in user_roles:
            raise PermissionError(f"User {user_id} does not have role {role_name}")

    def require_any_role(self, user_id: str, role_names: list[str]) -> None:
        """Require any of the specified roles or raise exception.

        Args:
            user_id: User identifier
            role_names: List of acceptable role names

        Raises:
            PermissionError: If user doesn't have any of the roles
        """
        user_roles = set(self.rbac_manager.get_user_roles(user_id))
        required_roles = set(role_names)

        if not user_roles.intersection(required_roles):
            raise PermissionError(
                f"User {user_id} does not have any of the required roles: {role_names}"
            )
