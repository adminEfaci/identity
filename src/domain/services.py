"""Domain Services for Identity Module.

This module contains domain services that encapsulate complex business logic
that doesn't naturally fit within a single entity or value object.
"""

from typing import Optional

from .entities import Permission, Role
from .enums import PermissionScope, UserStatus
from .repositories import PermissionRepository, RoleRepository, UserRepository
from .value_objects import PermissionId, RoleId, UserId


class UserDomainService:
    """Domain service for user-related business operations.

    Encapsulates complex user business logic that involves multiple
    entities or external dependencies.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        role_repository: RoleRepository,
    ) -> None:
        """Initialize user domain service.

        Args:
            user_repository: Repository for user data access
            role_repository: Repository for role data access
        """
        self._user_repository = user_repository
        self._role_repository = role_repository

    async def can_user_be_deleted(self, user_id: UserId) -> bool:
        """Check if a user can be safely deleted.

        Args:
            user_id: ID of the user to check

        Returns:
            True if user can be deleted, False otherwise
        """
        user = await self._user_repository.find_by_id(user_id)
        if not user:
            return False

        # Business rule: Active users with admin roles cannot be deleted
        if user.status == UserStatus.ACTIVE:
            for role_id in user.role_ids:
                role = await self._role_repository.find_by_id(role_id)
                if role and role.name.lower() in (
                    "admin",
                    "administrator",
                    "superuser",
                ):
                    return False

        return True

    async def get_effective_permissions(self, user_id: UserId) -> set[PermissionId]:
        """Get all effective permissions for a user.

        Aggregates permissions from all assigned roles to determine
        the complete set of permissions the user has.

        Args:
            user_id: ID of the user

        Returns:
            Set of permission IDs the user has access to
        """
        user = await self._user_repository.find_by_id(user_id)
        if not user or not user.is_active():
            return set()

        effective_permissions: set[PermissionId] = set()

        for role_id in user.role_ids:
            role = await self._role_repository.find_by_id(role_id)
            if role and role.is_active:
                effective_permissions.update(role.permission_ids)

        return effective_permissions

    async def has_permission(
        self,
        user_id: UserId,
        resource: str,
        action: str,
    ) -> bool:
        """Check if a user has permission to perform an action on a resource.

        Args:
            user_id: ID of the user
            resource: Resource name
            action: Action name

        Returns:
            True if user has permission, False otherwise
        """
        effective_permissions = await self.get_effective_permissions(user_id)

        # This would typically involve checking against a permission repository
        # For now, we'll use a simplified approach
        return len(effective_permissions) > 0

    async def validate_role_assignment(
        self,
        user_id: UserId,
        role_id: RoleId,
    ) -> bool:
        """Validate if a role can be assigned to a user.

        Args:
            user_id: ID of the user
            role_id: ID of the role to assign

        Returns:
            True if role can be assigned, False otherwise
        """
        user = await self._user_repository.find_by_id(user_id)
        role = await self._role_repository.find_by_id(role_id)

        if not user or not role:
            return False

        # Business rule: Inactive users cannot be assigned roles
        if not user.is_active():
            return False

        # Business rule: Inactive roles cannot be assigned
        if not role.is_active:
            return False

        # Business rule: User cannot have duplicate roles
        return not user.has_role(role_id)


class RoleDomainService:
    """Domain service for role-related business operations.

    Encapsulates complex role business logic that involves multiple
    entities or external dependencies.
    """

    def __init__(
        self,
        role_repository: RoleRepository,
        permission_repository: PermissionRepository,
        user_repository: UserRepository,
    ) -> None:
        """Initialize role domain service.

        Args:
            role_repository: Repository for role data access
            permission_repository: Repository for permission data access
            user_repository: Repository for user data access
        """
        self._role_repository = role_repository
        self._permission_repository = permission_repository
        self._user_repository = user_repository

    async def can_role_be_deleted(self, role_id: RoleId) -> bool:
        """Check if a role can be safely deleted.

        Args:
            role_id: ID of the role to check

        Returns:
            True if role can be deleted, False otherwise
        """
        role = await self._role_repository.find_by_id(role_id)
        if not role:
            return False

        # Business rule: System roles cannot be deleted
        if not role.can_be_deleted():
            return False

        # Business rule: Roles assigned to users cannot be deleted
        users_with_role = await self._user_repository.find_by_role(role_id)
        return not users_with_role

    async def validate_permission_assignment(
        self,
        role_id: RoleId,
        permission_id: PermissionId,
    ) -> bool:
        """Validate if a permission can be assigned to a role.

        Args:
            role_id: ID of the role
            permission_id: ID of the permission to assign

        Returns:
            True if permission can be assigned, False otherwise
        """
        role = await self._role_repository.find_by_id(role_id)
        permission = await self._permission_repository.find_by_id(permission_id)

        if not role or not permission:
            return False

        # Business rule: System roles cannot be modified
        if not role.can_be_modified():
            return False

        # Business rule: Inactive permissions cannot be assigned
        if not permission.is_active:
            return False

        # Business rule: Role cannot have duplicate permissions
        return not role.has_permission(permission_id)

    async def get_role_hierarchy(self, role_id: RoleId) -> list[Role]:
        """Get the hierarchy of roles (if inheritance is implemented).

        Args:
            role_id: ID of the role

        Returns:
            List of roles in hierarchy order
        """
        # This is a placeholder for role hierarchy logic
        # In a full implementation, this would traverse role inheritance
        role = await self._role_repository.find_by_id(role_id)
        return [role] if role else []


class PermissionDomainService:
    """Domain service for permission-related business operations.

    Encapsulates complex permission business logic that involves multiple
    entities or external dependencies.
    """

    def __init__(
        self,
        permission_repository: PermissionRepository,
        role_repository: RoleRepository,
    ) -> None:
        """Initialize permission domain service.

        Args:
            permission_repository: Repository for permission data access
            role_repository: Repository for role data access
        """
        self._permission_repository = permission_repository
        self._role_repository = role_repository

    async def can_permission_be_deleted(self, permission_id: PermissionId) -> bool:
        """Check if a permission can be safely deleted.

        Args:
            permission_id: ID of the permission to check

        Returns:
            True if permission can be deleted, False otherwise
        """
        # Business rule: Permissions assigned to roles cannot be deleted
        roles_with_permission = await self._role_repository.find_by_permission(
            permission_id
        )
        return len(roles_with_permission) == 0

    async def find_conflicting_permissions(
        self,
        resource: str,
        action: str,
        scope: PermissionScope,
    ) -> list[Permission]:
        """Find permissions that might conflict with a new permission.

        Args:
            resource: Resource name
            action: Action name
            scope: Permission scope

        Returns:
            List of potentially conflicting permissions
        """
        existing_permissions = (
            await self._permission_repository.find_by_resource_and_action(
                resource, action
            )
        )

        # Filter for permissions with overlapping scopes
        conflicting = []
        for permission in existing_permissions:
            if (
                permission.scope == scope
                or permission.scope.can_inherit_from(scope)
                or scope.can_inherit_from(permission.scope)
            ):
                conflicting.append(permission)

        return conflicting

    async def validate_permission_scope_hierarchy(
        self,
        permissions: list[Permission],
    ) -> bool:
        """Validate that permission scopes form a valid hierarchy.

        Args:
            permissions: List of permissions to validate

        Returns:
            True if hierarchy is valid, False otherwise
        """
        # Group permissions by resource and action
        resource_actions = {}
        for permission in permissions:
            key = (permission.resource, permission.action)
            if key not in resource_actions:
                resource_actions[key] = []
            resource_actions[key].append(permission)

        # Check each resource-action group for valid scope hierarchy
        for permission_group in resource_actions.values():
            scopes = [p.scope for p in permission_group]
            scope_levels = [s.hierarchy_level for s in scopes]

            # Check for duplicate scope levels (invalid)
            if len(set(scope_levels)) != len(scope_levels):
                return False

        return True


class AuthorizationService:
    """Domain service for authorization operations.

    Provides high-level authorization logic that combines user,
    role, and permission concepts.
    """

    def __init__(
        self,
        user_service: UserDomainService,
        role_service: RoleDomainService,
        permission_service: PermissionDomainService,
    ) -> None:
        """Initialize authorization service.

        Args:
            user_service: User domain service
            role_service: Role domain service
            permission_service: Permission domain service
        """
        self._user_service = user_service
        self._role_service = role_service
        self._permission_service = permission_service

    async def authorize_user_action(
        self,
        user_id: UserId,
        resource: str,
        action: str,
        context: Optional[dict] = None,
    ) -> bool:
        """Authorize a user to perform an action on a resource.

        Args:
            user_id: ID of the user
            resource: Resource name
            action: Action name
            context: Optional context for authorization

        Returns:
            True if authorized, False otherwise
        """
        # Check if user has the required permission
        has_permission = await self._user_service.has_permission(
            user_id, resource, action
        )

        # Additional context-based authorization logic could go here
        # For example, checking resource ownership, time-based access, etc.

        return has_permission

    async def get_user_accessible_resources(
        self,
        user_id: UserId,
        resource_type: str,
    ) -> list[str]:
        """Get list of resources a user can access.

        Args:
            user_id: ID of the user
            resource_type: Type of resources to check

        Returns:
            List of accessible resource identifiers
        """
        # This would typically involve complex logic to determine
        # which specific resources the user can access based on
        # their permissions and the current context

        # Placeholder implementation
        effective_permissions = await self._user_service.get_effective_permissions(
            user_id
        )

        # In a real implementation, this would map permissions to actual resources
        return [] if not effective_permissions else [f"{resource_type}:example"]
