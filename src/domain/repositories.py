"""Repository Interfaces for Identity Module.

This module contains abstract repository interfaces following DDD principles.
These interfaces define contracts for data access without coupling to
specific persistence technologies.
"""

from abc import ABC, abstractmethod
from typing import Optional

from .entities import Permission, Role, User
from .enums import PermissionScope, RoleType, UserStatus
from .value_objects import Email, PermissionId, RoleId, UserId


class UserRepository(ABC):
    """Abstract repository interface for User entities.

    Defines the contract for user data access operations following
    the Repository pattern from DDD.
    """

    @abstractmethod
    async def save(self, user: User) -> None:
        """Save a user entity.

        Args:
            user: User entity to save

        Raises:
            RepositoryError: If the save operation fails
        """
        pass

    @abstractmethod
    async def find_by_id(self, user_id: UserId) -> Optional[User]:
        """Find a user by their ID.

        Args:
            user_id: User ID to search for

        Returns:
            User entity if found, None otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_email(self, email: Email) -> Optional[User]:
        """Find a user by their email address.

        Args:
            email: Email address to search for

        Returns:
            User entity if found, None otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_status(self, status: UserStatus) -> list[User]:
        """Find all users with a specific status.

        Args:
            status: User status to filter by

        Returns:
            List of users with the specified status

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_role(self, role_id: RoleId) -> list[User]:
        """Find all users with a specific role.

        Args:
            role_id: Role ID to filter by

        Returns:
            List of users with the specified role

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[User]:
        """Find all users with optional pagination.

        Args:
            limit: Maximum number of users to return
            offset: Number of users to skip

        Returns:
            List of users

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def exists_by_email(self, email: Email) -> bool:
        """Check if a user exists with the given email.

        Args:
            email: Email address to check

        Returns:
            True if user exists, False otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def count_by_status(self, status: UserStatus) -> int:
        """Count users by status.

        Args:
            status: User status to count

        Returns:
            Number of users with the specified status

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def delete(self, user_id: UserId) -> bool:
        """Delete a user by ID.

        Args:
            user_id: ID of the user to delete

        Returns:
            True if user was deleted, False if not found

        Raises:
            RepositoryError: If the delete operation fails
        """
        pass

    @abstractmethod
    async def search_by_email_pattern(self, pattern: str) -> list[User]:
        """Search users by email pattern.

        Args:
            pattern: Email pattern to search for (supports wildcards)

        Returns:
            List of users matching the pattern

        Raises:
            RepositoryError: If the query fails
        """
        pass


class RoleRepository(ABC):
    """Abstract repository interface for Role entities.

    Defines the contract for role data access operations following
    the Repository pattern from DDD.
    """

    @abstractmethod
    async def save(self, role: Role) -> None:
        """Save a role entity.

        Args:
            role: Role entity to save

        Raises:
            RepositoryError: If the save operation fails
        """
        pass

    @abstractmethod
    async def find_by_id(self, role_id: RoleId) -> Optional[Role]:
        """Find a role by its ID.

        Args:
            role_id: Role ID to search for

        Returns:
            Role entity if found, None otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_name(self, name: str) -> Optional[Role]:
        """Find a role by its name.

        Args:
            name: Role name to search for

        Returns:
            Role entity if found, None otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_type(self, role_type: RoleType) -> list[Role]:
        """Find all roles of a specific type.

        Args:
            role_type: Role type to filter by

        Returns:
            List of roles with the specified type

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_permission(self, permission_id: PermissionId) -> list[Role]:
        """Find all roles that have a specific permission.

        Args:
            permission_id: Permission ID to filter by

        Returns:
            List of roles with the specified permission

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_all_active(self) -> list[Role]:
        """Find all active roles.

        Returns:
            List of active roles

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[Role]:
        """Find all roles with optional pagination.

        Args:
            limit: Maximum number of roles to return
            offset: Number of roles to skip

        Returns:
            List of roles

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def exists_by_name(self, name: str) -> bool:
        """Check if a role exists with the given name.

        Args:
            name: Role name to check

        Returns:
            True if role exists, False otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def delete(self, role_id: RoleId) -> bool:
        """Delete a role by ID.

        Args:
            role_id: ID of the role to delete

        Returns:
            True if role was deleted, False if not found

        Raises:
            RepositoryError: If the delete operation fails
        """
        pass

    @abstractmethod
    async def find_system_roles(self) -> list[Role]:
        """Find all system roles.

        Returns:
            List of system roles

        Raises:
            RepositoryError: If the query fails
        """
        pass


class PermissionRepository(ABC):
    """Abstract repository interface for Permission entities.

    Defines the contract for permission data access operations following
    the Repository pattern from DDD.
    """

    @abstractmethod
    async def save(self, permission: Permission) -> None:
        """Save a permission entity.

        Args:
            permission: Permission entity to save

        Raises:
            RepositoryError: If the save operation fails
        """
        pass

    @abstractmethod
    async def find_by_id(self, permission_id: PermissionId) -> Optional[Permission]:
        """Find a permission by its ID.

        Args:
            permission_id: Permission ID to search for

        Returns:
            Permission entity if found, None otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_name(self, name: str) -> Optional[Permission]:
        """Find a permission by its name.

        Args:
            name: Permission name to search for

        Returns:
            Permission entity if found, None otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_resource_and_action(
        self,
        resource: str,
        action: str,
    ) -> list[Permission]:
        """Find permissions by resource and action.

        Args:
            resource: Resource name to filter by
            action: Action name to filter by

        Returns:
            List of permissions matching the criteria

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_scope(self, scope: PermissionScope) -> list[Permission]:
        """Find all permissions with a specific scope.

        Args:
            scope: Permission scope to filter by

        Returns:
            List of permissions with the specified scope

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_by_resource(self, resource: str) -> list[Permission]:
        """Find all permissions for a specific resource.

        Args:
            resource: Resource name to filter by

        Returns:
            List of permissions for the specified resource

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_all_active(self) -> list[Permission]:
        """Find all active permissions.

        Returns:
            List of active permissions

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def find_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[Permission]:
        """Find all permissions with optional pagination.

        Args:
            limit: Maximum number of permissions to return
            offset: Number of permissions to skip

        Returns:
            List of permissions

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def exists_by_name(self, name: str) -> bool:
        """Check if a permission exists with the given name.

        Args:
            name: Permission name to check

        Returns:
            True if permission exists, False otherwise

        Raises:
            RepositoryError: If the query fails
        """
        pass

    @abstractmethod
    async def delete(self, permission_id: PermissionId) -> bool:
        """Delete a permission by ID.

        Args:
            permission_id: ID of the permission to delete

        Returns:
            True if permission was deleted, False if not found

        Raises:
            RepositoryError: If the delete operation fails
        """
        pass

    @abstractmethod
    async def find_by_ids(self, permission_ids: set[PermissionId]) -> list[Permission]:
        """Find permissions by a set of IDs.

        Args:
            permission_ids: Set of permission IDs to find

        Returns:
            List of permissions found

        Raises:
            RepositoryError: If the query fails
        """
        pass


class RepositoryError(Exception):
    """Base exception for repository operations.

    Raised when repository operations fail due to data access issues,
    constraint violations, or other persistence-related problems.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        """Initialize repository error.

        Args:
            message: Error message describing the failure
            cause: Optional underlying exception that caused this error
        """
        super().__init__(message)
        self.cause = cause

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.cause:
            return f"{super().__str__()} (caused by: {self.cause})"
        return super().__str__()


class DuplicateEntityError(RepositoryError):
    """Exception raised when attempting to create a duplicate entity.

    Typically occurs when trying to save an entity that violates
    unique constraints (e.g., duplicate email, role name, etc.).
    """

    def __init__(self, entity_type: str, identifier: str) -> None:
        """Initialize duplicate entity error.

        Args:
            entity_type: Type of entity that already exists
            identifier: Identifier value that caused the conflict
        """
        message = f"{entity_type} with identifier '{identifier}' already exists"
        super().__init__(message)
        self.entity_type = entity_type
        self.identifier = identifier


class EntityNotFoundError(RepositoryError):
    """Exception raised when an entity is not found.

    Typically occurs when trying to retrieve an entity by ID
    that doesn't exist in the repository.
    """

    def __init__(self, entity_type: str, identifier: str) -> None:
        """Initialize entity not found error.

        Args:
            entity_type: Type of entity that was not found
            identifier: Identifier value that was searched for
        """
        message = f"{entity_type} with identifier '{identifier}' not found"
        super().__init__(message)
        self.entity_type = entity_type
        self.identifier = identifier
