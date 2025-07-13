"""Domain Entities for Identity Module.

This module contains the core domain entities following DDD principles.
Entities have identity and encapsulate business logic and invariants.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from .enums import PermissionScope, RoleType, UserStatus
from .events import (
    DomainEvent,
    UserCreated,
    UserDeleted,
    UserModified,
    UserPasswordChanged,
    UserRoleAssigned,
    UserRoleRemoved,
    UserStatusChanged,
)
from .value_objects import AuditInfo, Email, PasswordHash, PermissionId, RoleId, UserId


@dataclass
class User:
    """User aggregate root entity.

    Represents a user in the system with identity, authentication credentials,
    status, and role assignments. Encapsulates user-related business logic
    and maintains consistency through domain events.
    """

    id: UserId = field()
    email: Email = field()
    password_hash: PasswordHash = field()
    status: UserStatus = field()
    audit_info: AuditInfo = field()
    role_ids: set[RoleId] = field(default_factory=set)
    _domain_events: list[DomainEvent] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        """Validate user entity upon creation."""
        self._validate_invariants()

    def _validate_invariants(self) -> None:
        """Validate business invariants for the user entity."""
        if not self.id:
            raise ValueError("User ID is required")

        if not self.email:
            raise ValueError("Email is required")

        if not self.password_hash:
            raise ValueError("Password hash is required")

        if self.status == UserStatus.ACTIVE and not self.role_ids:
            # Active users should have at least one role (business rule)
            pass  # This might be relaxed based on business requirements

    @property
    def domain_events(self) -> list[DomainEvent]:
        """Get the list of domain events raised by this entity."""
        return self._domain_events.copy()

    def clear_domain_events(self) -> None:
        """Clear the domain events after they have been processed."""
        self._domain_events.clear()

    def _add_domain_event(self, event: DomainEvent) -> None:
        """Add a domain event to the entity."""
        self._domain_events.append(event)

    @classmethod
    def create(
        cls,
        email: Email,
        password_hash: PasswordHash,
        created_by: UUID,
        initial_status: UserStatus = UserStatus.PENDING_VERIFICATION,
        initial_roles: Optional[set[RoleId]] = None,
    ) -> "User":
        """Create a new user with proper event handling.

        Args:
            email: User's email address
            password_hash: Hashed password
            created_by: ID of the user creating this user
            initial_status: Initial user status
            initial_roles: Optional set of initial roles

        Returns:
            New User instance with UserCreated event
        """
        user_id = UserId.generate()
        audit_info = AuditInfo(
            created_by=created_by,
            created_at=datetime.utcnow(),
        )

        roles = initial_roles or set()

        user = cls(
            id=user_id,
            email=email,
            password_hash=password_hash,
            status=initial_status,
            audit_info=audit_info,
            role_ids=roles,
        )

        # Raise domain event
        event = UserCreated(
            event_id=uuid4(),
            aggregate_id=user_id.value,
            occurred_at=datetime.utcnow(),
            user_id=user_id,
            email=email,
            status=initial_status,
            created_by=created_by,
            initial_roles=frozenset(roles),
        )
        user._add_domain_event(event)

        return user

    def change_email(self, new_email: Email, modified_by: UUID) -> None:
        """Change the user's email address.

        Args:
            new_email: New email address
            modified_by: ID of the user making the change
        """
        if new_email == self.email:
            return  # No change needed

        old_email = self.email
        self.email = new_email

        # Update audit info
        self.audit_info = self.audit_info.with_modification(modified_by)

        # Raise domain event
        event = UserModified(
            event_id=uuid4(),
            aggregate_id=self.id.value,
            occurred_at=datetime.utcnow(),
            user_id=self.id,
            modified_by=modified_by,
            changes={"email": str(new_email)},
            previous_values={"email": str(old_email)},
        )
        self._add_domain_event(event)

        self._validate_invariants()

    def change_password(
        self,
        new_password_hash: PasswordHash,
        changed_by: UUID,
        is_self_change: bool = True,
    ) -> None:
        """Change the user's password.

        Args:
            new_password_hash: New password hash
            changed_by: ID of the user making the change
            is_self_change: Whether the user is changing their own password
        """
        self.password_hash = new_password_hash

        # Update audit info
        self.audit_info = self.audit_info.with_modification(changed_by)

        # Raise domain event
        event = UserPasswordChanged(
            event_id=uuid4(),
            aggregate_id=self.id.value,
            occurred_at=datetime.utcnow(),
            user_id=self.id,
            changed_by=changed_by,
            is_self_change=is_self_change,
        )
        self._add_domain_event(event)

        self._validate_invariants()

    def change_status(
        self,
        new_status: UserStatus,
        changed_by: UUID,
        reason: Optional[str] = None,
    ) -> None:
        """Change the user's status.

        Args:
            new_status: New user status
            changed_by: ID of the user making the change
            reason: Optional reason for the status change
        """
        if new_status == self.status:
            return  # No change needed

        old_status = self.status
        self.status = new_status

        # Update audit info
        self.audit_info = self.audit_info.with_modification(changed_by)

        # Raise domain event
        event = UserStatusChanged(
            event_id=uuid4(),
            aggregate_id=self.id.value,
            occurred_at=datetime.utcnow(),
            user_id=self.id,
            previous_status=old_status,
            new_status=new_status,
            changed_by=changed_by,
            reason=reason,
        )
        self._add_domain_event(event)

        self._validate_invariants()

    def assign_role(self, role_id: RoleId, assigned_by: UUID) -> None:
        """Assign a role to the user.

        Args:
            role_id: ID of the role to assign
            assigned_by: ID of the user making the assignment
        """
        if role_id in self.role_ids:
            return  # Role already assigned

        self.role_ids.add(role_id)

        # Update audit info
        self.audit_info = self.audit_info.with_modification(assigned_by)

        # Raise domain event
        event = UserRoleAssigned(
            event_id=uuid4(),
            aggregate_id=self.id.value,
            occurred_at=datetime.utcnow(),
            user_id=self.id,
            role_id=role_id,
            assigned_by=assigned_by,
        )
        self._add_domain_event(event)

        self._validate_invariants()

    def remove_role(
        self,
        role_id: RoleId,
        removed_by: UUID,
        reason: Optional[str] = None,
    ) -> None:
        """Remove a role from the user.

        Args:
            role_id: ID of the role to remove
            removed_by: ID of the user making the removal
            reason: Optional reason for the removal
        """
        if role_id not in self.role_ids:
            return  # Role not assigned

        self.role_ids.remove(role_id)

        # Update audit info
        self.audit_info = self.audit_info.with_modification(removed_by)

        # Raise domain event
        event = UserRoleRemoved(
            event_id=uuid4(),
            aggregate_id=self.id.value,
            occurred_at=datetime.utcnow(),
            user_id=self.id,
            role_id=role_id,
            removed_by=removed_by,
            removal_reason=reason,
        )
        self._add_domain_event(event)

        self._validate_invariants()

    def has_role(self, role_id: RoleId) -> bool:
        """Check if the user has a specific role."""
        return role_id in self.role_ids

    def is_active(self) -> bool:
        """Check if the user is active."""
        return self.status == UserStatus.ACTIVE

    def can_login(self) -> bool:
        """Check if the user can login."""
        return self.status.can_login

    def delete(self, deleted_by: UUID, soft_delete: bool = True) -> None:
        """Delete the user.

        Args:
            deleted_by: ID of the user performing the deletion
            soft_delete: Whether to perform a soft delete
        """
        if soft_delete:
            self.change_status(UserStatus.DELETED, deleted_by, "User deleted")

        # Raise domain event
        event = UserDeleted(
            event_id=uuid4(),
            aggregate_id=self.id.value,
            occurred_at=datetime.utcnow(),
            user_id=self.id,
            deleted_by=deleted_by,
            email=self.email,
            soft_delete=soft_delete,
        )
        self._add_domain_event(event)


@dataclass
class Role:
    """Role entity.

    Represents a role that can be assigned to users, containing a set of
    permissions and metadata about the role's purpose and scope.
    """

    id: RoleId = field()
    name: str = field()
    description: Optional[str] = field()
    role_type: RoleType = field()
    audit_info: AuditInfo = field()
    permission_ids: set[PermissionId] = field(default_factory=set)
    is_active: bool = field(default=True)

    def __post_init__(self) -> None:
        """Validate role entity upon creation."""
        self._validate_invariants()

    def _validate_invariants(self) -> None:
        """Validate business invariants for the role entity."""
        if not self.id:
            raise ValueError("Role ID is required")

        if not self.name or not self.name.strip():
            raise ValueError("Role name is required")

        if len(self.name) > 100:
            raise ValueError("Role name cannot exceed 100 characters")

        if self.description and len(self.description) > 500:
            raise ValueError("Role description cannot exceed 500 characters")

    @classmethod
    def create(
        cls,
        name: str,
        role_type: RoleType,
        created_by: UUID,
        description: Optional[str] = None,
        initial_permissions: Optional[set[PermissionId]] = None,
    ) -> "Role":
        """Create a new role.

        Args:
            name: Role name
            role_type: Type of the role
            created_by: ID of the user creating the role
            description: Optional role description
            initial_permissions: Optional set of initial permissions

        Returns:
            New Role instance
        """
        role_id = RoleId.generate()
        audit_info = AuditInfo(
            created_by=created_by,
            created_at=datetime.utcnow(),
        )

        permissions = initial_permissions or set()

        return cls(
            id=role_id,
            name=name.strip(),
            description=description.strip() if description else None,
            role_type=role_type,
            permission_ids=permissions,
            audit_info=audit_info,
        )

    def add_permission(self, permission_id: PermissionId) -> None:
        """Add a permission to the role."""
        self.permission_ids.add(permission_id)

    def remove_permission(self, permission_id: PermissionId) -> None:
        """Remove a permission from the role."""
        self.permission_ids.discard(permission_id)

    def has_permission(self, permission_id: PermissionId) -> bool:
        """Check if the role has a specific permission."""
        return permission_id in self.permission_ids

    def can_be_modified(self) -> bool:
        """Check if the role can be modified."""
        return self.role_type.is_modifiable

    def can_be_deleted(self) -> bool:
        """Check if the role can be deleted."""
        return self.role_type.can_be_deleted


@dataclass
class Permission:
    """Permission entity.

    Represents a specific permission that can be granted to roles,
    defining what actions can be performed on what resources.
    """

    id: PermissionId = field()
    name: str = field()
    description: Optional[str] = field()
    resource: str = field()
    action: str = field()
    scope: PermissionScope = field()
    audit_info: AuditInfo = field()
    is_active: bool = field(default=True)

    def __post_init__(self) -> None:
        """Validate permission entity upon creation."""
        self._validate_invariants()

    def _validate_invariants(self) -> None:
        """Validate business invariants for the permission entity."""
        if not self.id:
            raise ValueError("Permission ID is required")

        if not self.name or not self.name.strip():
            raise ValueError("Permission name is required")

        if not self.resource or not self.resource.strip():
            raise ValueError("Permission resource is required")

        if not self.action or not self.action.strip():
            raise ValueError("Permission action is required")

        if len(self.name) > 100:
            raise ValueError("Permission name cannot exceed 100 characters")

        if len(self.resource) > 50:
            raise ValueError("Permission resource cannot exceed 50 characters")

        if len(self.action) > 50:
            raise ValueError("Permission action cannot exceed 50 characters")

    @classmethod
    def create(
        cls,
        name: str,
        resource: str,
        action: str,
        scope: PermissionScope,
        created_by: UUID,
        description: Optional[str] = None,
    ) -> "Permission":
        """Create a new permission.

        Args:
            name: Permission name
            resource: Resource the permission applies to
            action: Action the permission allows
            scope: Scope of the permission
            created_by: ID of the user creating the permission
            description: Optional permission description

        Returns:
            New Permission instance
        """
        permission_id = PermissionId.generate()
        audit_info = AuditInfo(
            created_by=created_by,
            created_at=datetime.utcnow(),
        )

        return cls(
            id=permission_id,
            name=name.strip(),
            description=description.strip() if description else None,
            resource=resource.strip(),
            action=action.strip(),
            scope=scope,
            audit_info=audit_info,
        )

    @property
    def full_name(self) -> str:
        """Get the full permission name including resource and action."""
        return f"{self.resource}:{self.action}"

    def matches(self, resource: str, action: str) -> bool:
        """Check if this permission matches a resource and action."""
        return self.resource == resource and self.action == action

    def can_inherit_from(self, other: "Permission") -> bool:
        """Check if this permission can inherit from another permission."""
        return (
            self.resource == other.resource
            and self.action == other.action
            and self.scope.can_inherit_from(other.scope)
        )
