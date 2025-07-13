"""Exception classes for Identity Domain Module.

This module contains custom exception classes that represent domain-specific
error conditions and business rule violations.
"""

from typing import Any, Optional
from uuid import UUID


class DomainError(Exception):
    """Base exception for all domain-related errors.

    Represents violations of business rules, invariants, or other
    domain-specific error conditions.
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Initialize domain error.

        Args:
            message: Human-readable error message
            error_code: Optional machine-readable error code
            details: Optional additional error details
        """
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the error."""
        base_message = super().__str__()
        if self.error_code:
            return f"[{self.error_code}] {base_message}"
        return base_message


class ValidationError(DomainError):
    """Exception raised when domain validation fails.

    Typically occurs when creating or modifying entities with
    invalid data that violates business rules or constraints.
    """

    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        invalid_value: Optional[Any] = None,
    ) -> None:
        """Initialize validation error.

        Args:
            message: Validation error message
            field_name: Name of the field that failed validation
            invalid_value: The invalid value that caused the error
        """
        details = {}
        if field_name:
            details["field_name"] = field_name
        if invalid_value is not None:
            details["invalid_value"] = str(invalid_value)

        super().__init__(message, "VALIDATION_ERROR", details)
        self.field_name = field_name
        self.invalid_value = invalid_value


class BusinessRuleViolationError(DomainError):
    """Exception raised when a business rule is violated.

    Represents violations of complex business logic that cannot
    be expressed as simple validation rules.
    """

    def __init__(
        self,
        message: str,
        rule_name: str,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        """Initialize business rule violation error.

        Args:
            message: Business rule violation message
            rule_name: Name of the violated business rule
            context: Optional context information about the violation
        """
        details = {"rule_name": rule_name}
        if context:
            details.update(context)

        super().__init__(message, "BUSINESS_RULE_VIOLATION", details)
        self.rule_name = rule_name
        self.context = context or {}


class UserDomainError(DomainError):
    """Base exception for user-related domain errors."""

    def __init__(
        self,
        message: str,
        user_id: Optional[UUID] = None,
        error_code: Optional[str] = None,
    ) -> None:
        """Initialize user domain error.

        Args:
            message: Error message
            user_id: Optional user ID related to the error
            error_code: Optional error code
        """
        details = {}
        if user_id:
            details["user_id"] = str(user_id)

        super().__init__(message, error_code, details)
        self.user_id = user_id


class InvalidEmailError(ValidationError):
    """Exception raised when an invalid email address is provided."""

    def __init__(self, email: str) -> None:
        """Initialize invalid email error.

        Args:
            email: The invalid email address
        """
        super().__init__(
            f"Invalid email format: {email}",
            field_name="email",
            invalid_value=email,
        )


class WeakPasswordError(ValidationError):
    """Exception raised when a password doesn't meet security requirements."""

    def __init__(self, reason: str) -> None:
        """Initialize weak password error.

        Args:
            reason: Reason why the password is considered weak
        """
        super().__init__(
            f"Password does not meet security requirements: {reason}",
            field_name="password",
        )


class UserAlreadyExistsError(UserDomainError):
    """Exception raised when attempting to create a user that already exists."""

    def __init__(self, email: str) -> None:
        """Initialize user already exists error.

        Args:
            email: Email address of the existing user
        """
        super().__init__(
            f"User with email '{email}' already exists",
            error_code="USER_ALREADY_EXISTS",
        )
        self.email = email


class UserNotFoundError(UserDomainError):
    """Exception raised when a user cannot be found."""

    def __init__(self, identifier: str, identifier_type: str = "id") -> None:
        """Initialize user not found error.

        Args:
            identifier: User identifier (ID, email, etc.)
            identifier_type: Type of identifier used
        """
        super().__init__(
            f"User not found with {identifier_type}: {identifier}",
            error_code="USER_NOT_FOUND",
        )
        self.identifier = identifier
        self.identifier_type = identifier_type


class UserStatusError(UserDomainError):
    """Exception raised when user status prevents an operation."""

    def __init__(self, message: str, user_id: UUID, current_status: str) -> None:
        """Initialize user status error.

        Args:
            message: Error message
            user_id: ID of the user
            current_status: Current user status
        """
        super().__init__(
            message,
            user_id=user_id,
            error_code="USER_STATUS_ERROR",
        )
        self.current_status = current_status


class InactiveUserError(UserStatusError):
    """Exception raised when an inactive user attempts an operation."""

    def __init__(self, user_id: UUID, current_status: str) -> None:
        """Initialize inactive user error.

        Args:
            user_id: ID of the inactive user
            current_status: Current user status
        """
        super().__init__(
            f"User is inactive and cannot perform this operation (status: {current_status})",
            user_id=user_id,
            current_status=current_status,
        )


class RoleDomainError(DomainError):
    """Base exception for role-related domain errors."""

    def __init__(
        self,
        message: str,
        role_id: Optional[UUID] = None,
        error_code: Optional[str] = None,
    ) -> None:
        """Initialize role domain error.

        Args:
            message: Error message
            role_id: Optional role ID related to the error
            error_code: Optional error code
        """
        details = {}
        if role_id:
            details["role_id"] = str(role_id)

        super().__init__(message, error_code, details)
        self.role_id = role_id


class RoleNotFoundError(RoleDomainError):
    """Exception raised when a role cannot be found."""

    def __init__(self, identifier: str, identifier_type: str = "id") -> None:
        """Initialize role not found error.

        Args:
            identifier: Role identifier (ID, name, etc.)
            identifier_type: Type of identifier used
        """
        super().__init__(
            f"Role not found with {identifier_type}: {identifier}",
            error_code="ROLE_NOT_FOUND",
        )
        self.identifier = identifier
        self.identifier_type = identifier_type


class RoleAlreadyExistsError(RoleDomainError):
    """Exception raised when attempting to create a role that already exists."""

    def __init__(self, name: str) -> None:
        """Initialize role already exists error.

        Args:
            name: Name of the existing role
        """
        super().__init__(
            f"Role with name '{name}' already exists",
            error_code="ROLE_ALREADY_EXISTS",
        )
        self.name = name


class SystemRoleModificationError(RoleDomainError):
    """Exception raised when attempting to modify a system role."""

    def __init__(self, role_name: str) -> None:
        """Initialize system role modification error.

        Args:
            role_name: Name of the system role
        """
        super().__init__(
            f"System role '{role_name}' cannot be modified",
            error_code="SYSTEM_ROLE_MODIFICATION_ERROR",
        )
        self.role_name = role_name


class RoleAssignmentError(DomainError):
    """Exception raised when role assignment fails."""

    def __init__(
        self,
        message: str,
        user_id: UUID,
        role_id: UUID,
    ) -> None:
        """Initialize role assignment error.

        Args:
            message: Error message
            user_id: ID of the user
            role_id: ID of the role
        """
        details = {
            "user_id": str(user_id),
            "role_id": str(role_id),
        }

        super().__init__(message, "ROLE_ASSIGNMENT_ERROR", details)
        self.user_id = user_id
        self.role_id = role_id


class PermissionDomainError(DomainError):
    """Base exception for permission-related domain errors."""

    def __init__(
        self,
        message: str,
        permission_id: Optional[UUID] = None,
        error_code: Optional[str] = None,
    ) -> None:
        """Initialize permission domain error.

        Args:
            message: Error message
            permission_id: Optional permission ID related to the error
            error_code: Optional error code
        """
        details = {}
        if permission_id:
            details["permission_id"] = str(permission_id)

        super().__init__(message, error_code, details)
        self.permission_id = permission_id


class PermissionNotFoundError(PermissionDomainError):
    """Exception raised when a permission cannot be found."""

    def __init__(self, identifier: str, identifier_type: str = "id") -> None:
        """Initialize permission not found error.

        Args:
            identifier: Permission identifier (ID, name, etc.)
            identifier_type: Type of identifier used
        """
        super().__init__(
            f"Permission not found with {identifier_type}: {identifier}",
            error_code="PERMISSION_NOT_FOUND",
        )
        self.identifier = identifier
        self.identifier_type = identifier_type


class PermissionAlreadyExistsError(PermissionDomainError):
    """Exception raised when attempting to create a permission that already exists."""

    def __init__(self, name: str) -> None:
        """Initialize permission already exists error.

        Args:
            name: Name of the existing permission
        """
        super().__init__(
            f"Permission with name '{name}' already exists",
            error_code="PERMISSION_ALREADY_EXISTS",
        )
        self.name = name


class InsufficientPermissionsError(DomainError):
    """Exception raised when a user lacks required permissions."""

    def __init__(
        self,
        user_id: UUID,
        required_permission: str,
        resource: Optional[str] = None,
    ) -> None:
        """Initialize insufficient permissions error.

        Args:
            user_id: ID of the user lacking permissions
            required_permission: The required permission
            resource: Optional resource the permission applies to
        """
        message = f"User lacks required permission: {required_permission}"
        if resource:
            message += f" on resource: {resource}"

        details = {
            "user_id": str(user_id),
            "required_permission": required_permission,
        }
        if resource:
            details["resource"] = resource

        super().__init__(message, "INSUFFICIENT_PERMISSIONS", details)
        self.user_id = user_id
        self.required_permission = required_permission
        self.resource = resource


class ConcurrencyError(DomainError):
    """Exception raised when a concurrency conflict occurs."""

    def __init__(self, entity_type: str, entity_id: UUID) -> None:
        """Initialize concurrency error.

        Args:
            entity_type: Type of entity that had the conflict
            entity_id: ID of the entity
        """
        super().__init__(
            f"Concurrency conflict detected for {entity_type} with ID: {entity_id}",
            error_code="CONCURRENCY_ERROR",
        )
        self.entity_type = entity_type
        self.entity_id = entity_id
