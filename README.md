# Identity Module Backend

A comprehensive identity management system with Multi-Factor Authentication (MFA), Role-Based Access Control (RBAC), auditing, and notification capabilities, following Domain-Driven Design (DDD) principles.

## Overview

This module provides a complete identity management domain layer with:

- **Entities**: User, Role, Permission with rich business behavior
- **Value Objects**: Email, PasswordHash, AuditInfo, and strongly-typed IDs
- **Enums**: UserStatus, AuditAction, PermissionScope, RoleType
- **Domain Events**: Complete event model for audit trails and integration
- **Repository Interfaces**: Abstract contracts for data access
- **Domain Services**: Complex business logic coordination
- **Exceptions**: Comprehensive error handling for business rules

## Architecture

The module follows strict DDD principles:

```
src/domain/
├── __init__.py          # Public API exports
├── entities.py          # Domain entities (User, Role, Permission)
├── value_objects.py     # Immutable value objects
├── enums.py            # Domain enumerations
├── events.py           # Domain events for event sourcing
├── repositories.py     # Repository interface contracts
├── services.py         # Domain services for complex logic
└── exceptions.py       # Domain-specific exceptions
```

## Key Features

### Entities

- **User**: Aggregate root with identity, authentication, and role management
- **Role**: Contains permissions and metadata with type-based behavior
- **Permission**: Resource-action-scope based authorization model

### Value Objects

- **Email**: Validated email addresses with domain extraction
- **PasswordHash**: Secure password storage with algorithm metadata
- **AuditInfo**: Complete audit trail with creation and modification tracking
- **Strongly-typed IDs**: UserId, RoleId, PermissionId to prevent ID mixing

### Domain Events

- **UserCreated**: User registration events
- **UserModified**: User profile changes
- **UserDeleted**: User deletion (soft/hard)
- **UserRoleAssigned/Removed**: Role management events
- **UserPasswordChanged**: Security events
- **UserStatusChanged**: Status transition events

### Business Rules

- Active users must have valid email addresses
- System roles cannot be modified or deleted
- Users cannot have duplicate roles
- Permissions follow scope hierarchy (Global > Organization > Project > Resource)
- Inactive users cannot be assigned roles
- Password changes generate security events

## Usage Examples

### Creating a User

```python
from domain import User, Email, PasswordHash, UserStatus
from uuid import uuid4

# Create value objects
email = Email("user@example.com")
password_hash = PasswordHash.from_plaintext("secure_password")

# Create user entity
user = User.create(
    email=email,
    password_hash=password_hash,
    created_by=uuid4(),
    initial_status=UserStatus.PENDING_VERIFICATION
)

# Access domain events
events = user.domain_events  # [UserCreated(...)]
```

### Role Management

```python
from domain import Role, RoleType, Permission, PermissionScope
from uuid import uuid4

# Create permission
permission = Permission.create(
    name="Read Users",
    resource="user",
    action="read",
    scope=PermissionScope.GLOBAL,
    created_by=uuid4()
)

# Create role with permissions
role = Role.create(
    name="User Manager",
    role_type=RoleType.CUSTOM,
    created_by=uuid4(),
    initial_permissions={permission.id}
)

# Assign role to user
user.assign_role(role.id, assigned_by=uuid4())
```

### Authorization

```python
from domain.services import AuthorizationService

# Check user permissions
authorized = await auth_service.authorize_user_action(
    user_id=user.id,
    resource="user",
    action="read"
)
```

## Quality Standards

- **Type Safety**: Full type annotations with mypy compliance
- **Documentation**: Comprehensive docstrings for all public APIs
- **Testing**: Unit tests with pytest and async support
- **Linting**: Ruff for code quality and formatting
- **Coverage**: High test coverage requirements

## Development

### Setup

```bash
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Linting

```bash
ruff check src/
ruff format src/
```

### Type Checking

```bash
mypy src/
```

## Design Principles

1. **Domain-Driven Design**: Clear separation of domain logic from infrastructure
2. **Immutability**: Value objects are immutable for thread safety
3. **Event Sourcing**: Domain events capture all state changes
4. **Rich Domain Model**: Entities contain business logic, not just data
5. **Explicit Dependencies**: Repository interfaces define clear contracts
6. **Fail Fast**: Validation at object creation prevents invalid states
7. **Type Safety**: Strong typing prevents runtime errors

## Business Rules

### User Rules
- Email addresses must be unique across the system
- Active users can login and perform operations
- Pending users require email verification
- Deleted users cannot be reactivated (business decision)

### Role Rules
- System roles cannot be modified or deleted
- Custom roles can be fully managed
- Roles must have unique names
- Inactive roles cannot be assigned to users

### Permission Rules
- Permissions follow scope hierarchy
- Resource-action combinations must be unique per scope
- Permissions can inherit from broader scopes

### Security Rules
- Password changes generate audit events
- Role assignments require proper authorization
- Status changes are logged with reasons
- All modifications include audit trails

## Integration

This domain module is designed to integrate with:

- **Application Layer**: Use cases and command handlers
- **Infrastructure Layer**: Database repositories and external services
- **API Layer**: REST/GraphQL endpoints
- **Event Bus**: Domain event publishing for integration

## License

MIT License - see LICENSE file for details.