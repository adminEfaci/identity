"""Application layer for the Identity module.

This module provides the application layer implementation following CQRS patterns.
It includes commands, queries, handlers, services, and DTOs that orchestrate
domain operations and provide clean boundaries for external integration.

The application layer is responsible for:
- Defining application-specific operations through commands and queries
- Implementing handlers that process these operations
- Providing services that orchestrate domain logic
- Converting between domain entities and DTOs for external communication
- Enforcing application-level business rules and validation

Key Components:
- Commands: Write operations (CreateUser, ModifyUser, DeleteUser)
- Queries: Read operations (GetUser, ListUsers)
- Handlers: Process commands and queries with dependency injection
- Services: Orchestrate domain operations and provide business logic
- DTOs: Data transfer objects for external communication
- Interfaces: Contracts for dependency injection and testing
"""

from .commands import (
    CreateUserCommand,
    DeleteUserCommand,
    ModifyUserCommand,
)
from .dtos import (
    CreateUserDto,
    ModifyUserDto,
    UserDto,
)
from .handlers import (
    CreateUserHandler,
    DeleteUserHandler,
    GetUserHandler,
    ListUsersHandler,
    ModifyUserHandler,
)
from .interfaces import (
    ICommandHandler,
    IQueryHandler,
    IUserService,
)
from .queries import (
    GetUserQuery,
    ListUsersQuery,
)
from .services import (
    UserService,
)

__all__ = [
    # Commands
    "CreateUserCommand",
    "ModifyUserCommand",
    "DeleteUserCommand",

    # Queries
    "GetUserQuery",
    "ListUsersQuery",

    # DTOs
    "UserDto",
    "CreateUserDto",
    "ModifyUserDto",

    # Handlers
    "CreateUserHandler",
    "ModifyUserHandler",
    "DeleteUserHandler",
    "GetUserHandler",
    "ListUsersHandler",

    # Services
    "UserService",

    # Interfaces
    "ICommandHandler",
    "IQueryHandler",
    "IUserService",
]
