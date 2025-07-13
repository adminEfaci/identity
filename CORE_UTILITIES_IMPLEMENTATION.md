# Identity Module Core Utilities Implementation

## Overview

This document provides a comprehensive overview of the core utilities implementation for the Identity Module. The implementation follows Domain-Driven Design (DDD) principles and provides foundational functionality for authentication, authorization, security, and data management.

## Architecture

```
src/
├── core/                    # Core business utilities
│   ├── auth/               # JWT authentication utilities
│   ├── crypto/             # Cryptographic utilities
│   ├── logging/            # Structured JSON logging
│   ├── mfa/                # Multi-factor authentication
│   ├── permissions/        # RBAC and permission management
│   └── utils/              # General security utilities
└── utils/                  # Supporting utilities
    ├── error_handling/     # Error management and structured exceptions
    ├── validation/         # Data validation utilities
    └── helpers/            # Helper functions (timestamps, URLs, strings, etc.)
```

## Core Modules

### 1. Structured Logging (`core/logging/`)

**Features:**
- JSON-structured logging with comprehensive metadata
- Context-aware logging with user ID, request ID, correlation ID
- Security event logging
- Audit event logging
- Configurable output (console, file)
- Thread-safe logging operations

**Key Components:**
- `StructuredLogger`: Main logging class with context management
- `LogRecord`: Pydantic model for structured log entries
- `StructuredFormatter`: JSON formatter for log output
- `get_logger()`: Factory function for logger instances

**Usage Example:**
```python
from core.logging import get_logger

logger = get_logger('my_service')
logger.info('User action', user_id='123', request_id='req-456')
logger.log_security_event('login_attempt', user_id='123', ip_address='192.168.1.1')
logger.log_audit_event('user_created', 'users', user_id='admin', result='success')
```

### 2. JWT Authentication (`core/auth/`)

**Features:**
- Complete JWT token management (create, decode, verify)
- Access and refresh token support
- Comprehensive claims management (roles, permissions, MFA status)
- Token validation with expiration and signature verification
- Bearer token extraction utilities

**Key Components:**
- `JWTManager`: Core JWT operations
- `TokenValidator`: Token validation and requirement checking
- `JWTClaims`: Pydantic model for token claims
- Authentication exceptions (TokenExpiredError, TokenInvalidError)

**Usage Example:**
```python
from core.auth import JWTManager, TokenValidator

jwt_manager = JWTManager('secret-key')
token = jwt_manager.create_access_token(
    user_id='user123',
    roles=['user', 'admin'],
    permissions=['read:posts', 'write:posts'],
    mfa_verified=True
)

claims = jwt_manager.decode_token(token)
validator = TokenValidator(jwt_manager)
validator.require_mfa(claims)
validator.require_roles(claims, ['admin'])
```

### 3. Cryptographic Utilities (`core/crypto/`)

**Features:**
- Password hashing with Argon2 (industry standard)
- Multiple encryption algorithms (AES-256-GCM, Fernet)
- Key derivation with PBKDF2
- Secure random token generation
- Data integrity verification

**Key Components:**
- `HashingManager`: Password hashing and verification
- `EncryptionManager`: Data encryption and decryption
- Utility functions for secure token generation

**Usage Example:**
```python
from core.crypto import HashingManager, EncryptionManager

# Password hashing
hasher = HashingManager()
password_hash = hasher.hash_password('user_password')
is_valid = hasher.verify_password('user_password', password_hash)

# Data encryption
encryptor = EncryptionManager()
encrypted = encryptor.encrypt_text('sensitive data')
decrypted = encryptor.decrypt_text(encrypted)
```

### 4. Multi-Factor Authentication (`core/mfa/`)

**Features:**
- TOTP (Time-based One-Time Password) implementation
- QR code generation for authenticator apps
- Hardware token support (FIDO2/WebAuthn framework)
- Backup code generation and verification
- Rate limiting for MFA attempts

**Key Components:**
- `TOTPManager`: TOTP secret generation and verification
- `HardwareTokenManager`: Hardware token management
- `TOTPSecret`: Configuration model for TOTP setup
- Backup code utilities

**Usage Example:**
```python
from core.mfa import TOTPManager, generate_backup_codes

totp_manager = TOTPManager()
totp_config = totp_manager.generate_totp_config('user@example.com')
qr_code_png = totp_manager.generate_qr_code(totp_config)

# Verify TOTP code
totp_code = '123456'
is_valid = totp_manager.verify_totp(totp_config.secret, totp_code, 'user123')

# Generate backup codes
backup_codes = generate_backup_codes(10)
```

### 5. Role-Based Access Control (`core/permissions/`)

**Features:**
- Hierarchical role and permission system
- Fine-grained permission levels (READ, WRITE, DELETE, ADMIN)
- Conditional permissions with context
- System and custom role support
- Permission inheritance through role hierarchy

**Key Components:**
- `RBACManager`: Role and permission management
- `PermissionChecker`: Permission validation utilities
- `Role`: Role model with permissions and metadata
- `Permission`: Permission model with resource and level
- `PermissionLevel`: Enum for permission hierarchy

**Usage Example:**
```python
from core.permissions import RBACManager, PermissionChecker, PermissionLevel, Permission

rbac = RBACManager()

# Create custom role
rbac.create_role('editor', permissions=[
    Permission(resource='posts', level=PermissionLevel.WRITE),
    Permission(resource='comments', level=PermissionLevel.READ)
])

# Assign role and check permissions
rbac.assign_role('user123', 'editor')
checker = PermissionChecker(rbac)
has_permission = checker.check_permission('user123', 'posts', PermissionLevel.WRITE)
```

### 6. Security Utilities (`core/utils/`)

**Features:**
- Secure password generation with customizable criteria
- Password strength analysis
- Input sanitization and validation
- URL safety validation
- IP address validation and classification

**Key Components:**
- `SecurityUtils`: Security-related utility functions
- `ValidationUtils`: Data validation utilities
- `DataUtils`: Data manipulation helpers

**Usage Example:**
```python
from core.utils import SecurityUtils, ValidationUtils

# Password utilities
secure_password = SecurityUtils.generate_secure_password(16)
strength = SecurityUtils.check_password_strength('MyPassword123!')

# Validation utilities
is_valid_email = ValidationUtils.validate_email('user@example.com')
username_check = ValidationUtils.validate_username('user_123')
```

## Supporting Utilities

### 1. Error Handling (`utils/error_handling/`)

**Features:**
- Structured error hierarchy with detailed information
- Centralized error handling and logging
- HTTP status code mapping
- Context-aware error reporting
- Exception decoration for automatic error handling

**Key Components:**
- `ServiceError`: Base error class with structured data
- `ErrorHandler`: Centralized error processing
- Specific error types (ValidationError, AuthenticationError, etc.)
- `ErrorCode`: Standardized error codes

### 2. Data Validation (`utils/validation/`)

**Features:**
- JSON Schema validation
- Pydantic model validation
- Field-level validation utilities
- Common validation schemas (user registration, password change)
- Comprehensive error reporting

**Key Components:**
- `DataValidator`: General validation utilities
- `SchemaValidator`: JSON Schema validation
- Pre-defined schemas for common use cases

### 3. Helper Utilities (`utils/helpers/`)

**Features:**
- Timestamp and datetime utilities
- URL manipulation and validation
- String processing and formatting
- File operations and utilities
- In-memory caching with TTL

**Key Components:**
- `TimestampHelper`: Date/time operations
- `URLHelper`: URL manipulation
- `StringHelper`: String processing
- `FileHelper`: File operations
- `CacheHelper`: Simple caching

## Configuration and Dependencies

### Required Dependencies
```toml
dependencies = [
    # Security
    "argon2-cffi>=23.0.0",
    "pyjwt[crypto]>=2.8.0",
    "cryptography>=41.0.0",
    # MFA and QR Code
    "qrcode[pil]>=7.4.0",
    # Utilities
    "pydantic>=2.5.0",
    "jsonschema>=4.20.0",
]
```

### Code Quality
- **Zero lint errors** with ruff
- **Complete type annotations** for all public APIs
- **Comprehensive error handling** with structured exceptions
- **Extensive logging** for security and audit purposes

## Security Considerations

1. **Password Security**: Uses Argon2 for password hashing with configurable parameters
2. **Token Security**: JWT tokens with proper expiration and signature verification
3. **Encryption**: Multiple encryption algorithms with secure key management
4. **Input Validation**: Comprehensive input sanitization and validation
5. **Rate Limiting**: Built-in rate limiting for sensitive operations
6. **Audit Logging**: Complete audit trail for security events

## Testing and Validation

All utilities have been tested with:
- ✅ Import validation
- ✅ Basic functionality testing
- ✅ Error handling verification
- ✅ Type annotation compliance
- ✅ Lint-free code validation

## Integration Points

These utilities are designed to integrate with:
- **Presentation Layer**: FastAPI/GraphQL APIs
- **Domain Layer**: Business logic and entities
- **Infrastructure Layer**: Database and external services
- **Application Layer**: Use cases and orchestration

## Next Steps

1. **Unit Testing**: Comprehensive test suite for all utilities
2. **Integration Testing**: End-to-end testing with other modules
3. **Performance Testing**: Load testing for critical operations
4. **Documentation**: API documentation and usage guides
5. **Monitoring**: Metrics and monitoring integration

This implementation provides a solid foundation for the Identity Module's core functionality, ensuring security, reliability, and maintainability while following best practices and industry standards.