"""Data validation utilities for the identity service."""

import json
from datetime import datetime
from typing import Any, Optional, Union

import jsonschema
from jsonschema import ValidationError as JsonSchemaValidationError
from jsonschema import validate
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from core.logging import get_logger

from ..error_handling import ErrorCode, ErrorDetail, ValidationError

logger = get_logger(__name__)


class DataValidator:
    """General data validation utilities."""

    @staticmethod
    def validate_required_fields(
        data: dict[str, Any],
        required_fields: list[str]
    ) -> list[ErrorDetail]:
        """Validate that required fields are present.

        Args:
            data: Data dictionary to validate
            required_fields: List of required field names

        Returns:
            List of validation errors
        """
        errors = []

        for field in required_fields:
            if field not in data or data[field] is None:
                errors.append(ErrorDetail(
                    code=ErrorCode.MISSING_REQUIRED_FIELD,
                    message=f"Field '{field}' is required",
                    field=field
                ))

        return errors

    @staticmethod
    def validate_field_types(
        data: dict[str, Any],
        field_types: dict[str, type]
    ) -> list[ErrorDetail]:
        """Validate field types.

        Args:
            data: Data dictionary to validate
            field_types: Dictionary mapping field names to expected types

        Returns:
            List of validation errors
        """
        errors = []

        for field, expected_type in field_types.items():
            if field in data and data[field] is not None and not isinstance(data[field], expected_type):
                errors.append(ErrorDetail(
                    code=ErrorCode.INVALID_FORMAT,
                    message=f"Field '{field}' must be of type {expected_type.__name__}",
                    field=field,
                    value=data[field]
                ))

        return errors

    @staticmethod
    def validate_string_length(
        data: dict[str, Any],
        field_constraints: dict[str, dict[str, int]]
    ) -> list[ErrorDetail]:
        """Validate string field lengths.

        Args:
            data: Data dictionary to validate
            field_constraints: Dictionary mapping field names to length constraints
                             e.g., {"username": {"min": 3, "max": 50}}

        Returns:
            List of validation errors
        """
        errors = []

        for field, constraints in field_constraints.items():
            if field in data and isinstance(data[field], str):
                value = data[field]

                if "min" in constraints and len(value) < constraints["min"]:
                    errors.append(ErrorDetail(
                        code=ErrorCode.VALUE_TOO_SHORT,
                        message=f"Field '{field}' must be at least {constraints['min']} characters",
                        field=field,
                        value=value
                    ))

                if "max" in constraints and len(value) > constraints["max"]:
                    errors.append(ErrorDetail(
                        code=ErrorCode.VALUE_TOO_LONG,
                        message=f"Field '{field}' must be no more than {constraints['max']} characters",
                        field=field,
                        value=value
                    ))

        return errors

    @staticmethod
    def validate_numeric_range(
        data: dict[str, Any],
        field_constraints: dict[str, dict[str, Union[int, float]]]
    ) -> list[ErrorDetail]:
        """Validate numeric field ranges.

        Args:
            data: Data dictionary to validate
            field_constraints: Dictionary mapping field names to range constraints
                             e.g., {"age": {"min": 0, "max": 150}}

        Returns:
            List of validation errors
        """
        errors = []

        for field, constraints in field_constraints.items():
            if field in data and isinstance(data[field], (int, float)):
                value = data[field]

                if "min" in constraints and value < constraints["min"]:
                    errors.append(ErrorDetail(
                        code=ErrorCode.INVALID_INPUT,
                        message=f"Field '{field}' must be at least {constraints['min']}",
                        field=field,
                        value=value
                    ))

                if "max" in constraints and value > constraints["max"]:
                    errors.append(ErrorDetail(
                        code=ErrorCode.INVALID_INPUT,
                        message=f"Field '{field}' must be no more than {constraints['max']}",
                        field=field,
                        value=value
                    ))

        return errors

    @staticmethod
    def validate_allowed_values(
        data: dict[str, Any],
        field_values: dict[str, list[Any]]
    ) -> list[ErrorDetail]:
        """Validate that field values are from allowed sets.

        Args:
            data: Data dictionary to validate
            field_values: Dictionary mapping field names to allowed values

        Returns:
            List of validation errors
        """
        errors = []

        for field, allowed_values in field_values.items():
            if field in data and data[field] not in allowed_values:
                errors.append(ErrorDetail(
                    code=ErrorCode.INVALID_INPUT,
                    message=f"Field '{field}' must be one of: {allowed_values}",
                    field=field,
                    value=data[field]
                ))

        return errors

    @staticmethod
    def validate_email_format(email: str) -> Optional[ErrorDetail]:
        """Validate email format.

        Args:
            email: Email address to validate

        Returns:
            ErrorDetail if invalid, None if valid
        """
        import re

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if not re.match(pattern, email):
            return ErrorDetail(
                code=ErrorCode.INVALID_FORMAT,
                message="Invalid email format",
                field="email",
                value=email
            )

        return None

    @staticmethod
    def validate_password_strength(password: str) -> list[ErrorDetail]:
        """Validate password strength.

        Args:
            password: Password to validate

        Returns:
            List of validation errors
        """
        errors = []

        if len(password) < 8:
            errors.append(ErrorDetail(
                code=ErrorCode.VALUE_TOO_SHORT,
                message="Password must be at least 8 characters long",
                field="password"
            ))

        if not any(c.isupper() for c in password):
            errors.append(ErrorDetail(
                code=ErrorCode.INVALID_FORMAT,
                message="Password must contain at least one uppercase letter",
                field="password"
            ))

        if not any(c.islower() for c in password):
            errors.append(ErrorDetail(
                code=ErrorCode.INVALID_FORMAT,
                message="Password must contain at least one lowercase letter",
                field="password"
            ))

        if not any(c.isdigit() for c in password):
            errors.append(ErrorDetail(
                code=ErrorCode.INVALID_FORMAT,
                message="Password must contain at least one digit",
                field="password"
            ))

        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            errors.append(ErrorDetail(
                code=ErrorCode.INVALID_FORMAT,
                message="Password must contain at least one special character",
                field="password"
            ))

        return errors


class SchemaValidator:
    """JSON Schema validation utilities."""

    def __init__(self):
        """Initialize schema validator."""
        self.schemas: dict[str, dict[str, Any]] = {}

    def register_schema(self, name: str, schema: dict[str, Any]) -> None:
        """Register a JSON schema.

        Args:
            name: Schema name
            schema: JSON schema definition
        """
        self.schemas[name] = schema
        logger.debug(f"Schema '{name}' registered")

    def validate_data(self, data: Any, schema_name: str) -> list[ErrorDetail]:
        """Validate data against a registered schema.

        Args:
            data: Data to validate
            schema_name: Name of the schema to validate against

        Returns:
            List of validation errors
        """
        if schema_name not in self.schemas:
            raise ValueError(f"Schema '{schema_name}' not found")

        schema = self.schemas[schema_name]

        try:
            validate(instance=data, schema=schema)
            return []
        except JsonSchemaValidationError as e:
            return self._convert_jsonschema_error(e)

    def _convert_jsonschema_error(self, error: JsonSchemaValidationError) -> list[ErrorDetail]:
        """Convert JSON schema validation error to ErrorDetail list.

        Args:
            error: JSON schema validation error

        Returns:
            List of ErrorDetail objects
        """
        errors = []

        # Convert the main error
        field_path = ".".join(str(p) for p in error.absolute_path) if error.absolute_path else None

        error_detail = ErrorDetail(
            code=ErrorCode.INVALID_INPUT,
            message=error.message,
            field=field_path,
            value=error.instance if hasattr(error, 'instance') else None
        )
        errors.append(error_detail)

        # Convert context errors (sub-errors)
        for context_error in error.context:
            context_field = ".".join(str(p) for p in context_error.absolute_path) if context_error.absolute_path else None

            context_detail = ErrorDetail(
                code=ErrorCode.INVALID_INPUT,
                message=context_error.message,
                field=context_field,
                value=context_error.instance if hasattr(context_error, 'instance') else None
            )
            errors.append(context_detail)

        return errors


def validate_json_schema(data: Any, schema: dict[str, Any]) -> list[ErrorDetail]:
    """Validate data against a JSON schema.

    Args:
        data: Data to validate
        schema: JSON schema definition

    Returns:
        List of validation errors
    """
    try:
        validate(instance=data, schema=schema)
        return []
    except JsonSchemaValidationError as e:
        validator = SchemaValidator()
        return validator._convert_jsonschema_error(e)


def validate_model(data: dict[str, Any], model_class: type[BaseModel]) -> list[ErrorDetail]:
    """Validate data against a Pydantic model.

    Args:
        data: Data to validate
        model_class: Pydantic model class

    Returns:
        List of validation errors
    """
    try:
        model_class(**data)
        return []
    except PydanticValidationError as e:
        return _convert_pydantic_error(e)


def _convert_pydantic_error(error: PydanticValidationError) -> list[ErrorDetail]:
    """Convert Pydantic validation error to ErrorDetail list.

    Args:
        error: Pydantic validation error

    Returns:
        List of ErrorDetail objects
    """
    errors = []

    for error_dict in error.errors():
        field_path = ".".join(str(loc) for loc in error_dict["loc"])
        error_type = error_dict["type"]
        message = error_dict["msg"]

        # Map Pydantic error types to our error codes
        if error_type == "missing":
            code = ErrorCode.MISSING_REQUIRED_FIELD
        elif error_type in ["type_error", "value_error"]:
            code = ErrorCode.INVALID_FORMAT
        elif "too_short" in error_type:
            code = ErrorCode.VALUE_TOO_SHORT
        elif "too_long" in error_type:
            code = ErrorCode.VALUE_TOO_LONG
        else:
            code = ErrorCode.INVALID_INPUT

        error_detail = ErrorDetail(
            code=code,
            message=message,
            field=field_path,
            value=error_dict.get("input")
        )
        errors.append(error_detail)

    return errors


# Common JSON schemas
USER_REGISTRATION_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "format": "email"
        },
        "username": {
            "type": "string",
            "minLength": 3,
            "maxLength": 50,
            "pattern": "^[a-zA-Z0-9_.-]+$"
        },
        "password": {
            "type": "string",
            "minLength": 8
        },
        "first_name": {
            "type": "string",
            "maxLength": 100
        },
        "last_name": {
            "type": "string",
            "maxLength": 100
        }
    },
    "required": ["email", "username", "password"],
    "additionalProperties": False
}

USER_UPDATE_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "format": "email"
        },
        "first_name": {
            "type": "string",
            "maxLength": 100
        },
        "last_name": {
            "type": "string",
            "maxLength": 100
        },
        "phone": {
            "type": "string",
            "pattern": "^\\+?[1-9]\\d{1,14}$"
        }
    },
    "additionalProperties": False
}

PASSWORD_CHANGE_SCHEMA = {
    "type": "object",
    "properties": {
        "current_password": {
            "type": "string"
        },
        "new_password": {
            "type": "string",
            "minLength": 8
        }
    },
    "required": ["current_password", "new_password"],
    "additionalProperties": False
}

# Initialize global schema validator
global_schema_validator = SchemaValidator()
global_schema_validator.register_schema("user_registration", USER_REGISTRATION_SCHEMA)
global_schema_validator.register_schema("user_update", USER_UPDATE_SCHEMA)
global_schema_validator.register_schema("password_change", PASSWORD_CHANGE_SCHEMA)
