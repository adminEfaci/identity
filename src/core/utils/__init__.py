"""Core utility functions for the identity service."""

import ipaddress
import re
import secrets
import string
from datetime import datetime, timezone
from typing import Any, Optional, Union
from urllib.parse import urlparse

from ..logging import get_logger

logger = get_logger(__name__)


class SecurityUtils:
    """Security-related utility functions."""

    @staticmethod
    def generate_secure_password(
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_digits: bool = True,
        include_symbols: bool = True,
        exclude_ambiguous: bool = True
    ) -> str:
        """Generate a secure random password.

        Args:
            length: Password length
            include_uppercase: Include uppercase letters
            include_lowercase: Include lowercase letters
            include_digits: Include digits
            include_symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters (0, O, l, 1, etc.)

        Returns:
            Generated password
        """
        chars = ""

        if include_lowercase:
            chars += string.ascii_lowercase
        if include_uppercase:
            chars += string.ascii_uppercase
        if include_digits:
            chars += string.digits
        if include_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if exclude_ambiguous:
            ambiguous = "0O1lI"
            chars = ''.join(c for c in chars if c not in ambiguous)

        if not chars:
            raise ValueError("No character sets selected for password generation")

        password = ''.join(secrets.choice(chars) for _ in range(length))

        logger.debug("Secure password generated", length=length)
        return password

    @staticmethod
    def check_password_strength(password: str) -> dict[str, Any]:
        """Check password strength and return analysis.

        Args:
            password: Password to analyze

        Returns:
            Dictionary with strength analysis
        """
        analysis = {
            "length": len(password),
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_digits": bool(re.search(r'\d', password)),
            "has_symbols": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
            "has_spaces": ' ' in password,
            "score": 0,
            "strength": "very_weak"
        }

        # Calculate score
        if analysis["length"] >= 8:
            analysis["score"] += 1
        if analysis["length"] >= 12:
            analysis["score"] += 1
        if analysis["has_uppercase"]:
            analysis["score"] += 1
        if analysis["has_lowercase"]:
            analysis["score"] += 1
        if analysis["has_digits"]:
            analysis["score"] += 1
        if analysis["has_symbols"]:
            analysis["score"] += 1

        # Check for common patterns
        common_patterns = [
            r'123',
            r'abc',
            r'password',
            r'admin',
            r'qwerty'
        ]

        has_common_pattern = any(
            re.search(pattern, password.lower()) for pattern in common_patterns
        )

        if has_common_pattern:
            analysis["score"] -= 2

        # Determine strength
        if analysis["score"] <= 1:
            analysis["strength"] = "very_weak"
        elif analysis["score"] <= 2:
            analysis["strength"] = "weak"
        elif analysis["score"] <= 4:
            analysis["strength"] = "medium"
        elif analysis["score"] <= 5:
            analysis["strength"] = "strong"
        else:
            analysis["strength"] = "very_strong"

        return analysis

    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input to prevent injection attacks.

        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string
        """
        if not isinstance(input_str, str):
            return ""

        # Truncate to max length
        sanitized = input_str[:max_length]

        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')

        # Strip leading/trailing whitespace
        sanitized = sanitized.strip()

        return sanitized

    @staticmethod
    def is_safe_url(url: str, allowed_hosts: Optional[list[str]] = None) -> bool:
        """Check if URL is safe for redirects.

        Args:
            url: URL to check
            allowed_hosts: List of allowed hosts

        Returns:
            True if URL is safe
        """
        try:
            parsed = urlparse(url)

            # Check for javascript: or data: schemes
            if parsed.scheme.lower() in ['javascript', 'data', 'vbscript']:
                return False

            # If no allowed hosts specified, allow relative URLs
            if not allowed_hosts:
                return not parsed.netloc or parsed.netloc == ''

            # Check if host is in allowed list
            if parsed.netloc:
                return parsed.netloc.lower() in [host.lower() for host in allowed_hosts]

            return True

        except Exception:
            return False

    @staticmethod
    def validate_ip_address(ip_str: str) -> bool:
        """Validate IP address format.

        Args:
            ip_str: IP address string

        Returns:
            True if valid IP address
        """
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP address is private.

        Args:
            ip_str: IP address string

        Returns:
            True if private IP address
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False


class ValidationUtils:
    """Validation utility functions."""

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format.

        Args:
            email: Email address to validate

        Returns:
            True if valid email format
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_phone(phone: str, country_code: Optional[str] = None) -> bool:
        """Validate phone number format.

        Args:
            phone: Phone number to validate
            country_code: Optional country code for validation

        Returns:
            True if valid phone format
        """
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', phone)

        # Basic validation - should have 10-15 digits
        if len(digits_only) < 10 or len(digits_only) > 15:
            return False

        # More specific validation based on country code
        if country_code == "US":
            # US phone numbers should have 10 digits
            return len(digits_only) == 10
        elif country_code == "UK":
            # UK phone numbers should have 11 digits
            return len(digits_only) == 11

        return True

    @staticmethod
    def validate_username(username: str) -> dict[str, Any]:
        """Validate username and return analysis.

        Args:
            username: Username to validate

        Returns:
            Dictionary with validation results
        """
        result = {
            "valid": True,
            "errors": []
        }

        # Length check
        if len(username) < 3:
            result["valid"] = False
            result["errors"].append("Username must be at least 3 characters long")

        if len(username) > 50:
            result["valid"] = False
            result["errors"].append("Username must be no more than 50 characters long")

        # Character check
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            result["valid"] = False
            result["errors"].append("Username can only contain letters, numbers, dots, hyphens, and underscores")

        # Must start with letter or number
        if not re.match(r'^[a-zA-Z0-9]', username):
            result["valid"] = False
            result["errors"].append("Username must start with a letter or number")

        # Cannot end with special characters
        if username.endswith(('.', '-', '_')):
            result["valid"] = False
            result["errors"].append("Username cannot end with special characters")

        # No consecutive special characters
        if re.search(r'[._-]{2,}', username):
            result["valid"] = False
            result["errors"].append("Username cannot contain consecutive special characters")

        return result

    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format.

        Args:
            url: URL to validate

        Returns:
            True if valid URL format
        """
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False

    @staticmethod
    def validate_date_string(date_str: str, format_str: str = "%Y-%m-%d") -> bool:
        """Validate date string format.

        Args:
            date_str: Date string to validate
            format_str: Expected date format

        Returns:
            True if valid date format
        """
        try:
            datetime.strptime(date_str, format_str)
            return True
        except ValueError:
            return False


class DataUtils:
    """Data manipulation utility functions."""

    @staticmethod
    def deep_merge_dicts(dict1: dict[str, Any], dict2: dict[str, Any]) -> dict[str, Any]:
        """Deep merge two dictionaries.

        Args:
            dict1: First dictionary
            dict2: Second dictionary

        Returns:
            Merged dictionary
        """
        result = dict1.copy()

        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = DataUtils.deep_merge_dicts(result[key], value)
            else:
                result[key] = value

        return result

    @staticmethod
    def flatten_dict(d: dict[str, Any], parent_key: str = '', sep: str = '.') -> dict[str, Any]:
        """Flatten a nested dictionary.

        Args:
            d: Dictionary to flatten
            parent_key: Parent key prefix
            sep: Separator for nested keys

        Returns:
            Flattened dictionary
        """
        items = []

        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k

            if isinstance(v, dict):
                items.extend(DataUtils.flatten_dict(v, new_key, sep).items())
            else:
                items.append((new_key, v))

        return dict(items)

    @staticmethod
    def remove_none_values(d: dict[str, Any]) -> dict[str, Any]:
        """Remove None values from dictionary.

        Args:
            d: Dictionary to clean

        Returns:
            Dictionary without None values
        """
        return {k: v for k, v in d.items() if v is not None}

    @staticmethod
    def paginate_list(items: list[Any], page: int, per_page: int) -> dict[str, Any]:
        """Paginate a list of items.

        Args:
            items: List of items to paginate
            page: Page number (1-based)
            per_page: Items per page

        Returns:
            Dictionary with pagination info and items
        """
        total_items = len(items)
        total_pages = (total_items + per_page - 1) // per_page

        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page

        return {
            "items": items[start_idx:end_idx],
            "page": page,
            "per_page": per_page,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages
        }


def generate_correlation_id() -> str:
    """Generate a correlation ID for request tracing.

    Returns:
        Correlation ID string
    """
    return secrets.token_urlsafe(16)


def get_client_ip(headers: dict[str, str]) -> Optional[str]:
    """Extract client IP from request headers.

    Args:
        headers: Request headers

    Returns:
        Client IP address or None
    """
    # Check common headers for client IP
    ip_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP',
        'CF-Connecting-IP',
        'True-Client-IP'
    ]

    for header in ip_headers:
        ip = headers.get(header)
        if ip:
            # X-Forwarded-For can contain multiple IPs, take the first one
            ip = ip.split(',')[0].strip()
            if SecurityUtils.validate_ip_address(ip):
                return ip

    return None


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data for logging.

    Args:
        data: Data to mask
        mask_char: Character to use for masking
        visible_chars: Number of characters to leave visible

    Returns:
        Masked data string
    """
    if len(data) <= visible_chars:
        return mask_char * len(data)

    return data[:visible_chars] + mask_char * (len(data) - visible_chars)


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.1f}s"
    else:
        hours = int(seconds // 3600)
        remaining_seconds = seconds % 3600
        minutes = int(remaining_seconds // 60)
        return f"{hours}h {minutes}m"
