"""Helper utilities for the identity service."""

import hashlib
import mimetypes
import os
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from core.logging import get_logger

logger = get_logger(__name__)


class TimestampHelper:
    """Timestamp and datetime utility functions."""

    @staticmethod
    def now_utc() -> datetime:
        """Get current UTC datetime.

        Returns:
            Current UTC datetime
        """
        return datetime.now(timezone.utc)

    @staticmethod
    def unix_timestamp() -> int:
        """Get current Unix timestamp.

        Returns:
            Current Unix timestamp
        """
        return int(time.time())

    @staticmethod
    def from_unix_timestamp(timestamp: Union[int, float]) -> datetime:
        """Convert Unix timestamp to datetime.

        Args:
            timestamp: Unix timestamp

        Returns:
            Datetime object
        """
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    @staticmethod
    def to_unix_timestamp(dt: datetime) -> int:
        """Convert datetime to Unix timestamp.

        Args:
            dt: Datetime object

        Returns:
            Unix timestamp
        """
        return int(dt.timestamp())

    @staticmethod
    def add_time(
        dt: datetime,
        days: int = 0,
        hours: int = 0,
        minutes: int = 0,
        seconds: int = 0
    ) -> datetime:
        """Add time to datetime.

        Args:
            dt: Base datetime
            days: Days to add
            hours: Hours to add
            minutes: Minutes to add
            seconds: Seconds to add

        Returns:
            New datetime with added time
        """
        delta = timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
        return dt + delta

    @staticmethod
    def is_expired(dt: datetime, now: Optional[datetime] = None) -> bool:
        """Check if datetime is expired (in the past).

        Args:
            dt: Datetime to check
            now: Current time (uses UTC now if None)

        Returns:
            True if datetime is expired
        """
        if now is None:
            now = TimestampHelper.now_utc()
        return dt < now

    @staticmethod
    def time_until_expiry(dt: datetime, now: Optional[datetime] = None) -> timedelta:
        """Get time until datetime expires.

        Args:
            dt: Expiry datetime
            now: Current time (uses UTC now if None)

        Returns:
            Time delta until expiry (negative if already expired)
        """
        if now is None:
            now = TimestampHelper.now_utc()
        return dt - now

    @staticmethod
    def format_iso(dt: datetime) -> str:
        """Format datetime as ISO string.

        Args:
            dt: Datetime to format

        Returns:
            ISO formatted string
        """
        return dt.isoformat()

    @staticmethod
    def parse_iso(iso_string: str) -> datetime:
        """Parse ISO datetime string.

        Args:
            iso_string: ISO formatted datetime string

        Returns:
            Datetime object
        """
        return datetime.fromisoformat(iso_string.replace('Z', '+00:00'))


class URLHelper:
    """URL manipulation and validation utilities."""

    @staticmethod
    def join_url(base: str, *parts: str) -> str:
        """Join URL parts safely.

        Args:
            base: Base URL
            parts: URL parts to join

        Returns:
            Joined URL
        """
        url = base
        for part in parts:
            url = urljoin(url.rstrip('/') + '/', part.lstrip('/'))
        return url

    @staticmethod
    def add_query_params(url: str, params: dict[str, Any]) -> str:
        """Add query parameters to URL.

        Args:
            url: Base URL
            params: Query parameters to add

        Returns:
            URL with added parameters
        """
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)

        # Add new parameters
        for key, value in params.items():
            if isinstance(value, list):
                query_dict[key] = value
            else:
                query_dict[key] = [str(value)]

        # Rebuild query string
        query_string = urlencode(query_dict, doseq=True)

        # Rebuild URL
        return parsed._replace(query=query_string).geturl()

    @staticmethod
    def remove_query_params(url: str, params: list[str]) -> str:
        """Remove query parameters from URL.

        Args:
            url: URL to modify
            params: List of parameter names to remove

        Returns:
            URL with parameters removed
        """
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)

        # Remove specified parameters
        for param in params:
            query_dict.pop(param, None)

        # Rebuild query string
        query_string = urlencode(query_dict, doseq=True)

        # Rebuild URL
        return parsed._replace(query=query_string).geturl()

    @staticmethod
    def get_domain(url: str) -> Optional[str]:
        """Extract domain from URL.

        Args:
            url: URL to extract domain from

        Returns:
            Domain name or None if invalid
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return None

    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs have the same domain.

        Args:
            url1: First URL
            url2: Second URL

        Returns:
            True if same domain
        """
        domain1 = URLHelper.get_domain(url1)
        domain2 = URLHelper.get_domain(url2)
        return domain1 is not None and domain1 == domain2

    @staticmethod
    def validate_url(url: str, allowed_schemes: Optional[list[str]] = None) -> bool:
        """Validate URL format and scheme.

        Args:
            url: URL to validate
            allowed_schemes: List of allowed schemes (default: http, https)

        Returns:
            True if URL is valid
        """
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']

        try:
            parsed = urlparse(url)
            return (
                parsed.scheme.lower() in allowed_schemes and
                bool(parsed.netloc)
            )
        except Exception:
            return False


class StringHelper:
    """String manipulation utilities."""

    @staticmethod
    def truncate(text: str, length: int, suffix: str = "...") -> str:
        """Truncate string to specified length.

        Args:
            text: Text to truncate
            length: Maximum length
            suffix: Suffix to add if truncated

        Returns:
            Truncated string
        """
        if len(text) <= length:
            return text

        return text[:length - len(suffix)] + suffix

    @staticmethod
    def slugify(text: str) -> str:
        """Convert text to URL-safe slug.

        Args:
            text: Text to slugify

        Returns:
            Slugified string
        """
        import re

        # Convert to lowercase and replace spaces with hyphens
        slug = text.lower().replace(' ', '-')

        # Remove non-alphanumeric characters except hyphens
        slug = re.sub(r'[^a-z0-9-]', '', slug)

        # Remove multiple consecutive hyphens
        slug = re.sub(r'-+', '-', slug)

        # Remove leading/trailing hyphens
        return slug.strip('-')

    @staticmethod
    def camel_to_snake(text: str) -> str:
        """Convert camelCase to snake_case.

        Args:
            text: CamelCase string

        Returns:
            snake_case string
        """
        import re

        # Insert underscore before uppercase letters
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\\1_\\2', text)
        return re.sub('([a-z0-9])([A-Z])', r'\\1_\\2', s1).lower()

    @staticmethod
    def snake_to_camel(text: str, capitalize_first: bool = False) -> str:
        """Convert snake_case to camelCase.

        Args:
            text: snake_case string
            capitalize_first: Whether to capitalize first letter

        Returns:
            camelCase string
        """
        components = text.split('_')
        if capitalize_first:
            return ''.join(word.capitalize() for word in components)
        else:
            return components[0] + ''.join(word.capitalize() for word in components[1:])

    @staticmethod
    def mask_string(text: str, visible_chars: int = 4, mask_char: str = "*") -> str:
        """Mask string for security purposes.

        Args:
            text: String to mask
            visible_chars: Number of characters to leave visible
            mask_char: Character to use for masking

        Returns:
            Masked string
        """
        if len(text) <= visible_chars:
            return mask_char * len(text)

        return text[:visible_chars] + mask_char * (len(text) - visible_chars)

    @staticmethod
    def extract_initials(name: str) -> str:
        """Extract initials from a name.

        Args:
            name: Full name

        Returns:
            Initials string
        """
        words = name.strip().split()
        return ''.join(word[0].upper() for word in words if word)

    @staticmethod
    def generate_random_string(length: int, chars: Optional[str] = None) -> str:
        """Generate random string.

        Args:
            length: String length
            chars: Characters to use (default: alphanumeric)

        Returns:
            Random string
        """
        import secrets
        import string

        if chars is None:
            chars = string.ascii_letters + string.digits

        return ''.join(secrets.choice(chars) for _ in range(length))


class FileHelper:
    """File and path utilities."""

    @staticmethod
    def get_file_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
        """Calculate file hash.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm

        Returns:
            File hash
        """
        hash_obj = hashlib.new(algorithm)

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """Get file size in bytes.

        Args:
            file_path: Path to file

        Returns:
            File size in bytes
        """
        return os.path.getsize(file_path)

    @staticmethod
    def get_mime_type(file_path: Union[str, Path]) -> Optional[str]:
        """Get MIME type of file.

        Args:
            file_path: Path to file

        Returns:
            MIME type or None
        """
        mime_type, _ = mimetypes.guess_type(str(file_path))
        return mime_type

    @staticmethod
    def ensure_directory(dir_path: Union[str, Path]) -> None:
        """Ensure directory exists, create if it doesn't.

        Args:
            dir_path: Directory path
        """
        Path(dir_path).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def safe_filename(filename: str) -> str:
        """Make filename safe for filesystem.

        Args:
            filename: Original filename

        Returns:
            Safe filename
        """
        import re

        # Remove or replace unsafe characters
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)

        # Remove leading/trailing dots and spaces
        safe_name = safe_name.strip('. ')

        # Ensure it's not empty
        if not safe_name:
            safe_name = "file"

        return safe_name

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in human-readable format.

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"


class CacheHelper:
    """Simple in-memory cache utilities."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        """Initialize cache helper.

        Args:
            max_size: Maximum number of items to cache
            ttl_seconds: Time to live in seconds
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict = OrderedDict()
        self._timestamps: dict[str, float] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        """Get item from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        with self._lock:
            if key not in self._cache:
                return None

            # Check if expired
            if self._is_expired(key):
                self._remove(key)
                return None

            # Move to end (LRU)
            self._cache.move_to_end(key)
            return self._cache[key]

    def set(self, key: str, value: Any) -> None:
        """Set item in cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        with self._lock:
            # Remove if exists
            if key in self._cache:
                self._remove(key)

            # Add new item
            self._cache[key] = value
            self._timestamps[key] = time.time()

            # Enforce max size
            while len(self._cache) > self.max_size:
                oldest_key = next(iter(self._cache))
                self._remove(oldest_key)

    def delete(self, key: str) -> bool:
        """Delete item from cache.

        Args:
            key: Cache key

        Returns:
            True if item was deleted
        """
        with self._lock:
            if key in self._cache:
                self._remove(key)
                return True
            return False

    def clear(self) -> None:
        """Clear all items from cache."""
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()

    def size(self) -> int:
        """Get current cache size.

        Returns:
            Number of items in cache
        """
        with self._lock:
            return len(self._cache)

    def _is_expired(self, key: str) -> bool:
        """Check if cache item is expired."""
        timestamp = self._timestamps.get(key, 0)
        return time.time() - timestamp > self.ttl_seconds

    def _remove(self, key: str) -> None:
        """Remove item from cache."""
        self._cache.pop(key, None)
        self._timestamps.pop(key, None)

    def cleanup_expired(self) -> int:
        """Remove expired items from cache.

        Returns:
            Number of items removed
        """
        with self._lock:
            expired_keys = [
                key for key in self._cache
                if self._is_expired(key)
            ]

            for key in expired_keys:
                self._remove(key)

            return len(expired_keys)
