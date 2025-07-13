"""Structured JSON logging utilities for the identity service."""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from pydantic import BaseModel, Field


class LogRecord(BaseModel):
    """Structured log record model."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    level: str
    logger_name: str
    message: str
    module: Optional[str] = None
    function: Optional[str] = None
    line_number: Optional[int] = None
    thread_id: Optional[int] = None
    process_id: Optional[int] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        log_data = LogRecord(
            level=record.levelname,
            logger_name=record.name,
            message=record.getMessage(),
            module=record.module if hasattr(record, 'module') else None,
            function=record.funcName if hasattr(record, 'funcName') else None,
            line_number=record.lineno if hasattr(record, 'lineno') else None,
            thread_id=record.thread if hasattr(record, 'thread') else None,
            process_id=record.process if hasattr(record, 'process') else None,
            user_id=getattr(record, 'user_id', None),
            request_id=getattr(record, 'request_id', None),
            correlation_id=getattr(record, 'correlation_id', None),
            extra={
                k: v for k, v in record.__dict__.items()
                if k not in {
                    'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                    'filename', 'module', 'lineno', 'funcName', 'created',
                    'msecs', 'relativeCreated', 'thread', 'threadName',
                    'processName', 'process', 'getMessage', 'exc_info',
                    'exc_text', 'stack_info', 'user_id', 'request_id',
                    'correlation_id'
                }
            }
        )

        return log_data.model_dump_json(exclude_none=True)


class StructuredLogger:
    """Structured logger with JSON output and context management."""

    def __init__(
        self,
        name: str,
        level: str = "INFO",
        output_file: Optional[Path] = None,
        include_console: bool = True
    ):
        """Initialize structured logger.

        Args:
            name: Logger name
            level: Logging level
            output_file: Optional file output path
            include_console: Whether to include console output
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))

        # Clear existing handlers
        self.logger.handlers.clear()

        formatter = StructuredFormatter()

        # Console handler
        if include_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # File handler
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(output_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def _log_with_context(
        self,
        level: str,
        message: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Log message with context."""
        # Filter out reserved keywords that might conflict
        filtered_kwargs = {
            k: v for k, v in kwargs.items()
            if k not in {'level', 'message', 'user_id', 'request_id', 'correlation_id'}
        }

        extra = {
            'user_id': user_id,
            'request_id': request_id,
            'correlation_id': correlation_id,
            **filtered_kwargs
        }

        getattr(self.logger, level.lower())(message, extra=extra)

    def debug(
        self,
        message: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Log debug message."""
        self._log_with_context("DEBUG", message, user_id, request_id, correlation_id, **kwargs)

    def info(
        self,
        message: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Log info message."""
        self._log_with_context("INFO", message, user_id, request_id, correlation_id, **kwargs)

    def warning(
        self,
        message: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Log warning message."""
        self._log_with_context("WARNING", message, user_id, request_id, correlation_id, **kwargs)

    def error(
        self,
        message: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        exc_info: bool = False,
        **kwargs: Any
    ) -> None:
        """Log error message."""
        if exc_info:
            kwargs['exc_info'] = True
        self._log_with_context("ERROR", message, user_id, request_id, correlation_id, **kwargs)

    def critical(
        self,
        message: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        exc_info: bool = False,
        **kwargs: Any
    ) -> None:
        """Log critical message."""
        if exc_info:
            kwargs['exc_info'] = True
        self._log_with_context("CRITICAL", message, user_id, request_id, correlation_id, **kwargs)

    def log_security_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Log security-related events."""
        self.warning(
            f"Security event: {event_type}",
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            security_event=True,
            **(details or {})
        )

    def log_audit_event(
        self,
        action: str,
        resource: str,
        user_id: Optional[str] = None,
        result: str = "success",
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Log audit events."""
        self.info(
            f"Audit: {action} on {resource} - {result}",
            user_id=user_id,
            audit_action=action,
            audit_resource=resource,
            audit_result=result,
            audit_event=True,
            **(details or {})
        )


# Global logger instances
_loggers: dict[str, StructuredLogger] = {}


def get_logger(
    name: str,
    level: str = "INFO",
    output_file: Optional[Union[str, Path]] = None,
    include_console: bool = True
) -> StructuredLogger:
    """Get or create a structured logger instance.

    Args:
        name: Logger name
        level: Logging level
        output_file: Optional file output path
        include_console: Whether to include console output

    Returns:
        StructuredLogger instance
    """
    if name not in _loggers:
        file_path = Path(output_file) if output_file else None
        _loggers[name] = StructuredLogger(
            name=name,
            level=level,
            output_file=file_path,
            include_console=include_console
        )

    return _loggers[name]


def configure_logging(
    level: str = "INFO",
    log_file: Optional[Union[str, Path]] = None,
    include_console: bool = True
) -> None:
    """Configure global logging settings.

    Args:
        level: Default logging level
        log_file: Optional log file path
        include_console: Whether to include console output
    """
    # Configure root logger
    get_logger(
        "identity",
        level=level,
        output_file=log_file,
        include_console=include_console
    )

    # Set up application loggers
    get_logger("identity.auth", level=level, output_file=log_file, include_console=include_console)
    get_logger("identity.api", level=level, output_file=log_file, include_console=include_console)
    get_logger("identity.security", level=level, output_file=log_file, include_console=include_console)
