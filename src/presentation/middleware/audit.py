"""HTTP Audit Middleware for FastAPI Applications.

This module provides middleware for auditing HTTP requests and responses,
capturing relevant information for security and compliance purposes.
"""

import json
import logging
import time
from typing import Any, Callable, Optional
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse

from ...infrastructure.audit.config import AuditConfig
from ...infrastructure.messaging import MessageBus

logger = logging.getLogger(__name__)


class HTTPAuditMiddleware(BaseHTTPMiddleware):
    """HTTP Audit Middleware for FastAPI applications.
    
    Captures HTTP requests and responses for audit logging including
    user context, request/response data, and timing information.
    """

    def __init__(
        self,
        app: Any,
        message_bus: MessageBus,
        audit_config: AuditConfig,
    ) -> None:
        """Initialize HTTP audit middleware.
        
        Args:
            app: FastAPI application instance
            message_bus: Message bus for publishing audit events
            audit_config: Audit configuration settings
        """
        super().__init__(app)
        self._message_bus = message_bus
        self._audit_config = audit_config

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with audit logging.
        
        Args:
            request: HTTP request
            call_next: Next middleware in chain
            
        Returns:
            HTTP response
        """
        # Skip audit for excluded paths
        if not self._audit_config.enabled or self._audit_config.is_path_excluded(request.url.path):
            return await call_next(request)

        # Generate correlation ID for this request
        correlation_id = str(uuid4())

        # Capture request start time
        start_time = time.time()

        # Capture request information
        request_info = await self._capture_request_info(request, correlation_id)

        # Process the request
        try:
            response = await call_next(request)

            # Capture response information
            response_info = await self._capture_response_info(response)

            # Calculate request duration
            duration_ms = (time.time() - start_time) * 1000

            # Publish audit event asynchronously
            if self._audit_config.async_processing:
                await self._publish_audit_event(
                    request_info=request_info,
                    response_info=response_info,
                    duration_ms=duration_ms,
                    correlation_id=correlation_id,
                )
            else:
                # For synchronous processing, we would process immediately
                # This is typically used in testing environments
                logger.debug(f"Audit event for {request.method} {request.url.path} (sync mode)")

            return response

        except Exception as e:
            # Capture error information
            error_response_info = {
                "status_code": 500,
                "headers": {},
                "body": {"error": "Internal server error"},
            }

            duration_ms = (time.time() - start_time) * 1000

            # Publish audit event for the error
            if self._audit_config.async_processing:
                await self._publish_audit_event(
                    request_info=request_info,
                    response_info=error_response_info,
                    duration_ms=duration_ms,
                    correlation_id=correlation_id,
                    error=str(e),
                )

            # Re-raise the exception
            raise

    async def _capture_request_info(self, request: Request, correlation_id: str) -> dict[str, Any]:
        """Capture relevant request information for audit logging.
        
        Args:
            request: HTTP request
            correlation_id: Correlation ID for this request
            
        Returns:
            Dictionary containing request information
        """
        # Get user information from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id", None)
        user_email = getattr(request.state, "user_email", None)

        # Extract client information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent")

        # Capture request body for certain methods
        request_body = None
        if request.method in {"POST", "PUT", "PATCH"} and request.headers.get("content-type"):
            try:
                # Read the request body
                body = await request.body()
                if body:
                    content_type = request.headers.get("content-type", "").lower()
                    if "application/json" in content_type:
                        request_body = json.loads(body.decode("utf-8"))
                    elif "application/x-www-form-urlencoded" in content_type:
                        # Parse form data
                        form_data = await request.form()
                        request_body = dict(form_data)
                    else:
                        # For other content types, just capture size
                        request_body = {
                            "content_type": content_type,
                            "size_bytes": len(body),
                            "data": "***BINARY_DATA***",
                        }
            except Exception as e:
                logger.warning(f"Failed to capture request body: {e}")
                request_body = {"error": "Failed to capture request body"}

        return {
            "method": request.method,
            "path": str(request.url.path),
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "body": request_body,
            "user_id": user_id,
            "user_email": user_email,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "correlation_id": correlation_id,
            "occurred_at": time.time(),
        }

    async def _capture_response_info(self, response: Response) -> dict[str, Any]:
        """Capture relevant response information for audit logging.
        
        Args:
            response: HTTP response
            
        Returns:
            Dictionary containing response information
        """
        response_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": None,
        }

        # Try to capture response body for certain status codes and content types
        if (
            response.status_code < 500  # Don't capture server error responses
            and hasattr(response, "body")
            and response.body
        ):
            try:
                content_type = response.headers.get("content-type", "").lower()
                if "application/json" in content_type:
                    # For JSON responses, parse and potentially truncate
                    body_text = response.body.decode("utf-8")
                    if len(body_text) <= self._audit_config.max_payload_size:
                        response_info["body"] = json.loads(body_text)
                    else:
                        response_info["body"] = {
                            "truncated": True,
                            "size_bytes": len(body_text),
                            "max_size": self._audit_config.max_payload_size,
                        }
                elif isinstance(response, StreamingResponse):
                    # Don't capture streaming response bodies
                    response_info["body"] = {"streaming": True}
                else:
                    # For other content types, just capture metadata
                    response_info["body"] = {
                        "content_type": content_type,
                        "size_bytes": len(response.body),
                    }
            except Exception as e:
                logger.warning(f"Failed to capture response body: {e}")
                response_info["body"] = {"error": "Failed to capture response body"}

        return response_info

    async def _publish_audit_event(
        self,
        request_info: dict[str, Any],
        response_info: dict[str, Any],
        duration_ms: float,
        correlation_id: str,
        error: Optional[str] = None,
    ) -> None:
        """Publish audit event to message bus.
        
        Args:
            request_info: Request information
            response_info: Response information
            duration_ms: Request duration in milliseconds
            correlation_id: Correlation ID for this request
            error: Error message if request failed
        """
        try:
            # Sanitize sensitive data
            sanitized_request = self._sanitize_data(request_info)
            sanitized_response = self._sanitize_data(response_info)

            # Publish to message bus
            task_id = await self._message_bus.publish_audit_api_request(
                method=request_info["method"],
                path=request_info["path"],
                status_code=response_info["status_code"],
                occurred_at=time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime(request_info["occurred_at"])),
                user_id=request_info["user_id"],
                session_id=None,  # Could be extracted from request if needed
                ip_address=request_info["client_ip"],
                user_agent=request_info["user_agent"],
                request_data=sanitized_request,
                response_data=sanitized_response,
                duration_ms=duration_ms,
                correlation_id=correlation_id,
            )

            if task_id:
                logger.debug(f"Published audit event for {request_info['method']} {request_info['path']} with task ID {task_id}")
            else:
                logger.warning(f"Failed to publish audit event for {request_info['method']} {request_info['path']}")

        except Exception as e:
            logger.error(f"Error publishing audit event: {e}")

    def _sanitize_data(self, data: Any) -> Any:
        """Sanitize data by masking sensitive fields.
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data with sensitive fields masked
        """
        if not self._audit_config.mask_sensitive_data:
            return data

        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if self._audit_config.should_mask_field(key):
                    sanitized[key] = "***MASKED***"
                else:
                    sanitized[key] = self._sanitize_data(value)
            return sanitized

        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]

        else:
            return data

    def _get_client_ip(self, request: Request) -> Optional[str]:
        """Extract client IP address from request headers.
        
        Args:
            request: HTTP request
            
        Returns:
            Client IP address or None if not found
        """
        # Check various headers that may contain the real client IP
        ip_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Client-IP",
            "CF-Connecting-IP",  # Cloudflare
            "True-Client-IP",    # Akamai
        ]

        for header in ip_headers:
            ip = request.headers.get(header)
            if ip:
                # X-Forwarded-For can contain multiple IPs, take the first one
                return ip.split(",")[0].strip()

        # Fall back to direct client IP
        if hasattr(request, "client") and request.client:
            return request.client.host

        return None
