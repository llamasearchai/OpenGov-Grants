"""Security utilities and rate limiting for OpenGov Grants."""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Union
from ipaddress import ip_address, ip_network
import structlog

from fastapi import Request, HTTPException, status
from fastapi.security import APIKeyHeader, APIKeyQuery
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .config import get_settings
from .exceptions import RateLimitError

logger = structlog.get_logger(__name__)

# API Key authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)


class RateLimiter:
    """Rate limiting implementation using sliding window."""

    def __init__(self):
        """Initialize rate limiter."""
        self.settings = get_settings()
        self.requests = {}  # key -> list of timestamps
        self.cleanup_task = None
        # Don't start cleanup task at import time - will be started when needed

    def _start_cleanup_task(self):
        """Start background task to clean up old request records."""
        if self.cleanup_task is None or self.cleanup_task.done():
            self.cleanup_task = asyncio.create_task(self._cleanup_old_records())

    async def _cleanup_old_records(self):
        """Clean up old request records periodically."""
        while True:
            try:
                await asyncio.sleep(60)  # Clean up every minute
                current_time = time.time()
                cutoff_time = current_time - 3600  # Keep records for 1 hour

                for key in list(self.requests.keys()):
                    self.requests[key] = [
                        timestamp for timestamp in self.requests[key]
                        if timestamp > cutoff_time
                    ]
                    if not self.requests[key]:
                        del self.requests[key]

            except Exception as e:
                logger.error("Rate limiter cleanup error", error=str(e))

    async def is_allowed(
        self,
        key: str,
        limit: int = None,
        window_seconds: int = 60
    ) -> bool:
        """Check if request is allowed under rate limit."""
        if limit is None:
            limit = self.settings.rate_limit_per_minute

        current_time = time.time()

        # Initialize request list for this key
        if key not in self.requests:
            self.requests[key] = []

        # Remove old requests outside the window
        cutoff_time = current_time - window_seconds
        self.requests[key] = [
            timestamp for timestamp in self.requests[key]
            if timestamp > cutoff_time
        ]

        # Check if under limit
        if len(self.requests[key]) < limit:
            self.requests[key].append(current_time)
            return True

        return False

    async def get_remaining_requests(self, key: str, limit: int = None, window_seconds: int = 60) -> int:
        """Get remaining requests allowed for the current window."""
        if limit is None:
            limit = self.settings.rate_limit_per_minute

        current_time = time.time()

        if key not in self.requests:
            return limit

        # Remove old requests outside the window
        cutoff_time = current_time - window_seconds
        self.requests[key] = [
            timestamp for timestamp in self.requests[key]
            if timestamp > cutoff_time
        ]

        return max(0, limit - len(self.requests[key]))

    async def get_reset_time(self, key: str, window_seconds: int = 60) -> float:
        """Get time when rate limit will reset."""
        if key not in self.requests or not self.requests[key]:
            return time.time() + window_seconds

        # Find the oldest request in current window
        oldest_request = min(self.requests[key])
        return oldest_request + window_seconds


class SecurityManager:
    """Security management utilities."""

    def __init__(self):
        """Initialize security manager."""
        self.settings = get_settings()
        self.rate_limiter = RateLimiter()
        self.suspicious_ips = set()
        self.failed_attempts = {}  # IP -> attempt count
        self.blocked_until = {}  # IP -> block expiry time

    async def check_rate_limit(
        self,
        request: Request,
        custom_limit: Optional[int] = None
    ) -> None:
        """Check if request is within rate limits."""
        client_ip = self._get_client_ip(request)

        if not await self.rate_limiter.is_allowed(client_ip, custom_limit):
            remaining = await self.rate_limiter.get_remaining_requests(client_ip, custom_limit)
            reset_time = await self.rate_limiter.get_reset_time(client_ip)

            logger.warning(
                "Rate limit exceeded",
                ip=client_ip,
                path=request.url.path,
                remaining=remaining,
                reset_time=reset_time
            )

            raise RateLimitError(
                message="Rate limit exceeded",
                retry_after=int(reset_time - time.time())
            )

    async def check_suspicious_activity(self, request: Request) -> None:
        """Check for suspicious activity patterns."""
        client_ip = self._get_client_ip(request)

        # Check if IP is blocked
        if client_ip in self.blocked_until:
            if time.time() < self.blocked_until[client_ip]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access blocked due to suspicious activity"
                )
            else:
                # Block period expired
                del self.blocked_until[client_ip]
                self.failed_attempts.pop(client_ip, None)

        # Check for rapid failed requests
        if client_ip in self.failed_attempts:
            if self.failed_attempts[client_ip] > 10:  # More than 10 failed attempts
                self.suspicious_ips.add(client_ip)
                self.blocked_until[client_ip] = time.time() + 300  # Block for 5 minutes

                logger.warning(
                    "IP blocked for suspicious activity",
                    ip=client_ip,
                    failed_attempts=self.failed_attempts[client_ip]
                )

    def record_failed_attempt(self, request: Request) -> None:
        """Record a failed authentication attempt."""
        client_ip = self._get_client_ip(request)

        if client_ip not in self.failed_attempts:
            self.failed_attempts[client_ip] = 0

        self.failed_attempts[client_ip] += 1

        logger.warning(
            "Failed authentication attempt recorded",
            ip=client_ip,
            total_attempts=self.failed_attempts[client_ip]
        )

    def record_successful_attempt(self, request: Request) -> None:
        """Record a successful authentication attempt."""
        client_ip = self._get_client_ip(request)

        # Reset failed attempts on successful login
        if client_ip in self.failed_attempts:
            del self.failed_attempts[client_ip]

        # Remove from suspicious IPs
        if client_ip in self.suspicious_ips:
            self.suspicious_ips.discard(client_ip)

        logger.info("Successful authentication", ip=client_ip)

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check X-Forwarded-For header (for proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in case of multiple proxies
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to client host
        return request.client.host if request.client else "unknown"

    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key for service-to-service authentication."""
        # In production, this would validate against a database or external service
        # For now, return a mock validation
        if api_key == "test-api-key":
            return {
                "service": "test-service",
                "permissions": ["read", "write"]
            }
        return None

    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP address is allowed."""
        # Check against allowed IP ranges
        allowed_ranges = [
            "127.0.0.1/8",  # localhost
            "10.0.0.0/8",   # private
            "172.16.0.0/12", # private
            "192.168.0.0/16", # private
        ]

        try:
            client_ip = ip_address(ip)
            for range_str in allowed_ranges:
                if client_ip in ip_network(range_str):
                    return True
        except ValueError:
            pass

        return False

    def sanitize_input(self, data: Union[str, Dict, List]) -> Union[str, Dict, List]:
        """Sanitize input data to prevent injection attacks."""
        if isinstance(data, str):
            # Remove potentially dangerous characters and normalize whitespace
            import re
            # More comprehensive pattern to prevent XSS and injection attacks
            sanitized = re.sub(r'[<>"\'&]|javascript:|on\w+\s*=', '', data, flags=re.IGNORECASE)
            return sanitized.strip()
        elif isinstance(data, dict):
            return {key: self.sanitize_input(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_input(item) for item in data]
        else:
            return data

    def validate_file_upload(self, filename: str, content_type: str, file_size: int) -> None:
        """Validate file upload for security."""
        # Check filename length
        if len(filename) > 255:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename too long"
            )

        # Check for dangerous file extensions
        dangerous_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            '.jar', '.php', '.asp', '.jsp', '.cgi', '.pl', '.py', '.sh'
        }

        # Use os.path.splitext for more robust extension extraction
        import os
        _, file_ext = os.path.splitext(filename.lower())
        if file_ext in dangerous_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File type not allowed"
            )

        # Check file size
        max_size = 10 * 1024 * 1024  # 10MB
        if file_size > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File too large"
            )

        # Check content type
        allowed_content_types = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf', 'text/plain', 'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]

        if content_type not in allowed_content_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Content type not allowed"
            )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to responses."""

    async def dispatch(self, request: Request, call_next):
        """Add security headers to response."""
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response


class CORSMiddleware:
    """Custom CORS middleware with enhanced security.

    Note: This is a custom implementation rather than using FastAPI's CORSMiddleware
    to provide additional security controls and logging capabilities specific to
    the OpenGov Grants application requirements.
    """

    def __init__(
        self,
        allow_origins: List[str] = None,
        allow_credentials: bool = True,
        allow_methods: List[str] = None,
        allow_headers: List[str] = None,
        max_age: int = 86400
    ):
        """Initialize CORS middleware."""
        self.allow_origins = allow_origins or ["*"]
        self.allow_credentials = allow_credentials
        self.allow_methods = allow_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allow_headers = allow_headers or ["*"]
        self.max_age = max_age

    async def __call__(self, request: Request, call_next):
        """Handle CORS headers."""
        # Check if origin is allowed
        origin = request.headers.get("origin")
        if origin and not self._is_origin_allowed(origin):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Origin not allowed"}
            )

        response = await call_next(request)

        # Add CORS headers
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif "*" in self.allow_origins:
            response.headers["Access-Control-Allow-Origin"] = "*"

        if self.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"

        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)
        response.headers["Access-Control-Max-Age"] = str(self.max_age)

        return response

    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is allowed."""
        if "*" in self.allow_origins:
            return True

        for allowed_origin in self.allow_origins:
            if allowed_origin == origin:
                return True

        return False


# Global security manager instance
security_manager = SecurityManager()