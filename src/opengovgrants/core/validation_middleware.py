"""Request/Response validation middleware for OpenGov Grants."""

import json
import time
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import structlog

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, ValidationError

from .config import get_settings
from .exceptions import ValidationError as CustomValidationError
from .validation import ValidationManager

logger = structlog.get_logger(__name__)


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Middleware for validating incoming requests."""

    def __init__(self, app, validation_manager: Optional[ValidationManager] = None):
        """Initialize validation middleware."""
        super().__init__(app)
        self.settings = get_settings()
        self.validation_manager = validation_manager or ValidationManager()

    async def dispatch(self, request: Request, call_next):
        """Process request with validation."""
        start_time = time.time()

        try:
            # Validate request size
            await self._validate_request_size(request)

            # Validate content type
            await self._validate_content_type(request)

            # Validate JSON payload if present
            if self._should_validate_json(request):
                await self._validate_json_payload(request)

            # Process request
            response = await call_next(request)

            # Validate response if needed
            if self._should_validate_response(request, response):
                response = await self._validate_response(request, response)

            # Add validation headers
            response.headers["X-Validation-Time"] = str(time.time() - start_time)

            return response

        except ValidationError as e:
            logger.warning("Request validation failed", error=str(e), path=request.url.path)
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                content={
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Request validation failed",
                        "details": str(e)
                    }
                }
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Request validation error", error=str(e), path=request.url.path)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Request validation failed",
                        "details": "Internal validation error"
                    }
                }
            )

    async def _validate_request_size(self, request: Request) -> None:
        """Validate request size."""
        max_size = self.settings.max_request_size_mb * 1024 * 1024

        # Get content length
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Request too large. Maximum size: {self.settings.max_request_size_mb}MB"
            )

    async def _validate_content_type(self, request: Request) -> None:
        """Validate content type for requests with body."""
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")

            # Allow JSON and form data
            if not (content_type.startswith("application/json") or
                    content_type.startswith("application/x-www-form-urlencoded") or
                    content_type.startswith("multipart/form-data")):
                # Don't raise error for now, just log
                logger.warning("Unexpected content type", content_type=content_type, path=request.url.path)

    async def _validate_json_payload(self, request: Request) -> None:
        """Validate JSON payload structure."""
        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                # Read and parse JSON
                body = await request.body()
                if body:
                    json.loads(body.decode())
            except json.JSONDecodeError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid JSON: {str(e)}"
                )

    def _should_validate_json(self, request: Request) -> bool:
        """Check if request should have JSON validation."""
        return request.method in ["POST", "PUT", "PATCH"] and \
               request.headers.get("content-type", "").startswith("application/json")

    def _should_validate_response(self, request: Request, response: Response) -> bool:
        """Check if response should be validated."""
        return (
            response.status_code == status.HTTP_200_OK and
            response.headers.get("content-type", "").startswith("application/json")
        )

    async def _validate_response(self, request: Request, response: Response) -> Response:
        """Validate response structure."""
        try:
            if response.body:
                body = response.body.decode()
                json.loads(body)  # Validate JSON structure
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Response validation failed", path=request.url.path)
            # Don't modify response, just log

        return response


class ResponseFormatterMiddleware(BaseHTTPMiddleware):
    """Middleware for formatting API responses."""

    def __init__(self, app):
        """Initialize response formatter."""
        super().__init__(app)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next):
        """Format API responses."""
        response = await call_next(request)

        # Only format JSON responses
        if not response.headers.get("content-type", "").startswith("application/json"):
            return response

        # Add standard response headers
        response.headers["X-API-Version"] = "v1"
        response.headers["X-Response-Time"] = str(time.time() - getattr(request.state, "start_time", time.time()))

        # Add HATEOAS links for GET requests
        if request.method == "GET" and response.status_code == status.HTTP_200_OK:
            response = await self._add_hateoas_links(request, response)

        return response

    async def _add_hateoas_links(self, request: Request, response: Response) -> Response:
        """Add HATEOAS links to response."""
        try:
            if not response.body:
                return response

            body = json.loads(response.body.decode())
            links = self._generate_links(request, body)

            if links:
                if isinstance(body, dict):
                    body["_links"] = links
                elif isinstance(body, list) and body:
                    # Add links to list items if they have IDs
                    for item in body:
                        if isinstance(item, dict) and "id" in item:
                            item["_links"] = self._generate_item_links(request, item)

                # Update response body
                response.body = json.dumps(body).encode()
                response.headers["content-length"] = str(len(response.body))

        except (json.JSONDecodeError, KeyError):
            # If we can't parse the response, leave it as is
            pass

        return response

    def _generate_links(self, request: Request, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate HATEOAS links for response."""
        links = {
            "self": {"href": str(request.url)}
        }

        # Add common links based on request path
        path = request.url.path

        if "/api/users" in path:
            links["create"] = {"href": "/api/users", "method": "POST"}
        elif "/api/grants" in path:
            links["create"] = {"href": "/api/grants", "method": "POST"}
        elif "/api/applications" in path:
            links["create"] = {"href": "/api/applications", "method": "POST"}

        return links

    def _generate_item_links(self, request: Request, item: Dict[str, Any]) -> Dict[str, Any]:
        """Generate HATEOAS links for individual items."""
        base_path = str(request.url).split('?')[0]
        item_id = item.get("id")

        if not item_id:
            return {}

        return {
            "self": {"href": f"{base_path}/{item_id}"},
            "update": {"href": f"{base_path}/{item_id}", "method": "PUT"},
            "delete": {"href": f"{base_path}/{item_id}", "method": "DELETE"}
        }


class APIVersioningMiddleware(BaseHTTPMiddleware):
    """Middleware for API versioning support."""

    def __init__(self, app, default_version: str = "v1"):
        """Initialize API versioning middleware."""
        super().__init__(app)
        self.default_version = default_version
        self.supported_versions = ["v1", "v1.1"]

    async def dispatch(self, request: Request, call_next):
        """Handle API versioning."""
        # Extract version from header or path
        version = self._extract_version(request)

        if version not in self.supported_versions:
            return JSONResponse(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                content={
                    "error": {
                        "code": "UNSUPPORTED_VERSION",
                        "message": f"API version '{version}' is not supported",
                        "supported_versions": self.supported_versions
                    }
                }
            )

        # Add version to request state
        request.state.api_version = version

        response = await call_next(request)

        # Add version information to response
        response.headers["X-API-Version"] = version
        response.headers["X-Supported-Versions"] = ", ".join(self.supported_versions)

        return response

    def _extract_version(self, request: Request) -> str:
        """Extract API version from request."""
        # Check Accept-Version header
        version_header = request.headers.get("accept-version")
        if version_header:
            return version_header

        # Check custom version header
        custom_version = request.headers.get("x-api-version")
        if custom_version:
            return custom_version

        # Check path for version
        path = request.url.path
        if path.startswith("/api/"):
            path_parts = path.split("/")
            if len(path_parts) > 2 and path_parts[2].startswith("v"):
                return path_parts[2]

        return self.default_version


class ContentNegotiationMiddleware(BaseHTTPMiddleware):
    """Middleware for content negotiation."""

    def __init__(self, app):
        """Initialize content negotiation middleware."""
        super().__init__(app)
        self.supported_formats = {
            "application/json": "json",
            "application/xml": "xml",
            "text/csv": "csv"
        }

    async def dispatch(self, request: Request, call_next):
        """Handle content negotiation."""
        # Determine response format
        accept_header = request.headers.get("accept", "application/json")
        best_format = self._select_best_format(accept_header)

        if best_format not in self.supported_formats:
            return JSONResponse(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                content={
                    "error": {
                        "code": "UNSUPPORTED_FORMAT",
                        "message": f"Format '{best_format}' is not supported",
                        "supported_formats": list(self.supported_formats.keys())
                    }
                }
            )

        # Add format to request state
        request.state.response_format = self.supported_formats[best_format]

        response = await call_next(request)

        # Set content type based on negotiated format
        if best_format != "application/json":
            response.headers["content-type"] = best_format

        return response

    def _select_best_format(self, accept_header: str) -> str:
        """Select best response format based on Accept header."""
        # Parse Accept header (simplified)
        formats = [f.strip() for f in accept_header.split(",")]

        for format_type in formats:
            if format_type in self.supported_formats:
                return format_type

        return "application/json"  # Default fallback


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for comprehensive request logging."""

    def __init__(self, app, log_sensitive_data: bool = False):
        """Initialize request logging middleware."""
        super().__init__(app)
        self.log_sensitive_data = log_sensitive_data

    async def dispatch(self, request: Request, call_next):
        """Log request details."""
        start_time = time.time()

        # Generate request ID
        request_id = request.headers.get("x-request-id", f"req_{int(time.time() * 1000000)}")
        request.state.request_id = request_id

        # Log request start
        logger.info(
            "Request started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=self._get_client_ip(request),
            user_agent=request.headers.get("user-agent", "unknown")
        )

        try:
            response = await call_next(request)

            # Calculate processing time
            processing_time = time.time() - start_time

            # Log request completion
            logger.info(
                "Request completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                processing_time=f"{processing_time:.3f}s",
                response_size=len(response.body) if hasattr(response, 'body') else 0
            )

            return response

        except Exception as e:
            processing_time = time.time() - start_time

            logger.error(
                "Request failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                error=str(e),
                processing_time=f"{processing_time:.3f}s"
            )

            raise

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"


# Utility functions for validation
async def validate_request_data(
    data: Dict[str, Any],
    validator_type: str,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Validate request data using validation manager."""
    validation_manager = ValidationManager()

    result = await validation_manager.validate(data, validator_type, context)

    if not result.is_valid:
        raise CustomValidationError(
            message="Request validation failed",
            details={"errors": result.errors, "warnings": result.warnings}
        )

    return data


def create_response(
    data: Any = None,
    message: str = "Success",
    status_code: int = 200,
    links: Optional[Dict[str, Any]] = None,
    meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create standardized API response."""
    response = {
        "success": status_code < 400,
        "message": message,
        "data": data,
        "timestamp": datetime.utcnow().isoformat()
    }

    if links:
        response["_links"] = links

    if meta:
        response["_meta"] = meta

    return response


def create_error_response(
    error: str,
    error_code: str,
    status_code: int = 400,
    details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create standardized error response."""
    return {
        "success": False,
        "error": {
            "code": error_code,
            "message": error,
            "details": details or {}
        },
        "timestamp": datetime.utcnow().isoformat()
    }


def paginate_response(
    items: list,
    total: int,
    page: int,
    page_size: int,
    base_url: str
) -> Dict[str, Any]:
    """Create paginated response."""
    total_pages = (total + page_size - 1) // page_size

    return {
        "success": True,
        "data": items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        },
        "_links": {
            "self": f"{base_url}?page={page}&page_size={page_size}",
            "first": f"{base_url}?page=1&page_size={page_size}",
            "last": f"{base_url}?page={total_pages}&page_size={page_size}",
            "next": f"{base_url}?page={page + 1}&page_size={page_size}" if page < total_pages else None,
            "prev": f"{base_url}?page={page - 1}&page_size={page_size}" if page > 1 else None
        },
        "timestamp": datetime.utcnow().isoformat()
    }