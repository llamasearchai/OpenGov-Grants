"""Custom exception hierarchy for OpenGov Grants."""

from typing import Any, Dict, Optional
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse


class BaseOpenGovException(Exception):
    """Base exception for OpenGov Grants application."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None
    ):
        """Initialize base exception."""
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.error_code = error_code or self.__class__.__name__
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "error": {
                "code": self.error_code,
                "message": self.message,
                "details": self.details
            }
        }


# Authentication & Authorization Exceptions
class AuthenticationError(BaseOpenGovException):
    """Base authentication exception."""

    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, status_code=status.HTTP_401_UNAUTHORIZED, **kwargs)


class InvalidCredentialsError(AuthenticationError):
    """Invalid credentials provided."""

    def __init__(self, message: str = "Invalid username or password", **kwargs):
        super().__init__(message, error_code="INVALID_CREDENTIALS", **kwargs)


class TokenExpiredError(AuthenticationError):
    """JWT token has expired."""

    def __init__(self, message: str = "Token has expired", **kwargs):
        super().__init__(message, error_code="TOKEN_EXPIRED", **kwargs)


class TokenInvalidError(AuthenticationError):
    """JWT token is invalid."""

    def __init__(self, message: str = "Invalid token", **kwargs):
        super().__init__(message, error_code="TOKEN_INVALID", **kwargs)


class InsufficientPermissionsError(AuthenticationError):
    """User lacks required permissions."""

    def __init__(self, message: str = "Insufficient permissions", **kwargs):
        super().__init__(message, error_code="INSUFFICIENT_PERMISSIONS", **kwargs)


class AccountLockedError(AuthenticationError):
    """User account is locked."""

    def __init__(self, message: str = "Account is locked", **kwargs):
        super().__init__(message, error_code="ACCOUNT_LOCKED", **kwargs)


# Authorization Exceptions
class AuthorizationError(BaseOpenGovException):
    """Base authorization exception."""

    def __init__(self, message: str = "Authorization failed", **kwargs):
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN, **kwargs)


class RoleNotFoundError(AuthorizationError):
    """Required role not found."""

    def __init__(self, role: str, **kwargs):
        message = f"Role '{role}' not found"
        super().__init__(message, error_code="ROLE_NOT_FOUND", **kwargs)


class PermissionDeniedError(AuthorizationError):
    """Permission denied for operation."""

    def __init__(self, resource: str, operation: str, **kwargs):
        message = f"Permission denied: {operation} on {resource}"
        super().__init__(message, error_code="PERMISSION_DENIED", **kwargs)


# Resource Exceptions
class ResourceNotFoundError(BaseOpenGovException):
    """Resource not found."""

    def __init__(self, resource: str, identifier: str = "", **kwargs):
        message = f"{resource} not found"
        if identifier:
            message = f"{resource} with identifier '{identifier}' not found"
        super().__init__(message, status_code=status.HTTP_404_NOT_FOUND, error_code="RESOURCE_NOT_FOUND", **kwargs)


class ResourceAlreadyExistsError(BaseOpenGovException):
    """Resource already exists."""

    def __init__(self, resource: str, identifier: str = "", **kwargs):
        message = f"{resource} already exists"
        if identifier:
            message = f"{resource} with identifier '{identifier}' already exists"
        super().__init__(message, status_code=status.HTTP_409_CONFLICT, error_code="RESOURCE_ALREADY_EXISTS", **kwargs)


class ValidationError(BaseOpenGovException):
    """General validation error."""

    def __init__(self, message: str = "Validation failed", details: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, details=details, error_code="VALIDATION_ERROR", **kwargs)


class ResourceValidationError(BaseOpenGovException):
    """Resource validation failed."""

    def __init__(self, message: str = "Validation failed", details: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, details=details, error_code="VALIDATION_ERROR", **kwargs)


# Database Exceptions
class DatabaseError(BaseOpenGovException):
    """Base database exception."""

    def __init__(self, message: str = "Database operation failed", **kwargs):
        super().__init__(message, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, error_code="DATABASE_ERROR", **kwargs)


class ConnectionError(DatabaseError):
    """Database connection failed."""

    def __init__(self, message: str = "Database connection failed", **kwargs):
        super().__init__(message, error_code="CONNECTION_ERROR", **kwargs)


class TransactionError(DatabaseError):
    """Database transaction failed."""

    def __init__(self, message: str = "Transaction failed", **kwargs):
        super().__init__(message, error_code="TRANSACTION_ERROR", **kwargs)


class IntegrityError(DatabaseError):
    """Database integrity constraint violated."""

    def __init__(self, message: str = "Data integrity constraint violated", **kwargs):
        super().__init__(message, error_code="INTEGRITY_ERROR", **kwargs)


# External Service Exceptions
class ExternalServiceError(BaseOpenGovException):
    """External service error."""

    def __init__(self, service: str, message: str = "External service error", **kwargs):
        super().__init__(f"{service}: {message}", status_code=status.HTTP_502_BAD_GATEWAY, error_code="EXTERNAL_SERVICE_ERROR", **kwargs)


class AIProviderError(ExternalServiceError):
    """AI provider service error."""

    def __init__(self, provider: str, message: str = "AI provider error", **kwargs):
        super().__init__(provider, message, error_code="AI_PROVIDER_ERROR", **kwargs)


class EmailServiceError(ExternalServiceError):
    """Email service error."""

    def __init__(self, message: str = "Email service error", **kwargs):
        super().__init__("Email", message, error_code="EMAIL_SERVICE_ERROR", **kwargs)


# Rate Limiting Exceptions
class RateLimitError(BaseOpenGovException):
    """Rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None, **kwargs):
        details = kwargs.get("details", {})
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(message, status_code=status.HTTP_429_TOO_MANY_REQUESTS, details=details, error_code="RATE_LIMIT_EXCEEDED", **kwargs)


# Configuration Exceptions
class ConfigurationError(BaseOpenGovException):
    """Configuration error."""

    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(message, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, error_code="CONFIGURATION_ERROR", **kwargs)


# File Upload Exceptions
class FileUploadError(BaseOpenGovException):
    """File upload error."""

    def __init__(self, message: str = "File upload failed", **kwargs):
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST, error_code="FILE_UPLOAD_ERROR", **kwargs)


class FileSizeError(FileUploadError):
    """File size exceeds limit."""

    def __init__(self, max_size: int, actual_size: int, **kwargs):
        message = f"File size {actual_size} bytes exceeds maximum allowed size {max_size} bytes"
        details = {"max_size": max_size, "actual_size": actual_size}
        super().__init__(message, details=details, error_code="FILE_SIZE_ERROR", **kwargs)


class FileTypeError(FileUploadError):
    """File type not allowed."""

    def __init__(self, allowed_types: list, actual_type: str, **kwargs):
        message = f"File type '{actual_type}' not allowed. Allowed types: {', '.join(allowed_types)}"
        details = {"allowed_types": allowed_types, "actual_type": actual_type}
        super().__init__(message, details=details, error_code="FILE_TYPE_ERROR", **kwargs)


# Business Logic Exceptions
class BusinessRuleError(BaseOpenGovException):
    """Business rule violation."""

    def __init__(self, message: str = "Business rule violation", **kwargs):
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST, error_code="BUSINESS_RULE_ERROR", **kwargs)


class GrantNotAvailableError(BusinessRuleError):
    """Grant is not available for application."""

    def __init__(self, grant_id: str, reason: str = "", **kwargs):
        message = f"Grant {grant_id} is not available for application"
        if reason:
            message += f": {reason}"
        details = {"grant_id": grant_id, "reason": reason}
        super().__init__(message, details=details, error_code="GRANT_NOT_AVAILABLE", **kwargs)


class ApplicationDeadlineError(BusinessRuleError):
    """Application deadline has passed."""

    def __init__(self, deadline: str, **kwargs):
        message = f"Application deadline {deadline} has passed"
        details = {"deadline": deadline}
        super().__init__(message, details=details, error_code="APPLICATION_DEADLINE_PASSED", **kwargs)


class BudgetExceededError(BusinessRuleError):
    """Budget limit exceeded."""

    def __init__(self, limit: float, requested: float, **kwargs):
        message = f"Budget limit {limit} exceeded by requested amount {requested}"
        details = {"limit": limit, "requested": requested}
        super().__init__(message, details=details, error_code="BUDGET_EXCEEDED", **kwargs)


# Exception handler functions for FastAPI
def handle_opengov_exception(request: Request, exc: BaseOpenGovException) -> JSONResponse:
    """Handle OpenGov exceptions in FastAPI."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict()
    )


def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions in FastAPI."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": exc.detail,
                "details": {}
            }
        }
    )


def handle_generic_exception(request: Request, exc: Exception) -> JSONResponse:
    """Handle generic exceptions in FastAPI."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "details": {}
            }
        }
    )