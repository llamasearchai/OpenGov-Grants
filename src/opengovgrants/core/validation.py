"""Comprehensive data validation system for OpenGov Grants."""

from typing import Dict, Any, List, Optional, Union, Callable, Type
from datetime import datetime, date, timedelta
from decimal import Decimal
import re
import structlog

from pydantic import BaseModel, validator, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func

from .exceptions import ValidationError, BusinessRuleError

logger = structlog.get_logger(__name__)


class ValidationResult:
    """Result of a validation operation."""

    def __init__(self, is_valid: bool, errors: List[str] = None, warnings: List[str] = None):
        """Initialize validation result."""
        self.is_valid = is_valid
        self.errors = errors or []
        self.warnings = warnings or []

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)
        self.is_valid = False

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)

    def merge(self, other: 'ValidationResult') -> 'ValidationResult':
        """Merge with another validation result."""
        return ValidationResult(
            is_valid=self.is_valid and other.is_valid,
            errors=self.errors + other.errors,
            warnings=self.warnings + other.warnings
        )


class BaseValidator:
    """Base class for all validators."""

    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize validator."""
        self.session = session

    async def validate(self, data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate data and return result."""
        raise NotImplementedError("Subclasses must implement validate method")


class UserValidator(BaseValidator):
    """Validator for user data."""

    async def validate(self, data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate user data."""
        result = ValidationResult(is_valid=True)

        # Email validation
        if 'email' in data:
            if not self._is_valid_email(data['email']):
                result.add_error("Invalid email format")

            if self.session and await self._email_exists(data['email'], context):
                result.add_error("Email already exists")

        # Username validation
        if 'username' in data:
            if not self._is_valid_username(data['username']):
                result.add_error("Username must be 3-50 characters, alphanumeric with underscores")

            if self.session and await self._username_exists(data['username'], context):
                result.add_error("Username already exists")

        # Password validation
        if 'password' in data:
            password_result = self._validate_password_strength(data['password'])
            if not password_result.is_valid:
                result.errors.extend(password_result.errors)

        # Role validation
        if 'role' in data:
            if not self._is_valid_role(data['role']):
                result.add_error("Invalid user role")

        return result

    def _is_valid_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _is_valid_username(self, username: str) -> bool:
        """Validate username format."""
        if len(username) < 3 or len(username) > 50:
            return False
        return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

    def _validate_password_strength(self, password: str) -> ValidationResult:
        """Validate password strength."""
        result = ValidationResult(is_valid=True)

        if len(password) < 8:
            result.add_error("Password must be at least 8 characters long")

        if not re.search(r'[A-Z]', password):
            result.add_error("Password must contain at least one uppercase letter")

        if not re.search(r'[a-z]', password):
            result.add_error("Password must contain at least one lowercase letter")

        if not re.search(r'\d', password):
            result.add_error("Password must contain at least one digit")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            result.add_warning("Password should contain at least one special character")

        return result

    def _is_valid_role(self, role: str) -> bool:
        """Validate user role."""
        valid_roles = ['admin', 'manager', 'user', 'viewer']
        return role in valid_roles

    async def _email_exists(self, email: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if email already exists."""
        if not self.session:
            return False

        from ..models.database import User

        query = select(func.count()).select_from(User).where(User.email == email)

        # Exclude current user if updating
        if context and 'user_id' in context:
            query = query.where(User.id != context['user_id'])

        result = await self.session.execute(query)
        return result.scalar() > 0

    async def _username_exists(self, username: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if username already exists."""
        if not self.session:
            return False

        from ..models.database import User

        query = select(func.count()).select_from(User).where(User.username == username)

        # Exclude current user if updating
        if context and 'user_id' in context:
            query = query.where(User.id != context['user_id'])

        result = await self.session.execute(query)
        return result.scalar() > 0


class GrantValidator(BaseValidator):
    """Validator for grant data."""

    async def validate(self, data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate grant data."""
        result = ValidationResult(is_valid=True)

        # Title validation
        if 'title' in data:
            if len(data['title']) < 5 or len(data['title']) > 500:
                result.add_error("Grant title must be between 5 and 500 characters")

        # Description validation
        if 'description' in data:
            if len(data['description']) < 50:
                result.add_error("Grant description must be at least 50 characters")

        # Funding amounts validation
        if 'min_amount' in data and 'max_amount' in data:
            if data['min_amount'] and data['max_amount']:
                if data['min_amount'] > data['max_amount']:
                    result.add_error("Minimum amount cannot be greater than maximum amount")

        # Date validation
        if 'open_date' in data and 'close_date' in data:
            if data['open_date'] and data['close_date']:
                if data['open_date'] >= data['close_date']:
                    result.add_error("Open date must be before close date")

        # CFDA number validation
        if 'cfda_number' in data and data['cfda_number']:
            if not self._is_valid_cfda_number(data['cfda_number']):
                result.add_error("Invalid CFDA number format (should be XX.XXX)")

        # Grant number validation
        if 'grant_number' in data and data['grant_number']:
            if not self._is_valid_grant_number(data['grant_number']):
                result.add_error("Invalid grant number format")

        # Business rule validation
        if context and 'user_id' in context:
            business_result = await self._validate_business_rules(data, context)
            result = result.merge(business_result)

        return result

    def _is_valid_cfda_number(self, cfda_number: str) -> bool:
        """Validate CFDA number format."""
        pattern = r'^\d{2}\.\d{3}$'
        return re.match(pattern, cfda_number) is not None

    def _is_valid_grant_number(self, grant_number: str) -> bool:
        """Validate grant number format."""
        # Allow alphanumeric with dashes and underscores
        pattern = r'^[A-Za-z0-9_-]{3,50}$'
        return re.match(pattern, grant_number) is not None

    async def _validate_business_rules(self, data: Dict[str, Any], context: Dict[str, Any]) -> ValidationResult:
        """Validate business rules for grants."""
        result = ValidationResult(is_valid=True)

        # Check if user has permission to create grants
        user_id = context['user_id']
        if not await self._user_can_create_grants(user_id):
            result.add_error("User does not have permission to create grants")

        # Check for duplicate grant numbers
        if 'grant_number' in data and data['grant_number']:
            if await self._grant_number_exists(data['grant_number'], context):
                result.add_error("Grant number already exists")

        return result

    async def _user_can_create_grants(self, user_id: str) -> bool:
        """Check if user can create grants."""
        if not self.session:
            return True  # Allow in non-database context

        from ..models.database import User

        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            return False

        return user.role in ['admin', 'manager']

    async def _grant_number_exists(self, grant_number: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if grant number already exists."""
        if not self.session:
            return False

        from ..models.database import Grant

        query = select(func.count()).select_from(Grant).where(Grant.grant_number == grant_number)

        # Exclude current grant if updating
        if context and 'grant_id' in context:
            query = query.where(Grant.id != context['grant_id'])

        result = await self.session.execute(query)
        return result.scalar() > 0


class ApplicationValidator(BaseValidator):
    """Validator for application data."""

    async def validate(self, data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate application data."""
        result = ValidationResult(is_valid=True)

        # Title validation
        if 'title' in data:
            if len(data['title']) < 5 or len(data['title']) > 500:
                result.add_error("Application title must be between 5 and 500 characters")

        # Project summary validation
        if 'project_summary' in data:
            if len(data['project_summary']) < 100:
                result.add_error("Project summary must be at least 100 characters")

        # Project description validation
        if 'project_description' in data:
            if len(data['project_description']) < 200:
                result.add_error("Project description must be at least 200 characters")

        # Budget validation
        if 'requested_amount' in data and data['requested_amount']:
            if data['requested_amount'] <= 0:
                result.add_error("Requested amount must be greater than zero")

            if data['requested_amount'] > 10000000:  # 10 million
                result.add_warning("Requested amount is unusually high")

        # Matching funds validation
        if 'matching_funds' in data and data['matching_funds'] is not None:
            if data['matching_funds'] < 0:
                result.add_error("Matching funds cannot be negative")

        # Business rule validation
        if context and 'grant_id' in context:
            business_result = await self._validate_business_rules(data, context)
            result = result.merge(business_result)

        return result

    async def _validate_business_rules(self, data: Dict[str, Any], context: Dict[str, Any]) -> ValidationResult:
        """Validate business rules for applications."""
        result = ValidationResult(is_valid=True)

        grant_id = context['grant_id']

        # Check if grant exists and is open
        if not await self._grant_is_open(grant_id):
            result.add_error("Grant is not currently open for applications")

        # Check if user already has an application for this grant
        if 'applicant_id' in context:
            if await self._user_has_application_for_grant(grant_id, context['applicant_id']):
                result.add_error("User already has an application for this grant")

        # Check application deadline
        if await self._grant_deadline_passed(grant_id):
            result.add_error("Application deadline has passed")

        # Check budget constraints
        if 'requested_amount' in data and data['requested_amount']:
            budget_result = await self._validate_budget_constraints(data['requested_amount'], grant_id)
            result = result.merge(budget_result)

        return result

    async def _grant_is_open(self, grant_id: str) -> bool:
        """Check if grant is open for applications."""
        if not self.session:
            return True

        from ..models.database import Grant

        result = await self.session.execute(
            select(Grant).where(
                and_(
                    Grant.id == grant_id,
                    Grant.is_deleted == False,
                    Grant.status.in_(['published', 'active'])
                )
            )
        )
        grant = result.scalar_one_or_none()

        if not grant:
            return False

        today = date.today()

        # Check if grant is within open/close dates
        if grant.open_date and grant.open_date.date() > today:
            return False

        if grant.close_date and grant.close_date.date() < today:
            return False

        return True

    async def _user_has_application_for_grant(self, grant_id: str, applicant_id: str) -> bool:
        """Check if user already has an application for the grant."""
        if not self.session:
            return False

        from ..models.database import Application

        result = await self.session.execute(
            select(func.count()).select_from(Application).where(
                and_(
                    Application.grant_id == grant_id,
                    Application.applicant_id == applicant_id,
                    Application.is_deleted == False
                )
            )
        )
        return result.scalar() > 0

    async def _grant_deadline_passed(self, grant_id: str) -> bool:
        """Check if grant deadline has passed."""
        if not self.session:
            return False

        from ..models.database import Grant

        result = await self.session.execute(
            select(Grant.close_date).where(Grant.id == grant_id)
        )
        close_date = result.scalar_one_or_none()

        if not close_date:
            return False

        return close_date.date() < date.today()

    async def _validate_budget_constraints(self, requested_amount: float, grant_id: str) -> ValidationResult:
        """Validate budget constraints."""
        result = ValidationResult(is_valid=True)

        if not self.session:
            return result

        from ..models.database import Grant

        result = await self.session.execute(
            select(Grant.min_amount, Grant.max_amount).where(Grant.id == grant_id)
        )
        row = result.fetchone()

        if not row:
            return result

        min_amount, max_amount = row

        if min_amount and requested_amount < min_amount:
            result.add_error(f"Requested amount is below minimum of ${min_amount:,.2f}")

        if max_amount and requested_amount > max_amount:
            result.add_error(f"Requested amount exceeds maximum of ${max_amount:,.2f}")

        return result


class ValidationManager:
    """Manager for coordinating multiple validators."""

    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize validation manager."""
        self.session = session
        self.validators = {
            'user': UserValidator(session),
            'grant': GrantValidator(session),
            'application': ApplicationValidator(session)
        }

    async def validate(
        self,
        data: Dict[str, Any],
        data_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate data using appropriate validator."""
        if data_type not in self.validators:
            raise ValueError(f"No validator available for type: {data_type}")

        validator = self.validators[data_type]
        return await validator.validate(data, context)

    async def validate_multiple(
        self,
        validations: List[Dict[str, Any]]
    ) -> Dict[str, ValidationResult]:
        """Validate multiple datasets."""
        results = {}

        for validation in validations:
            data = validation['data']
            data_type = validation['type']
            context = validation.get('context', {})

            result = await self.validate(data, data_type, context)
            results[f"{data_type}_{len(results)}"] = result

        return results

    def add_validator(self, name: str, validator: BaseValidator) -> None:
        """Add a custom validator."""
        self.validators[name] = validator

    def get_validator(self, name: str) -> BaseValidator:
        """Get a validator by name."""
        return self.validators[name]


# Utility functions for common validations
def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone: str) -> bool:
    """Validate phone number format."""
    # US phone number pattern
    pattern = r'^\+?1?[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$'
    return re.match(pattern, phone) is not None


def validate_currency(amount: Union[float, Decimal, str]) -> bool:
    """Validate currency amount."""
    try:
        amount = float(amount)
        return amount >= 0 and amount <= 1000000000  # Max 1 billion
    except (ValueError, TypeError):
        return False


def validate_date_range(start_date: date, end_date: date, max_days: int = 365) -> bool:
    """Validate date range."""
    if start_date >= end_date:
        return False

    days_diff = (end_date - start_date).days
    return days_diff <= max_days


def sanitize_string(text: str, max_length: int = 1000) -> str:
    """Sanitize string input."""
    # Remove potentially dangerous characters
    text = re.sub(r'[<>"&]', '', text)

    # Trim whitespace
    text = text.strip()

    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length].rsplit(' ', 1)[0] + '...'

    return text


def validate_file_upload(
    filename: str,
    file_size: int,
    allowed_extensions: List[str],
    max_size_mb: int = 10
) -> ValidationResult:
    """Validate file upload."""
    result = ValidationResult(is_valid=True)

    # Check file extension
    file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
    if file_ext not in allowed_extensions:
        result.add_error(f"File type .{file_ext} not allowed. Allowed types: {', '.join(allowed_extensions)}")

    # Check file size
    max_size_bytes = max_size_mb * 1024 * 1024
    if file_size > max_size_bytes:
        result.add_error(f"File size {file_size} bytes exceeds maximum allowed size {max_size_bytes} bytes")

    # Check filename length
    if len(filename) > 255:
        result.add_error("Filename too long (max 255 characters)")

    return result