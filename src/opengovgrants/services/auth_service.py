"""Authentication service for OpenGov Grants."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from uuid import UUID
import structlog

from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.exceptions import AuthenticationError, InvalidCredentialsError, TokenExpiredError, TokenInvalidError
from ..models.database import User, UserRole
from ..repositories.user_repository import UserRepository
from ..core.audit import AuditLogger

logger = structlog.get_logger(__name__)

security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """Service for handling authentication and authorization."""

    def __init__(self, session: AsyncSession, cache=None):
        """Initialize auth service."""
        self.session = session
        self.cache = cache
        self.settings = get_settings()
        self.user_repository = UserRepository(session)
        self.audit_logger = AuditLogger(session)

        # JWT configuration
        self.secret_key = self.settings.jwt_secret_key or "your-secret-key-change-this-in-production"
        self.algorithm = self.settings.jwt_algorithm or "HS256"
        self.access_token_expire_minutes = self.settings.jwt_expire_minutes or 30
        self.refresh_token_expire_days = self.settings.refresh_token_expire_days or 7

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        """Hash a password."""
        return pwd_context.hash(password)

    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token."""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire, "type": "access"})

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token."""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire, "type": "refresh"})

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            if payload.get("type") != token_type:
                logger.warning("Invalid token type", token_type=token_type, payload_type=payload.get("type"))
                return None

            return payload

        except JWTError as e:
            logger.warning("Token verification failed", error=str(e))
            return None
        except Exception as e:
            logger.error("Token verification error", error=str(e))
            return None

    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username/email and password."""
        try:
            # Try to find user by username or email
            user = await self.user_repository.get_by_username(username)
            if not user:
                user = await self.user_repository.get_by_email(username)

            if not user:
                logger.warning("User not found", username=username)
                return None

            # Check if user is active
            if not user.is_active:
                logger.warning("Inactive user attempted login", user_id=str(user.id))
                return None

            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                logger.warning("Locked account attempted login", user_id=str(user.id))
                return None

            # Verify password
            if not self.verify_password(password, user.hashed_password):
                # Increment failed login attempts
                await self.user_repository.increment_failed_logins(user.id)
                logger.warning("Invalid password", user_id=str(user.id))
                return None

            # Successful login - reset failed attempts
            await self.user_repository.reset_failed_logins(user.id)
            await self.user_repository.update_last_login(user.id)

            # Log successful login
            await self.audit_logger.log_user_action(
                action="login",
                user_id=user.id,
                target_user_id=user.id,
                notes="Successful login"
            )

            logger.info("User authenticated successfully", user_id=str(user.id))
            return user

        except Exception as e:
            logger.error("Authentication error", error=str(e))
            return None

    async def get_current_user(self, token: str) -> User:
        """Get current user from JWT token."""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        payload = self.verify_token(token, "access")
        if payload is None:
            raise credentials_exception

        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception

        try:
            user_id_uuid = UUID(user_id)
        except ValueError:
            raise credentials_exception

        # Try to get from cache first
        if self.cache:
            cache_key = f"user:{user_id_uuid}"
            cached_user = await self.cache.get(cache_key)
            if cached_user:
                return User(**cached_user)

        # Get from database
        user = await self.user_repository.get_by_id(user_id_uuid)
        if user is None:
            raise credentials_exception

        # Cache user data
        if self.cache:
            await self.cache.set(
                cache_key,
                user.__dict__,
                ttl=300  # 5 minutes
            )

        return user

    async def get_current_active_user(self, token: str) -> User:
        """Get current active user from JWT token."""
        current_user = await self.get_current_user(token)

        if not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )

        return current_user

    async def get_current_user_with_roles(self, token: str, required_roles: List[UserRole]) -> User:
        """Get current user and verify they have required roles."""
        current_user = await self.get_current_active_user(token)

        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )

        return current_user

    async def login(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user and return tokens."""
        user = await self.authenticate_user(username, password)
        if not user:
            raise InvalidCredentialsError()

        # Create tokens
        access_token = self.create_access_token(
            data={"sub": str(user.id), "username": user.username, "role": user.role.value}
        )
        refresh_token = self.create_refresh_token(
            data={"sub": str(user.id), "username": user.username}
        )

        # Cache refresh token
        if self.cache:
            await self.cache.set(
                f"refresh_token:{user.id}",
                refresh_token,
                ttl=self.refresh_token_expire_days * 24 * 3600
            )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60,
            "user": {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "role": user.role.value
            }
        }

    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token using refresh token."""
        payload = self.verify_token(refresh_token, "refresh")
        if payload is None:
            raise TokenInvalidError()

        user_id: str = payload.get("sub")
        if user_id is None:
            raise TokenInvalidError()

        try:
            user_id_uuid = UUID(user_id)
        except ValueError:
            raise TokenInvalidError()

        # Check if refresh token is valid (in cache)
        if self.cache:
            cached_token = await self.cache.get(f"refresh_token:{user_id_uuid}")
            if cached_token != refresh_token:
                raise TokenInvalidError()

        # Get user
        user = await self.user_repository.get_by_id(user_id_uuid)
        if not user or not user.is_active:
            raise TokenInvalidError()

        # Create new access token
        access_token = self.create_access_token(
            data={"sub": str(user.id), "username": user.username, "role": user.role.value}
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60
        }

    async def logout(self, token: str) -> bool:
        """Logout user and invalidate tokens."""
        try:
            payload = self.verify_token(token, "access")
            if payload is None:
                return False

            user_id: str = payload.get("sub")
            if user_id is None:
                return False

            user_id_uuid = UUID(user_id)

            # Remove refresh token from cache
            if self.cache:
                await self.cache.delete(f"refresh_token:{user_id_uuid}")
                await self.cache.delete(f"user:{user_id_uuid}")

            # Log logout
            await self.audit_logger.log_user_action(
                action="logout",
                user_id=user_id_uuid,
                target_user_id=user_id_uuid,
                notes="User logged out"
            )

            logger.info("User logged out", user_id=user_id)
            return True

        except Exception as e:
            logger.error("Logout error", error=str(e))
            return False

    async def change_password(self, user_id: UUID, current_password: str, new_password: str) -> bool:
        """Change user password."""
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Verify current password
            if not self.verify_password(current_password, user.hashed_password):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Incorrect current password"
                )

            # Hash new password
            hashed_new_password = self.get_password_hash(new_password)

            # Update password
            await self.user_repository.update(
                user_id,
                {"hashed_password": hashed_new_password},
                user_id
            )

            # Invalidate all user sessions
            if self.cache:
                await self.cache.delete(f"user:{user_id}")
                await self.cache.delete(f"refresh_token:{user_id}")

            # Log password change
            await self.audit_logger.log_user_action(
                action="update",
                user_id=user_id,
                target_user_id=user_id,
                notes="Password changed"
            )

            logger.info("Password changed", user_id=str(user_id))
            return True

        except HTTPException:
            raise
        except Exception as e:
            logger.error("Password change error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to change password"
            )

    async def reset_password(self, email: str) -> bool:
        """Initiate password reset process."""
        try:
            user = await self.user_repository.get_by_email(email)
            if not user:
                # Don't reveal if email exists
                return True

            # Generate reset token (in production, this would be a proper reset token)
            reset_token = self.create_access_token(
                data={"sub": str(user.id), "type": "reset"}
            )

            # In production, send email with reset token
            logger.info("Password reset initiated", user_id=str(user.id), email=email)

            # Log password reset request
            await self.audit_logger.log_user_action(
                action="update",
                user_id=user.id,
                target_user_id=user.id,
                notes="Password reset requested"
            )

            return True

        except Exception as e:
            logger.error("Password reset error", error=str(e))
            return False

    async def create_user(
        self,
        email: str,
        username: str,
        password: str,
        first_name: str,
        last_name: str,
        role: UserRole = UserRole.USER,
        created_by: Optional[UUID] = None
    ) -> User:
        """Create a new user."""
        try:
            # Hash password
            hashed_password = self.get_password_hash(password)

            # Create user data
            user_data = {
                "email": email,
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "hashed_password": hashed_password,
                "role": role,
                "is_active": True
            }

            # Create user
            user = await self.user_repository.create(user_data, created_by)

            # Log user creation
            await self.audit_logger.log_user_action(
                action="create",
                user_id=created_by or user.id,
                target_user_id=user.id,
                notes="User account created"
            )

            logger.info("User created", user_id=str(user.id), created_by=str(created_by))
            return user

        except Exception as e:
            logger.error("User creation error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )

    async def update_user(
        self,
        user_id: UUID,
        update_data: Dict[str, Any],
        updated_by: UUID
    ) -> User:
        """Update user information."""
        try:
            # Update user
            user = await self.user_repository.update(user_id, update_data, updated_by)

            # Invalidate cache
            if self.cache:
                await self.cache.delete(f"user:{user_id}")

            # Log user update
            await self.audit_logger.log_user_action(
                action="update",
                user_id=updated_by,
                target_user_id=user_id,
                notes="User information updated"
            )

            logger.info("User updated", user_id=str(user_id), updated_by=str(updated_by))
            return user

        except Exception as e:
            logger.error("User update error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user"
            )

    async def deactivate_user(self, user_id: UUID, deactivated_by: UUID) -> bool:
        """Deactivate a user account."""
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Update user
            await self.user_repository.update(
                user_id,
                {"is_active": False},
                deactivated_by
            )

            # Invalidate cache
            if self.cache:
                await self.cache.delete(f"user:{user_id}")
                await self.cache.delete(f"refresh_token:{user_id}")

            # Log user deactivation
            await self.audit_logger.log_user_action(
                action="update",
                user_id=deactivated_by,
                target_user_id=user_id,
                notes="User account deactivated"
            )

            logger.info("User deactivated", user_id=str(user_id), deactivated_by=str(deactivated_by))
            return True

        except HTTPException:
            raise
        except Exception as e:
            logger.error("User deactivation error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to deactivate user"
            )