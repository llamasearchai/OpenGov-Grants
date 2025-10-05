"""User repository implementation."""

from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.database import User, UserRole
from ..core.exceptions import ResourceNotFoundError, DatabaseError
from .base_repository import AuditableRepository


class UserRepository(AuditableRepository[User]):
    """Repository for user operations."""

    def get_model_class(self):
        """Return the User model class."""
        return User

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address."""
        try:
            result = await self.session.execute(
                select(User).where(User.email == email)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get user by email: {str(e)}")

    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        try:
            result = await self.session.execute(
                select(User).where(User.username == username)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get user by username: {str(e)}")

    async def get_active_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """Get active users with pagination."""
        try:
            result = await self.session.execute(
                select(User)
                .where(User.is_active == True)
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get active users: {str(e)}")

    async def get_users_by_role(self, role: UserRole, limit: int = 100, offset: int = 0) -> List[User]:
        """Get users by role with pagination."""
        try:
            result = await self.session.execute(
                select(User)
                .where(and_(User.role == role, User.is_active == True))
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get users by role: {str(e)}")

    async def update_last_login(self, user_id: UUID) -> bool:
        """Update user's last login timestamp."""
        try:
            stmt = select(User).where(User.id == user_id)
            result = await self.session.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                return False

            user.last_login = datetime.utcnow()
            await self.session.flush()
            return True
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to update last login: {str(e)}")

    async def increment_failed_logins(self, user_id: UUID) -> User:
        """Increment failed login attempts for user."""
        try:
            stmt = select(User).where(User.id == user_id)
            result = await self.session.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                raise ResourceNotFoundError("User", str(user_id))

            user.failed_login_attempts += 1

            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)

            await self.session.flush()
            await self.session.refresh(user)
            return user
        except ResourceNotFoundError:
            raise
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to increment failed logins: {str(e)}")

    async def reset_failed_logins(self, user_id: UUID) -> bool:
        """Reset failed login attempts for user."""
        try:
            stmt = select(User).where(User.id == user_id)
            result = await self.session.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                return False

            user.failed_login_attempts = 0
            user.locked_until = None
            await self.session.flush()
            return True
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to reset failed logins: {str(e)}")

    async def search_users(self, search_term: str, limit: int = 50) -> List[User]:
        """Search users by name or email."""
        try:
            result = await self.session.execute(
                select(User)
                .where(
                    and_(
                        User.is_active == True,
                        or_(
                            User.first_name.ilike(f"%{search_term}%"),
                            User.last_name.ilike(f"%{search_term}%"),
                            User.email.ilike(f"%{search_term}%"),
                            User.username.ilike(f"%{search_term}%")
                        )
                    )
                )
                .limit(limit)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to search users: {str(e)}")

    async def get_locked_users(self) -> List[User]:
        """Get users with locked accounts."""
        try:
            result = await self.session.execute(
                select(User)
                .where(
                    and_(
                        User.locked_until.is_not(None),
                        User.locked_until > datetime.utcnow()
                    )
                )
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get locked users: {str(e)}")

    async def unlock_user(self, user_id: UUID) -> bool:
        """Unlock a user account."""
        try:
            stmt = select(User).where(User.id == user_id)
            result = await self.session.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                return False

            user.locked_until = None
            user.failed_login_attempts = 0
            await self.session.flush()
            return True
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to unlock user: {str(e)}")