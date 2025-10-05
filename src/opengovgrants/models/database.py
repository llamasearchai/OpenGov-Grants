"""SQLAlchemy database models and utilities for OpenGov Grants."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, AsyncGenerator
from uuid import uuid4, UUID

from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey, JSON, Float, Enum, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.sql import func
import enum

from ..core.config import get_settings


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class UserRole(str, enum.Enum):
    """User role enumeration."""
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    VIEWER = "viewer"


class GrantStatus(str, enum.Enum):
    """Grant status enumeration."""
    DRAFT = "draft"
    PUBLISHED = "published"
    ACTIVE = "active"
    CLOSED = "closed"
    ARCHIVED = "archived"


class ApplicationStatus(str, enum.Enum):
    """Application status enumeration."""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class AuditAction(str, enum.Enum):
    """Audit action enumeration."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    VIEW = "view"


# User Model
class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    grants: Mapped[List["Grant"]] = relationship("Grant", back_populates="created_by_user")
    applications: Mapped[List["Application"]] = relationship("Application", back_populates="applicant")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")


# Grant Model
class Grant(Base):
    """Grant model for funding opportunities."""
    __tablename__ = "grants"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    short_description: Mapped[Optional[str]] = mapped_column(String(1000))

    # Grant details
    grant_number: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    funding_agency: Mapped[str] = mapped_column(String(255), nullable=False)
    opportunity_number: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    cfda_number: Mapped[Optional[str]] = mapped_column(String(50), index=True)

    # Financial information
    min_amount: Mapped[Optional[float]] = mapped_column(Float)
    max_amount: Mapped[Optional[float]] = mapped_column(Float)
    total_funding: Mapped[Optional[float]] = mapped_column(Float)

    # Dates
    open_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    close_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    award_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Status and metadata
    status: Mapped[GrantStatus] = mapped_column(Enum(GrantStatus), default=GrantStatus.DRAFT, nullable=False)
    eligibility_criteria: Mapped[Optional[str]] = mapped_column(Text)
    requirements: Mapped[Optional[str]] = mapped_column(Text)
    contact_info: Mapped[Optional[str]] = mapped_column(Text)

    # System fields
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    updated_by: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    created_by_user: Mapped[User] = relationship("User", back_populates="grants", foreign_keys=[created_by])
    updated_by_user: Mapped[Optional[User]] = relationship("User", foreign_keys=[updated_by])
    applications: Mapped[List["Application"]] = relationship("Application", back_populates="grant")
    attachments: Mapped[List["GrantAttachment"]] = relationship("GrantAttachment", back_populates="grant")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="grant")


# Application Model
class Application(Base):
    """Application model for grant applications."""
    __tablename__ = "applications"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    grant_id: Mapped[UUID] = mapped_column(ForeignKey("grants.id"), nullable=False)
    applicant_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)

    # Application content
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    project_summary: Mapped[str] = mapped_column(Text, nullable=False)
    project_description: Mapped[str] = mapped_column(Text, nullable=False)
    budget_narrative: Mapped[Optional[str]] = mapped_column(Text)
    timeline: Mapped[Optional[str]] = mapped_column(Text)

    # Financial information
    requested_amount: Mapped[Optional[float]] = mapped_column(Float)
    matching_funds: Mapped[Optional[float]] = mapped_column(Float)
    other_funding_sources: Mapped[Optional[str]] = mapped_column(Text)

    # Status and workflow
    status: Mapped[ApplicationStatus] = mapped_column(Enum(ApplicationStatus), default=ApplicationStatus.DRAFT, nullable=False)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    decision_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Review information
    reviewer_notes: Mapped[Optional[str]] = mapped_column(Text)
    review_score: Mapped[Optional[int]] = mapped_column(Integer)
    funding_recommended: Mapped[Optional[float]] = mapped_column(Float)

    # System fields
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    updated_by: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    grant: Mapped[Grant] = relationship("Grant", back_populates="applications")
    applicant: Mapped[User] = relationship("User", back_populates="applications", foreign_keys=[applicant_id])
    created_by_user: Mapped[User] = relationship("User", foreign_keys=[created_by])
    updated_by_user: Mapped[Optional[User]] = relationship("User", foreign_keys=[updated_by])
    attachments: Mapped[List["ApplicationAttachment"]] = relationship("ApplicationAttachment", back_populates="application")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="application")


# Attachment Models
class GrantAttachment(Base):
    """Grant attachment model."""
    __tablename__ = "grant_attachments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    grant_id: Mapped[UUID] = mapped_column(ForeignKey("grants.id"), nullable=False)

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500))

    uploaded_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    grant: Mapped[Grant] = relationship("Grant", back_populates="attachments")
    uploaded_by_user: Mapped[User] = relationship("User", foreign_keys=[uploaded_by])


class ApplicationAttachment(Base):
    """Application attachment model."""
    __tablename__ = "application_attachments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    application_id: Mapped[UUID] = mapped_column(ForeignKey("applications.id"), nullable=False)

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500))

    uploaded_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    application: Mapped[Application] = relationship("Application", back_populates="attachments")
    uploaded_by_user: Mapped[User] = relationship("User", foreign_keys=[uploaded_by])


# Audit Log Model
class AuditLog(Base):
    """Audit log model for tracking all changes."""
    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))
    grant_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("grants.id"))
    application_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("applications.id"))

    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(100), nullable=False)
    old_values: Mapped[Optional[dict]] = mapped_column(JSON)
    new_values: Mapped[Optional[dict]] = mapped_column(JSON)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(500))
    notes: Mapped[Optional[str]] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    user: Mapped[Optional[User]] = relationship("User", back_populates="audit_logs")
    grant: Mapped[Optional[Grant]] = relationship("Grant", back_populates="audit_logs")
    application: Mapped[Optional[Application]] = relationship("Application", back_populates="audit_logs")


# Database utilities
async def get_async_session(session_factory=None) -> AsyncGenerator[AsyncSession, None]:
    """Get async database session."""
    settings = get_settings()

    if session_factory is None:
        engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            future=True,
            # Connection pool configuration
            pool_size=20,          # Base number of connections
            max_overflow=30,       # Additional connections beyond pool_size
            pool_pre_ping=True,    # Validate connections before use
            pool_recycle=3600,     # Recycle connections after 1 hour
            pool_reset_on_return='commit',  # Reset connections on return
            # Performance optimizations
            pool_use_lifo=True,    # Use LIFO for better cache performance
            # Connection arguments for better performance
            connect_args={
                "check_same_thread": False,  # SQLite compatibility
                "server_side_cursors": True,  # Enable server-side cursors for large queries
            } if settings.database_url.startswith("sqlite") else {}
        )

        session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,  # Don't expire objects after commit
            autocommit=False,        # Manual transaction control
            autoflush=False,         # Manual flush control
        )

    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


class DatabaseManager:
    """Enhanced database manager with connection pooling and health checks."""

    def __init__(self):
        """Initialize database manager."""
        self.settings = get_settings()
        self._engine = None
        self._session_factory = None

    async def initialize(self) -> None:
        """Initialize database engine and session factory."""
        self._engine = create_async_engine(
            self.settings.database_url,
            echo=self.settings.debug,
            future=True,
            # Enhanced connection pool configuration
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_reset_on_return='commit',
            pool_use_lifo=True,
            # Connection arguments
            connect_args={
                "check_same_thread": False,
                "server_side_cursors": True,
            } if self.settings.database_url.startswith("sqlite") else {}
        )

        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

    async def shutdown(self) -> None:
        """Shutdown database connections."""
        if self._engine:
            await self._engine.dispose()

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with automatic cleanup."""
        if not self._session_factory:
            await self.initialize()

        session = self._session_factory()
        try:
            yield session
        finally:
            await session.close()

    async def health_check(self) -> Dict[str, Any]:
        """Perform database health check."""
        try:
            async for session in self.get_session():
                # Simple query to test connection
                result = await session.execute(text("SELECT 1 as health_check"))
                row = result.fetchone()

                if row and row[0] == 1:
                    return {
                        "status": "healthy",
                        "database": "connected",
                        "pool_size": self._engine.pool.size if self._engine else 0,
                        "checked_connections": self._engine.pool.checked_in if self._engine else 0,
                        "invalid_connections": self._engine.pool.invalid if self._engine else 0,
                    }
                else:
                    return {
                        "status": "unhealthy",
                        "database": "disconnected",
                        "error": "Health check query failed"
                    }
        except Exception as e:
            return {
                "status": "unhealthy",
                "database": "error",
                "error": str(e)
            }

    async def get_pool_status(self) -> Dict[str, Any]:
        """Get database connection pool status."""
        if not self._engine:
            return {"status": "not_initialized"}

        return {
            "pool_size": self._engine.pool.size,
            "checked_in": self._engine.pool.checked_in,
            "checked_out": self._engine.pool.checked_out,
            "invalid": self._engine.pool.invalid,
            "overflow": self._engine.pool.overflow,
            "waiters": len(self._engine.pool._pool.queue) if hasattr(self._engine.pool, '_pool') else 0,
        }


def create_tables(engine=None):
    """Create all database tables."""
    if engine is None:
        settings = get_settings()
        engine = create_async_engine(settings.database_url)

    Base.metadata.create_all(engine)


async def drop_tables(engine=None):
    """Drop all database tables."""
    if engine is None:
        settings = get_settings()
        engine = create_async_engine(settings.database_url)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)