"""Audit logging system for OpenGov Grants."""

from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID
from contextvars import ContextVar
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import event, select, and_

from ..models.database import AuditLog, AuditAction
from .exceptions import DatabaseError

logger = structlog.get_logger(__name__)

# Context variables for audit logging
current_user_id: ContextVar[Optional[UUID]] = ContextVar('current_user_id', default=None)
current_request_id: ContextVar[Optional[str]] = ContextVar('current_request_id', default=None)
current_ip_address: ContextVar[Optional[str]] = ContextVar('current_ip_address', default=None)
current_user_agent: ContextVar[Optional[str]] = ContextVar('current_user_agent', default=None)


class AuditLogger:
    """Comprehensive audit logging system."""

    def __init__(self, session: AsyncSession):
        """Initialize audit logger."""
        self.session = session

    async def log_action(
        self,
        action: AuditAction,
        resource_type: str,
        resource_id: str,
        user_id: Optional[UUID] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        notes: Optional[str] = None,
        grant_id: Optional[UUID] = None,
        application_id: Optional[UUID] = None
    ) -> AuditLog:
        """Log an audit action."""
        try:
            # Get context information
            context_user_id = current_user_id.get() or user_id
            request_id = current_request_id.get()
            ip_address = current_ip_address.get()
            user_agent = current_user_agent.get()

            # Create audit log entry
            audit_log = AuditLog(
                user_id=context_user_id,
                grant_id=grant_id,
                application_id=application_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                old_values=old_values,
                new_values=new_values,
                ip_address=ip_address,
                user_agent=user_agent,
                notes=notes
            )

            self.session.add(audit_log)
            await self.session.flush()

            logger.info(
                "Audit log created",
                action=action.value,
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=str(context_user_id) if context_user_id else None,
                request_id=request_id
            )

            return audit_log

        except Exception as e:
            logger.error("Failed to create audit log", error=str(e))
            # Don't raise exception to avoid breaking main operations
            return None

    async def log_user_action(
        self,
        action: AuditAction,
        user_id: UUID,
        target_user_id: Optional[UUID] = None,
        notes: Optional[str] = None
    ) -> None:
        """Log user-related actions."""
        await self.log_action(
            action=action,
            resource_type="User",
            resource_id=str(target_user_id or user_id),
            user_id=user_id,
            notes=notes
        )

    async def log_grant_action(
        self,
        action: AuditAction,
        grant_id: UUID,
        user_id: UUID,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        notes: Optional[str] = None
    ) -> None:
        """Log grant-related actions."""
        await self.log_action(
            action=action,
            resource_type="Grant",
            resource_id=str(grant_id),
            user_id=user_id,
            grant_id=grant_id,
            old_values=old_values,
            new_values=new_values,
            notes=notes
        )

    async def log_application_action(
        self,
        action: AuditAction,
        application_id: UUID,
        user_id: UUID,
        grant_id: Optional[UUID] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        notes: Optional[str] = None
    ) -> None:
        """Log application-related actions."""
        await self.log_action(
            action=action,
            resource_type="Application",
            resource_id=str(application_id),
            user_id=user_id,
            grant_id=grant_id,
            application_id=application_id,
            old_values=old_values,
            new_values=new_values,
            notes=notes
        )

    async def get_audit_trail(
        self,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        user_id: Optional[UUID] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLog]:
        """Get audit trail for a resource or user."""
        try:
            query = select(AuditLog)

            conditions = []
            if resource_type:
                conditions.append(AuditLog.resource_type == resource_type)
            if resource_id:
                conditions.append(AuditLog.resource_id == resource_id)
            if user_id:
                conditions.append(AuditLog.user_id == user_id)

            if conditions:
                query = query.where(and_(*conditions))

            query = query.order_by(AuditLog.created_at.desc())
            query = query.limit(limit).offset(offset)

            result = await self.session.execute(query)
            return list(result.scalars().all())

        except Exception as e:
            logger.error("Failed to get audit trail", error=str(e))
            raise DatabaseError(f"Failed to get audit trail: {str(e)}")

    async def get_user_activity(
        self,
        user_id: UUID,
        limit: int = 50
    ) -> List[AuditLog]:
        """Get user activity history."""
        try:
            query = select(AuditLog).where(AuditLog.user_id == user_id)
            query = query.order_by(AuditLog.created_at.desc())
            query = query.limit(limit)

            result = await self.session.execute(query)
            return list(result.scalars().all())

        except Exception as e:
            logger.error("Failed to get user activity", error=str(e))
            raise DatabaseError(f"Failed to get user activity: {str(e)}")

    async def get_resource_history(
        self,
        resource_type: str,
        resource_id: str,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get complete history for a specific resource."""
        try:
            query = select(AuditLog).where(
                and_(
                    AuditLog.resource_type == resource_type,
                    AuditLog.resource_id == resource_id
                )
            )
            query = query.order_by(AuditLog.created_at.desc())
            query = query.limit(limit)

            result = await self.session.execute(query)
            return list(result.scalars().all())

        except Exception as e:
            logger.error("Failed to get resource history", error=str(e))
            raise DatabaseError(f"Failed to get resource history: {str(e)}")


class SoftDeleteManager:
    """Manager for soft delete operations."""

    def __init__(self, session: AsyncSession):
        """Initialize soft delete manager."""
        self.session = session

    async def soft_delete(
        self,
        model_class,
        resource_id: UUID,
        user_id: UUID,
        reason: Optional[str] = None
    ) -> bool:
        """Perform soft delete on a record."""
        try:
            # Get the current record
            instance = await self.session.get(model_class, resource_id)
            if not instance:
                return False

            # Check if model supports soft delete
            if not hasattr(instance, 'is_deleted'):
                raise ValueError(f"Model {model_class.__name__} does not support soft delete")

            # Get old values for audit log
            old_values = {}
            for column in model_class.__table__.columns:
                if not column.primary_key:
                    old_values[column.name] = getattr(instance, column.name)

            # Perform soft delete
            instance.is_deleted = True

            # Update timestamp
            if hasattr(instance, 'updated_at'):
                instance.updated_at = datetime.utcnow()

            await self.session.flush()

            # Create audit log
            audit_logger = AuditLogger(self.session)
            await audit_logger.log_action(
                action=AuditAction.DELETE,
                resource_type=model_class.__name__,
                resource_id=str(resource_id),
                user_id=user_id,
                old_values=old_values,
                notes=f"Soft delete: {reason}" if reason else "Soft delete"
            )

            logger.info(
                "Soft delete performed",
                resource_type=model_class.__name__,
                resource_id=str(resource_id),
                user_id=str(user_id)
            )

            return True

        except Exception as e:
            await self.session.rollback()
            logger.error("Soft delete failed", error=str(e))
            raise DatabaseError(f"Soft delete failed: {str(e)}")

    async def restore(
        self,
        model_class,
        resource_id: UUID,
        user_id: UUID,
        reason: Optional[str] = None
    ) -> bool:
        """Restore a soft-deleted record."""
        try:
            # Get the record
            instance = await self.session.get(model_class, resource_id)
            if not instance:
                return False

            # Check if model supports soft delete
            if not hasattr(instance, 'is_deleted'):
                raise ValueError(f"Model {model_class.__name__} does not support soft delete")

            # Get old values for audit log
            old_values = {}
            for column in model_class.__table__.columns:
                if not column.primary_key:
                    old_values[column.name] = getattr(instance, column.name)

            # Restore the record
            instance.is_deleted = False

            # Update timestamp
            if hasattr(instance, 'updated_at'):
                instance.updated_at = datetime.utcnow()

            await self.session.flush()

            # Create audit log
            audit_logger = AuditLogger(self.session)
            await audit_logger.log_action(
                action=AuditAction.UPDATE,
                resource_type=model_class.__name__,
                resource_id=str(resource_id),
                user_id=user_id,
                old_values=old_values,
                new_values={"is_deleted": False},
                notes=f"Restored: {reason}" if reason else "Restored"
            )

            logger.info(
                "Record restored",
                resource_type=model_class.__name__,
                resource_id=str(resource_id),
                user_id=str(user_id)
            )

            return True

        except Exception as e:
            await self.session.rollback()
            logger.error("Restore failed", error=str(e))
            raise DatabaseError(f"Restore failed: {str(e)}")


# Context managers for audit logging
class AuditContext:
    """Context manager for audit logging."""

    def __init__(
        self,
        user_id: Optional[UUID] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Initialize audit context."""
        self.user_id = user_id
        self.request_id = request_id
        self.ip_address = ip_address
        self.user_agent = user_agent

    async def __aenter__(self):
        """Enter audit context."""
        if self.user_id:
            current_user_id.set(self.user_id)
        if self.request_id:
            current_request_id.set(self.request_id)
        if self.ip_address:
            current_ip_address.set(self.ip_address)
        if self.user_agent:
            current_user_agent.set(self.user_agent)

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit audit context."""
        current_user_id.set(None)
        current_request_id.set(None)
        current_ip_address.set(None)
        current_user_agent.set(None)


# SQLAlchemy event listeners for automatic audit logging
def setup_audit_events(session_factory):
    """Set up SQLAlchemy event listeners for automatic audit logging."""

    @event.listens_for(session_factory, 'before_flush')
    def before_flush(session, flush_context, instances):
        """Capture changes before flush for audit logging."""
        for obj in session.new:
            if hasattr(obj, '__tablename__'):
                # This will be handled by the audit logger
                pass

        for obj in session.dirty:
            if hasattr(obj, '__tablename__'):
                # This will be handled by the audit logger
                pass

        for obj in session.deleted:
            if hasattr(obj, '__tablename__'):
                # This will be handled by the audit logger
                pass