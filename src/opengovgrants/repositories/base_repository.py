"""Base repository pattern implementation."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, List, Optional, Dict, Any, Sequence
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from ..models.database import Base, User, Grant, Application, AuditLog, AuditAction
from ..core.exceptions import ResourceNotFoundError, DatabaseError

T = TypeVar('T', bound=Base)


class BaseRepository(Generic[T], ABC):
    """Base repository class with common CRUD operations."""

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session."""
        self.session = session
        self.model_class = self.get_model_class()

    @abstractmethod
    def get_model_class(self) -> type[T]:
        """Return the model class this repository handles."""
        pass

    async def create(self, data: Dict[str, Any], user_id: Optional[UUID] = None) -> T:
        """Create a new record with audit logging."""
        try:
            instance = self.model_class(**data)
            self.session.add(instance)
            await self.session.flush()
            await self.session.refresh(instance)

            # Create audit log if user_id is provided
            if user_id:
                from ..core.audit import AuditLogger
                audit_logger = AuditLogger(self.session)
                await audit_logger.log_action(
                    action="create",
                    resource_type=self.model_class.__name__,
                    resource_id=str(instance.id),
                    user_id=user_id,
                    new_values=data
                )

            return instance
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to create {self.model_class.__name__}: {str(e)}")

    async def get_by_id(self, id: UUID) -> Optional[T]:
        """Get a record by ID."""
        try:
            result = await self.session.execute(
                select(self.model_class).where(self.model_class.id == id)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get {self.model_class.__name__} by ID: {str(e)}")

    async def get_by_ids(self, ids: List[UUID]) -> List[T]:
        """Get multiple records by IDs."""
        try:
            result = await self.session.execute(
                select(self.model_class).where(self.model_class.id.in_(ids))
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get {self.model_class.__name__}s by IDs: {str(e)}")

    async def update(self, id: UUID, data: Dict[str, Any], user_id: Optional[UUID] = None, use_optimistic_lock: bool = True) -> T:
        """Update a record by ID with optional optimistic locking and audit logging."""
        try:
            # Check if record exists
            instance = await self.get_by_id(id)
            if not instance:
                raise ResourceNotFoundError(
                    self.model_class.__name__,
                    str(id)
                )

            # Get old values for audit logging
            old_values = {}
            for column in self.model_class.__table__.columns:
                if not column.primary_key:
                    old_values[column.name] = getattr(instance, column.name)

            # Use optimistic locking if supported
            if use_optimistic_lock and hasattr(instance, 'version'):
                from ..core.locking import OptimisticLockManager
                lock_manager = OptimisticLockManager(self.session)
                result = await lock_manager.update_with_version(
                    self.model_class,
                    id,
                    data,
                    getattr(instance, 'version', 0)
                )
            else:
                # Standard update without optimistic locking
                stmt = update(self.model_class).where(self.model_class.id == id).values(**data)
                await self.session.execute(stmt)
                await self.session.flush()
                await self.session.refresh(instance)
                result = instance

            # Create audit log
            if user_id:
                from ..core.audit import AuditLogger
                audit_logger = AuditLogger(self.session)

                # Get new values for audit logging
                new_values = {}
                for column in self.model_class.__table__.columns:
                    if not column.primary_key:
                        new_values[column.name] = getattr(result, column.name)

                await audit_logger.log_action(
                    action="update",
                    resource_type=self.model_class.__name__,
                    resource_id=str(id),
                    user_id=user_id,
                    old_values=old_values,
                    new_values=new_values
                )

            return result
        except ResourceNotFoundError:
            raise
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to update {self.model_class.__name__}: {str(e)}")

    async def delete(self, id: UUID, user_id: Optional[UUID] = None, hard_delete: bool = False) -> bool:
        """Delete a record by ID with soft delete support and audit logging."""
        try:
            instance = await self.get_by_id(id)
            if not instance:
                return False

            # Check if model supports soft delete
            if hasattr(instance, 'is_deleted') and not hard_delete:
                # Soft delete
                from ..core.audit import SoftDeleteManager
                soft_delete_manager = SoftDeleteManager(self.session)
                return await soft_delete_manager.soft_delete(
                    self.model_class,
                    id,
                    user_id or UUID('00000000-0000-0000-0000-000000000000'),
                    "Deleted via repository"
                )
            else:
                # Hard delete
                stmt = delete(self.model_class).where(self.model_class.id == id)
                result = await self.session.execute(stmt)
                await self.session.flush()

                # Create audit log for hard delete
                if user_id:
                    from ..core.audit import AuditLogger
                    audit_logger = AuditLogger(self.session)

                    # Get old values for audit logging
                    old_values = {}
                    for column in self.model_class.__table__.columns:
                        if not column.primary_key:
                            old_values[column.name] = getattr(instance, column.name)

                    await audit_logger.log_action(
                        action="delete",
                        resource_type=self.model_class.__name__,
                        resource_id=str(id),
                        user_id=user_id,
                        old_values=old_values,
                        notes="Hard delete"
                    )

                return result.rowcount > 0
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to delete {self.model_class.__name__}: {str(e)}")

    async def exists(self, id: UUID) -> bool:
        """Check if a record exists by ID."""
        try:
            result = await self.session.execute(
                select(func.count()).select_from(self.model_class).where(self.model_class.id == id)
            )
            return result.scalar() > 0
        except Exception as e:
            raise DatabaseError(f"Failed to check existence of {self.model_class.__name__}: {str(e)}")

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count records with optional filters."""
        try:
            query = select(func.count()).select_from(self.model_class)
            if filters:
                query = self._apply_filters(query, filters)
            result = await self.session.execute(query)
            return result.scalar()
        except Exception as e:
            raise DatabaseError(f"Failed to count {self.model_class.__name__}s: {str(e)}")

    def _apply_filters(self, query: Select, filters: Dict[str, Any]) -> Select:
        """Apply filters to query."""
        for field, value in filters.items():
            if hasattr(self.model_class, field):
                column = getattr(self.model_class, field)
                if isinstance(value, (list, tuple)):
                    query = query.where(column.in_(value))
                else:
                    query = query.where(column == value)
        return query

    def _apply_search(self, query: Select, search_term: str, search_fields: List[str]) -> Select:
        """Apply search term to query."""
        if not search_term or not search_fields:
            return query

        search_conditions = []
        for field in search_fields:
            if hasattr(self.model_class, field):
                column = getattr(self.model_class, field)
                search_conditions.append(column.ilike(f"%{search_term}%"))

        if search_conditions:
            query = query.where(or_(*search_conditions))

        return query

    def _apply_sort(self, query: Select, sort_by: str, sort_order: str = "asc") -> Select:
        """Apply sorting to query."""
        if not sort_by or not hasattr(self.model_class, sort_by):
            return query

        column = getattr(self.model_class, sort_by)
        if sort_order.lower() == "desc":
            query = query.order_by(column.desc())
        else:
            query = query.order_by(column.asc())

        return query

    def _apply_pagination(self, query: Select, limit: int, offset: int) -> Select:
        """Apply pagination to query."""
        return query.limit(limit).offset(offset)


class AuditableRepository(BaseRepository[T], ABC):
    """Repository with audit logging capabilities."""

    async def create(self, data: Dict[str, Any], user_id: UUID) -> T:
        """Create a new record with audit logging."""
        instance = await super().create(data)

        # Create audit log
        await self._create_audit_log(
            user_id=user_id,
            action=AuditAction.CREATE,
            resource_id=str(instance.id),
            new_values=data
        )

        return instance

    async def update(self, id: UUID, data: Dict[str, Any], user_id: UUID) -> T:
        """Update a record with audit logging."""
        # Get old values for audit log
        old_instance = await self.get_by_id(id)
        old_values = None
        if old_instance:
            old_values = {c.name: getattr(old_instance, c.name) for c in self.model_class.__table__.columns}

        instance = await super().update(id, data)

        # Create audit log
        await self._create_audit_log(
            user_id=user_id,
            action=AuditAction.UPDATE,
            resource_id=str(id),
            old_values=old_values,
            new_values=data
        )

        return instance

    async def delete(self, id: UUID, user_id: UUID) -> bool:
        """Delete a record with audit logging."""
        # Get old values for audit log
        old_instance = await self.get_by_id(id)
        old_values = None
        if old_instance:
            old_values = {c.name: getattr(old_instance, c.name) for c in self.model_class.__table__.columns}

        result = await super().delete(id)

        if result:
            # Create audit log
            await self._create_audit_log(
                user_id=user_id,
                action=AuditAction.DELETE,
                resource_id=str(id),
                old_values=old_values
            )

        return result

    async def _create_audit_log(
        self,
        user_id: UUID,
        action: AuditAction,
        resource_id: str,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        notes: Optional[str] = None
    ):
        """Create an audit log entry."""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=self.model_class.__name__,
                resource_id=resource_id,
                old_values=old_values,
                new_values=new_values,
                notes=notes
            )
            self.session.add(audit_log)
            await self.session.flush()
        except Exception as e:
            # Log audit error but don't fail the main operation
            print(f"Failed to create audit log: {e}")