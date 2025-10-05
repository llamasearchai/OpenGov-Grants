"""Optimistic locking utilities for concurrent updates."""

from datetime import datetime
from typing import Optional, Dict, Any, TypeVar, Type
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
import structlog

from .exceptions import DatabaseError, ResourceNotFoundError

logger = structlog.get_logger(__name__)

T = TypeVar('T')


class OptimisticLockError(DatabaseError):
    """Exception raised when optimistic locking fails."""

    def __init__(self, resource_type: str, resource_id: str, version: int):
        """Initialize optimistic lock error."""
        super().__init__(
            f"Optimistic lock failed for {resource_type} {resource_id}. "
            f"Expected version {version}, but record was modified by another process."
        )
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.version = version


class OptimisticLockManager:
    """Manager for optimistic locking operations."""

    def __init__(self, session: AsyncSession):
        """Initialize optimistic lock manager."""
        self.session = session

    async def update_with_version(
        self,
        model_class: Type[T],
        resource_id: UUID,
        update_data: Dict[str, Any],
        expected_version: int,
        user_id: Optional[UUID] = None
    ) -> T:
        """Update a record with optimistic locking."""
        try:
            # Get the current record with version check
            stmt = select(model_class).where(
                and_(
                    model_class.id == resource_id,
                    getattr(model_class, 'version', None) == expected_version
                )
            )

            result = await self.session.execute(stmt)
            instance = result.scalar_one_or_none()

            if not instance:
                # Check if record exists at all
                exists_stmt = select(model_class).where(model_class.id == resource_id)
                exists_result = await self.session.execute(exists_stmt)
                exists_instance = exists_result.scalar_one_or_none()

                if exists_instance:
                    current_version = getattr(exists_instance, 'version', 0)
                    raise OptimisticLockError(
                        model_class.__name__,
                        str(resource_id),
                        expected_version
                    )
                else:
                    raise ResourceNotFoundError(model_class.__name__, str(resource_id))

            # Update the record
            for key, value in update_data.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)

            # Increment version if the model supports it
            if hasattr(instance, 'version'):
                instance.version = (instance.version or 0) + 1

            # Update timestamp
            if hasattr(instance, 'updated_at'):
                instance.updated_at = datetime.utcnow()

            await self.session.flush()
            await self.session.refresh(instance)

            logger.info(
                "Optimistic lock update successful",
                resource_type=model_class.__name__,
                resource_id=str(resource_id),
                new_version=getattr(instance, 'version', None)
            )

            return instance

        except OptimisticLockError:
            raise
        except ResourceNotFoundError:
            raise
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Optimistic lock update failed: {str(e)}")

    async def get_with_version(self, model_class: Type[T], resource_id: UUID) -> tuple[T, int]:
        """Get a record with its current version."""
        try:
            stmt = select(model_class).where(model_class.id == resource_id)
            result = await self.session.execute(stmt)
            instance = result.scalar_one_or_none()

            if not instance:
                raise ResourceNotFoundError(model_class.__name__, str(resource_id))

            version = getattr(instance, 'version', 0)
            return instance, version

        except ResourceNotFoundError:
            raise
        except Exception as e:
            raise DatabaseError(f"Failed to get record with version: {str(e)}")

    async def bulk_update_with_version(
        self,
        model_class: Type[T],
        updates: list,
        user_id: Optional[UUID] = None
    ) -> list:
        """Perform bulk updates with optimistic locking."""
        results = []
        failed_updates = []

        for update in updates:
            resource_id = update['id']
            update_data = update['data']
            expected_version = update.get('expected_version', 0)

            try:
                result = await self.update_with_version(
                    model_class,
                    resource_id,
                    update_data,
                    expected_version,
                    user_id
                )
                results.append(result)

            except OptimisticLockError as e:
                failed_updates.append({
                    'id': resource_id,
                    'error': str(e),
                    'expected_version': expected_version
                })

            except Exception as e:
                failed_updates.append({
                    'id': resource_id,
                    'error': str(e)
                })

        if failed_updates:
            logger.warning(
                "Bulk update with optimistic locking had failures",
                total_updates=len(updates),
                successful=len(results),
                failed=len(failed_updates)
            )

        return results

    async def check_concurrent_modifications(
        self,
        model_class: Type[T],
        resource_ids: list[UUID],
        expected_versions: Dict[UUID, int]
    ) -> Dict[UUID, bool]:
        """Check if multiple records have been modified concurrently."""
        results = {}

        for resource_id in resource_ids:
            expected_version = expected_versions.get(resource_id, 0)

            try:
                stmt = select(model_class).where(
                    and_(
                        model_class.id == resource_id,
                        getattr(model_class, 'version', None) == expected_version
                    )
                )

                result = await self.session.execute(stmt)
                instance = result.scalar_one_or_none()

                results[resource_id] = instance is not None

            except Exception as e:
                logger.error(
                    "Error checking concurrent modification",
                    resource_id=str(resource_id),
                    error=str(e)
                )
                results[resource_id] = False

        return results


def add_version_column(model_class: Type[T]) -> None:
    """Add version column to a model class for optimistic locking."""
    if not hasattr(model_class, 'version'):
        # Import here to avoid circular imports
        from sqlalchemy import Column, Integer

        # Add version column
        version_column = Column('version', Integer, default=0, nullable=False)
        model_class.version = version_column

        logger.info(f"Added version column to {model_class.__name__}")


def increment_version(instance: T) -> None:
    """Increment the version of an instance."""
    if hasattr(instance, 'version'):
        instance.version = (instance.version or 0) + 1
        logger.debug(f"Incremented version for {instance.__class__.__name__}")


def get_current_version(instance: T) -> int:
    """Get the current version of an instance."""
    return getattr(instance, 'version', 0)