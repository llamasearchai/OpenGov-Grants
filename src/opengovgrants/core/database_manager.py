"""Enhanced database manager with transaction support and utilities."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional, Dict, Any
from datetime import datetime
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
import structlog

from .config import get_settings
from .exceptions import DatabaseError, ConnectionError, TransactionError, IntegrityError as CustomIntegrityError

logger = structlog.get_logger(__name__)


class DatabaseManager:
    """Enhanced database manager with transaction support and health checks."""

    def __init__(self):
        """Initialize database manager."""
        self.settings = get_settings()
        self._engine = None
        self._session_factory = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize database engine and session factory."""
        if self._initialized:
            return

        try:
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

            self._initialized = True
            logger.info("Database manager initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize database manager", error=str(e))
            raise ConnectionError(f"Database initialization failed: {str(e)}")

    async def shutdown(self) -> None:
        """Shutdown database connections."""
        if self._engine:
            await self._engine.dispose()
            self._initialized = False
            logger.info("Database manager shutdown complete")

    async def get_session(self) -> AsyncSession:
        """Get a database session."""
        if not self._initialized:
            await self.initialize()

        return self._session_factory()

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """Context manager for database transactions with automatic rollback on error."""
        session = await self.get_session()
        transaction = None

        try:
            transaction = await session.begin()
            logger.debug("Transaction started")

            yield session

            await transaction.commit()
            logger.debug("Transaction committed successfully")

        except Exception as e:
            if transaction:
                await transaction.rollback()
                logger.warning("Transaction rolled back due to error", error=str(e))
            raise TransactionError(f"Transaction failed: {str(e)}")
        finally:
            await session.close()

    @asynccontextmanager
    async def read_only_transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """Context manager for read-only database transactions."""
        session = await self.get_session()

        try:
            # Start a transaction for consistency
            transaction = await session.begin()

            # Set session to read-only mode if supported
            if hasattr(session, 'connection'):
                try:
                    await session.connection(execution_options={"autocommit": False})
                except Exception:
                    pass  # Some databases don't support this

            yield session

            await transaction.commit()

        except Exception as e:
            logger.error("Read-only transaction failed", error=str(e))
            raise DatabaseError(f"Read-only transaction failed: {str(e)}")
        finally:
            await session.close()

    async def execute_with_retry(
        self,
        operation,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ) -> Any:
        """Execute database operation with retry logic."""
        last_exception = None

        for attempt in range(max_retries):
            try:
                async with self.transaction() as session:
                    result = await operation(session)
                    return result

            except (ConnectionError, OperationalError) as e:
                last_exception = e
                if attempt < max_retries - 1:
                    logger.warning(
                        "Database operation failed, retrying",
                        attempt=attempt + 1,
                        max_retries=max_retries,
                        error=str(e)
                    )
                    await asyncio.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                else:
                    logger.error(
                        "Database operation failed after all retries",
                        attempts=max_retries,
                        error=str(e)
                    )
                    raise ConnectionError(f"Operation failed after {max_retries} attempts: {str(e)}")

            except IntegrityError as e:
                logger.error("Database integrity error", error=str(e))
                raise CustomIntegrityError(f"Data integrity constraint violated: {str(e)}")

            except Exception as e:
                # Don't retry for other types of errors
                logger.error("Database operation failed", error=str(e))
                raise DatabaseError(f"Database operation failed: {str(e)}")

        # This should never be reached, but just in case
        raise last_exception or DatabaseError("Unknown database error")

    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive database health check."""
        try:
            async with self.read_only_transaction() as session:
                # Test basic connectivity
                result = await session.execute(text("SELECT 1 as health_check"))
                row = result.fetchone()

                if not row or row[0] != 1:
                    return {
                        "status": "unhealthy",
                        "database": "disconnected",
                        "error": "Health check query failed"
                    }

                # Get database version
                try:
                    version_result = await session.execute(text("SELECT version()"))
                    version = version_result.scalar()
                except Exception:
                    version = "Unknown"

                # Get connection pool status
                pool_status = await self.get_pool_status()

                return {
                    "status": "healthy",
                    "database": "connected",
                    "version": version,
                    "pool_status": pool_status,
                    "timestamp": datetime.utcnow().isoformat()
                }

        except Exception as e:
            return {
                "status": "unhealthy",
                "database": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
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

    async def bulk_insert(self, model_class, data: list, batch_size: int = 1000) -> int:
        """Perform bulk insert with transaction management."""
        if not data:
            return 0

        inserted_count = 0

        async def insert_batch(session: AsyncSession, batch: list):
            session.add_all([model_class(**item) for item in batch])
            await session.flush()

        try:
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                await self.execute_with_retry(
                    lambda session: insert_batch(session, batch)
                )
                inserted_count += len(batch)

            logger.info("Bulk insert completed", inserted=len(data), batches=inserted_count // batch_size)
            return inserted_count

        except Exception as e:
            logger.error("Bulk insert failed", error=str(e))
            raise DatabaseError(f"Bulk insert failed: {str(e)}")

    async def bulk_update(self, model_class, updates: list, batch_size: int = 1000) -> int:
        """Perform bulk update with transaction management."""
        if not updates:
            return 0

        updated_count = 0

        async def update_batch(session: AsyncSession, batch: list):
            for update_data in batch:
                stmt = model_class.__table__.update().where(
                    model_class.id == update_data['id']
                ).values(**update_data['data'])
                await session.execute(stmt)
            await session.flush()

        try:
            for i in range(0, len(updates), batch_size):
                batch = updates[i:i + batch_size]
                await self.execute_with_retry(
                    lambda session: update_batch(session, batch)
                )
                updated_count += len(batch)

            logger.info("Bulk update completed", updated=len(updates), batches=updated_count // batch_size)
            return updated_count

        except Exception as e:
            logger.error("Bulk update failed", error=str(e))
            raise DatabaseError(f"Bulk update failed: {str(e)}")

    async def optimize_tables(self) -> Dict[str, Any]:
        """Optimize database tables for better performance."""
        try:
            async with self.transaction() as session:
                # VACUUM for SQLite
                if self.settings.database_url.startswith("sqlite"):
                    await session.execute(text("VACUUM"))
                    await session.execute(text("ANALYZE"))

                # REINDEX for SQLite
                    await session.execute(text("REINDEX"))

                # For PostgreSQL, run maintenance commands
                elif self.settings.database_url.startswith("postgresql"):
                    await session.execute(text("VACUUM ANALYZE"))
                    await session.execute(text("REINDEX DATABASE CONCURRENTLY opengovgrants"))

                return {
                    "status": "success",
                    "message": "Database optimization completed",
                    "timestamp": datetime.utcnow().isoformat()
                }

        except Exception as e:
            logger.error("Database optimization failed", error=str(e))
            raise DatabaseError(f"Database optimization failed: {str(e)}")


# Global database manager instance
db_manager = DatabaseManager()