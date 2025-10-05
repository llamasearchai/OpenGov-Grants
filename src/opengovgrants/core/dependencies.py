"""Dependency injection container for OpenGov Grants."""

from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager

from fastapi import Depends, Request, FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from redis.asyncio import Redis
import structlog

from .config import get_settings
from ..models.database import get_async_session
from ..repositories.user_repository import UserRepository
from ..repositories.grant_repository import GrantRepository
from ..repositories.application_repository import ApplicationRepository
from ..services.auth_service import AuthService
from ..services.agent_service import AgentService

logger = structlog.get_logger(__name__)


class RedisCache:
    """Simple Redis cache implementation."""

    def __init__(self, redis_client):
        """Initialize Redis cache."""
        self.redis_client = redis_client

    async def get(self, key: str):
        """Get value from cache."""
        return await self.redis_client.get(key)

    async def set(self, key: str, value, expire: int = None):
        """Set value in cache."""
        if expire:
            return await self.redis_client.setex(key, expire, value)
        else:
            return await self.redis_client.set(key, value)

    async def delete(self, key: str):
        """Delete value from cache."""
        return await self.redis_client.delete(key)


class GrantService:
    """Grant domain service operations."""

    def __init__(self, grant_repo: GrantRepository, ai_service: AgentService, cache=None):
        self.grant_repo = grant_repo
        self.ai_service = ai_service
        self.cache = cache


class ApplicationService:
    """Application domain service operations."""

    def __init__(self, app_repo: ApplicationRepository, grant_repo: GrantRepository, ai_service: AgentService, cache=None):
        self.app_repo = app_repo
        self.grant_repo = grant_repo
        self.ai_service = ai_service
        self.cache = cache


class NotificationService:
    """Notification service with Redis-backed dispatch tracking."""

    def __init__(self, cache=None):
        self.cache = cache

    async def notify_user(self, user_id: str, message: str) -> bool:
        if self.cache:
            await self.cache.set(f"notify:last:{user_id}", message, expire=300)
        logger.info("Notification dispatched", user_id=user_id)
        return True


# Dependency functions for FastAPI
def get_database_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database session."""
    return container.get_database_session()


def get_redis_client() -> Redis:
    """FastAPI dependency for Redis client."""
    return container.get_redis_client()


def get_cache() -> RedisCache:
    """FastAPI dependency for cache."""
    return container.get_cache()


def get_user_repository(session: AsyncSession = Depends(get_database_session)) -> UserRepository:
    """FastAPI dependency for user repository."""
    return container.get_user_repository(session)


def get_grant_repository(session: AsyncSession = Depends(get_database_session)) -> GrantRepository:
    """FastAPI dependency for grant repository."""
    return container.get_grant_repository(session)


def get_application_repository(session: AsyncSession = Depends(get_database_session)) -> ApplicationRepository:
    """FastAPI dependency for application repository."""
    return container.get_application_repository(session)


def get_auth_service(
    session: AsyncSession = Depends(get_database_session),
    cache: RedisCache = Depends(get_cache)
) -> AuthService:
    """FastAPI dependency for auth service."""
    return container.get_auth_service(session, cache)


def get_ai_service() -> AgentService:
    """FastAPI dependency for AI service."""
    return container.get_ai_service()


def get_grant_service(
    grant_repo: GrantRepository = Depends(get_grant_repository),
    ai_service: AgentService = Depends(get_ai_service),
    cache: RedisCache = Depends(get_cache)
) -> GrantService:
    """FastAPI dependency for grant service."""
    return container.get_grant_service(grant_repo, ai_service, cache)


def get_application_service(
    app_repo: ApplicationRepository = Depends(get_application_repository),
    grant_repo: GrantRepository = Depends(get_grant_repository),
    ai_service: AgentService = Depends(get_ai_service),
    cache: RedisCache = Depends(get_cache)
) -> ApplicationService:
    """FastAPI dependency for application service."""
    return container.get_application_service(app_repo, grant_repo, ai_service, cache)


def get_notification_service(cache: RedisCache = Depends(get_cache)) -> NotificationService:
    """FastAPI dependency for notification service."""
    return container.get_notification_service(cache)


def get_logger(request: Request) -> structlog.BoundLogger:
    """FastAPI dependency for logger with request context."""
    return container.get_logger(request)


class DependencyContainer:
    """Dependency injection container for managing service lifecycles."""

    def __init__(self):
        """Initialize dependency container."""
        self.settings = get_settings()
        self._engine = None
        self._session_factory = None
        self._redis_client = None
        self._cache = None

    async def initialize(self) -> None:
        """Initialize all dependencies."""
        logger.info("Initializing dependency container")

        # Initialize database engine and session factory
        self._engine = create_async_engine(
            self.settings.database_url,
            echo=self.settings.debug,
            future=True,
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Initialize Redis client
        if self.settings.redis_url:
            self._redis_client = Redis.from_url(
                self.settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )

            # Initialize cache
            self._cache = RedisCache(self._redis_client)

        logger.info("Dependency container initialized")

    async def shutdown(self) -> None:
        """Shutdown all dependencies."""
        logger.info("Shutting down dependency container")

        if self._engine:
            await self._engine.dispose()

        if self._redis_client:
            await self._redis_client.close()

        logger.info("Dependency container shutdown complete")

    def get_database_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session dependency."""
        return get_async_session(self._session_factory)

    def get_redis_client(self) -> Redis:
        """Get Redis client dependency."""
        if not self._redis_client:
            raise RuntimeError("Redis client not initialized")
        return self._redis_client

    def get_cache(self) -> RedisCache:
        """Get cache dependency."""
        if not self._cache:
            raise RuntimeError("Cache not initialized")
        return self._cache

    def get_user_repository(self, session: AsyncSession = Depends(get_database_session)) -> UserRepository:
        """Get user repository dependency."""
        return UserRepository(session)

    def get_grant_repository(self, session: AsyncSession = Depends(get_database_session)) -> GrantRepository:
        """Get grant repository dependency."""
        return GrantRepository(session)

    def get_application_repository(self, session: AsyncSession = Depends(get_database_session)) -> ApplicationRepository:
        """Get application repository dependency."""
        return ApplicationRepository(session)

    def get_auth_service(
        self,
        session: AsyncSession = Depends(get_database_session),
        cache: RedisCache = Depends(get_cache)
    ) -> AuthService:
        """Get auth service dependency."""
        return AuthService(session, cache)

    def get_grant_service(
        self,
        grant_repo: GrantRepository = Depends(get_grant_repository),
        ai_service: AgentService = Depends(get_ai_service),
        cache: RedisCache = Depends(get_cache)
    ) -> GrantService:
        """Get grant service dependency."""
        return GrantService(grant_repo, ai_service, cache)

    def get_application_service(
        self,
        app_repo: ApplicationRepository = Depends(get_application_repository),
        grant_repo: GrantRepository = Depends(get_grant_repository),
        ai_service: AgentService = Depends(get_ai_service),
        cache: RedisCache = Depends(get_cache)
    ) -> ApplicationService:
        """Get application service dependency."""
        return ApplicationService(app_repo, grant_repo, ai_service, cache)

    def get_ai_service(self) -> AgentService:
        """Get AI service dependency."""
        return AgentService()

    def get_notification_service(
        self,
        cache: RedisCache = Depends(get_cache)
    ) -> NotificationService:
        """Get notification service dependency."""
        return NotificationService(cache)

    def get_logger(self, request: Request) -> structlog.BoundLogger:
        """Get logger with request context."""
        return structlog.get_logger(__name__).bind(
            request_id=getattr(request.state, "request_id", "unknown"),
            user_agent=request.headers.get("user-agent", "unknown"),
            ip=request.client.host if request.client else "unknown"
        )


# Global dependency container instance
container = DependencyContainer()




@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager with dependency injection."""
    # Startup
    await container.initialize()
    logger.info("Application startup complete")
    yield
    # Shutdown
    await container.shutdown()
    logger.info("Application shutdown complete")