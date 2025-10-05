"""Role-Based Access Control (RBAC) system for OpenGov Grants."""

from typing import List, Dict, Any, Optional, Set, Union
from enum import Enum
import structlog

from fastapi import HTTPException, status

from .config import get_settings
from .exceptions import PermissionDeniedError, InsufficientPermissionsError

logger = structlog.get_logger(__name__)


class Permission(str, Enum):
    """System permissions enumeration."""

    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_LIST = "user:list"

    # Grant management
    GRANT_CREATE = "grant:create"
    GRANT_READ = "grant:read"
    GRANT_UPDATE = "grant:update"
    GRANT_DELETE = "grant:delete"
    GRANT_LIST = "grant:list"
    GRANT_PUBLISH = "grant:publish"
    GRANT_ARCHIVE = "grant:archive"

    # Application management
    APPLICATION_CREATE = "application:create"
    APPLICATION_READ = "application:read"
    APPLICATION_UPDATE = "application:update"
    APPLICATION_DELETE = "application:delete"
    APPLICATION_LIST = "application:list"
    APPLICATION_REVIEW = "application:review"
    APPLICATION_APPROVE = "application:approve"
    APPLICATION_REJECT = "application:reject"

    # System administration
    SYSTEM_CONFIG = "system:config"
    SYSTEM_AUDIT = "system:audit"
    SYSTEM_BACKUP = "system:backup"
    SYSTEM_MONITOR = "system:monitor"

    # File management
    FILE_UPLOAD = "file:upload"
    FILE_DOWNLOAD = "file:download"
    FILE_DELETE = "file:delete"

    # Analytics and reporting
    ANALYTICS_VIEW = "analytics:view"
    REPORTS_GENERATE = "reports:generate"
    REPORTS_EXPORT = "reports:export"


class Role(str, Enum):
    """User roles enumeration."""

    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    VIEWER = "viewer"


class RBACManager:
    """Role-Based Access Control manager."""

    def __init__(self):
        """Initialize RBAC manager."""
        self.settings = get_settings()

        # Define role-permission mappings
        self.role_permissions = {
            Role.ADMIN: {
                Permission.USER_CREATE,
                Permission.USER_READ,
                Permission.USER_UPDATE,
                Permission.USER_DELETE,
                Permission.USER_LIST,
                Permission.GRANT_CREATE,
                Permission.GRANT_READ,
                Permission.GRANT_UPDATE,
                Permission.GRANT_DELETE,
                Permission.GRANT_LIST,
                Permission.GRANT_PUBLISH,
                Permission.GRANT_ARCHIVE,
                Permission.APPLICATION_CREATE,
                Permission.APPLICATION_READ,
                Permission.APPLICATION_UPDATE,
                Permission.APPLICATION_DELETE,
                Permission.APPLICATION_LIST,
                Permission.APPLICATION_REVIEW,
                Permission.APPLICATION_APPROVE,
                Permission.APPLICATION_REJECT,
                Permission.SYSTEM_CONFIG,
                Permission.SYSTEM_AUDIT,
                Permission.SYSTEM_BACKUP,
                Permission.SYSTEM_MONITOR,
                Permission.FILE_UPLOAD,
                Permission.FILE_DOWNLOAD,
                Permission.FILE_DELETE,
                Permission.ANALYTICS_VIEW,
                Permission.REPORTS_GENERATE,
                Permission.REPORTS_EXPORT,
            },
            Role.MANAGER: {
                Permission.USER_READ,
                Permission.USER_LIST,
                Permission.GRANT_CREATE,
                Permission.GRANT_READ,
                Permission.GRANT_UPDATE,
                Permission.GRANT_LIST,
                Permission.GRANT_PUBLISH,
                Permission.APPLICATION_CREATE,
                Permission.APPLICATION_READ,
                Permission.APPLICATION_UPDATE,
                Permission.APPLICATION_LIST,
                Permission.APPLICATION_REVIEW,
                Permission.APPLICATION_APPROVE,
                Permission.APPLICATION_REJECT,
                Permission.FILE_UPLOAD,
                Permission.FILE_DOWNLOAD,
                Permission.ANALYTICS_VIEW,
                Permission.REPORTS_GENERATE,
            },
            Role.USER: {
                Permission.GRANT_READ,
                Permission.GRANT_LIST,
                Permission.APPLICATION_CREATE,
                Permission.APPLICATION_READ,
                Permission.APPLICATION_UPDATE,
                Permission.APPLICATION_LIST,
                Permission.FILE_UPLOAD,
                Permission.FILE_DOWNLOAD,
            },
            Role.VIEWER: {
                Permission.GRANT_READ,
                Permission.GRANT_LIST,
                Permission.APPLICATION_READ,
                Permission.APPLICATION_LIST,
                Permission.ANALYTICS_VIEW,
            }
        }

        # Define permission hierarchies (if user has parent, they have child)
        self.permission_hierarchy = {
            Permission.USER_DELETE: [Permission.USER_UPDATE],
            Permission.USER_UPDATE: [Permission.USER_READ],
            Permission.USER_LIST: [Permission.USER_READ],

            Permission.GRANT_DELETE: [Permission.GRANT_UPDATE],
            Permission.GRANT_UPDATE: [Permission.GRANT_READ],
            Permission.GRANT_PUBLISH: [Permission.GRANT_UPDATE],
            Permission.GRANT_ARCHIVE: [Permission.GRANT_UPDATE],

            Permission.APPLICATION_DELETE: [Permission.APPLICATION_UPDATE],
            Permission.APPLICATION_UPDATE: [Permission.APPLICATION_READ],
            Permission.APPLICATION_REVIEW: [Permission.APPLICATION_READ],
            Permission.APPLICATION_APPROVE: [Permission.APPLICATION_REVIEW],
            Permission.APPLICATION_REJECT: [Permission.APPLICATION_REVIEW],

            Permission.FILE_DELETE: [Permission.FILE_UPLOAD],
            Permission.REPORTS_EXPORT: [Permission.REPORTS_GENERATE],
        }

    def get_role_permissions(self, role: Role) -> Set[Permission]:
        """Get all permissions for a role."""
        permissions = set(self.role_permissions.get(role, set()))

        # Add hierarchical permissions
        for permission in list(permissions):
            if permission in self.permission_hierarchy:
                permissions.update(self.permission_hierarchy[permission])

        return permissions

    def has_permission(self, user_role: Role, required_permission: Permission) -> bool:
        """Check if user role has required permission."""
        user_permissions = self.get_role_permissions(user_role)
        return required_permission in user_permissions

    def has_any_permission(self, user_role: Role, required_permissions: List[Permission]) -> bool:
        """Check if user role has any of the required permissions."""
        user_permissions = self.get_role_permissions(user_role)
        return any(permission in user_permissions for permission in required_permissions)

    def has_all_permissions(self, user_role: Role, required_permissions: List[Permission]) -> bool:
        """Check if user role has all of the required permissions."""
        user_permissions = self.get_role_permissions(user_role)
        return all(permission in user_permissions for permission in required_permissions)

    def require_permission(self, user_role: Role, required_permission: Permission) -> None:
        """Require permission or raise exception."""
        if not self.has_permission(user_role, required_permission):
            raise PermissionDeniedError(
                resource=required_permission.split(':')[0],
                operation=required_permission.split(':')[1]
            )

    def require_any_permission(self, user_role: Role, required_permissions: List[Permission]) -> None:
        """Require any of the permissions or raise exception."""
        if not self.has_any_permission(user_role, required_permissions):
            permission_strs = [str(p) for p in required_permissions]
            raise InsufficientPermissionsError(
                f"Requires one of: {', '.join(permission_strs)}"
            )

    def require_all_permissions(self, user_role: Role, required_permissions: List[Permission]) -> None:
        """Require all permissions or raise exception."""
        if not self.has_all_permissions(user_role, required_permissions):
            permission_strs = [str(p) for p in required_permissions]
            raise InsufficientPermissionsError(
                f"Requires all of: {', '.join(permission_strs)}"
            )

    def get_user_permissions(self, user_role: Role) -> List[str]:
        """Get list of permission strings for a user role."""
        permissions = self.get_role_permissions(user_role)
        return sorted([str(p) for p in permissions])

    def get_all_permissions(self) -> List[str]:
        """Get all available permissions."""
        return sorted([str(p) for p in Permission])

    def get_all_roles(self) -> List[str]:
        """Get all available roles."""
        return sorted([str(r) for r in Role])

    def can_user_access_resource(
        self,
        user_role: Role,
        resource_type: str,
        operation: str,
        resource_owner_id: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> bool:
        """Check if user can access a specific resource."""
        # Map operation to permission
        permission_map = {
            'create': f"{resource_type}:create",
            'read': f"{resource_type}:read",
            'update': f"{resource_type}:update",
            'delete': f"{resource_type}:delete",
            'list': f"{resource_type}:list",
            'review': f"{resource_type}:review",
            'approve': f"{resource_type}:approve",
            'reject': f"{resource_type}:reject",
        }

        permission_str = permission_map.get(operation.lower())
        if not permission_str:
            return False

        try:
            permission = Permission(permission_str)
            return self.has_permission(user_role, permission)
        except ValueError:
            return False

    def filter_permissions_by_resource(
        self,
        user_role: Role,
        resource_type: str
    ) -> List[Permission]:
        """Get permissions for a specific resource type."""
        user_permissions = self.get_role_permissions(user_role)
        return [
            perm for perm in user_permissions
            if str(perm).startswith(f"{resource_type}:")
        ]

    def get_resource_operations(self, user_role: Role, resource_type: str) -> List[str]:
        """Get allowed operations for a resource type."""
        permissions = self.filter_permissions_by_resource(user_role, resource_type)
        operations = set()

        for perm in permissions:
            perm_str = str(perm)
            operation = perm_str.split(':')[1]
            operations.add(operation)

        return sorted(list(operations))

    def validate_permission_exists(self, permission: str) -> bool:
        """Validate that a permission exists."""
        try:
            Permission(permission)
            return True
        except ValueError:
            return False

    def validate_role_exists(self, role: str) -> bool:
        """Validate that a role exists."""
        try:
            Role(role)
            return True
        except ValueError:
            return False

    def get_role_hierarchy(self) -> Dict[str, List[str]]:
        """Get role hierarchy information."""
        hierarchy = {}
        for role in Role:
            permissions = self.get_role_permissions(role)
            hierarchy[role.value] = sorted([str(p) for p in permissions])
        return hierarchy

    def compare_roles(self, role1: Role, role2: Role) -> str:
        """Compare two roles and return relationship."""
        permissions1 = self.get_role_permissions(role1)
        permissions2 = self.get_role_permissions(role2)

        if permissions1 == permissions2:
            return "equal"
        elif permissions1.issubset(permissions2):
            return f"{role1.value} is subset of {role2.value}"
        elif permissions2.issubset(permissions1):
            return f"{role2.value} is subset of {role1.value}"
        else:
            return "incomparable"

    def get_effective_permissions(self, roles: List[Role]) -> Set[Permission]:
        """Get combined permissions from multiple roles."""
        all_permissions = set()
        for role in roles:
            all_permissions.update(self.get_role_permissions(role))
        return all_permissions


# Global RBAC manager instance
rbac_manager = RBACManager()


class PermissionChecker:
    """Helper class for permission checking in route handlers."""

    @staticmethod
    def require_permission(permission: Permission):
        """Decorator to enforce a single permission using kwargs context.

        Expects the wrapped endpoint to receive `user_role` in kwargs, or a dependency
        can inject it prior to calling the route handler.
        """
        def decorator(func):
            async def wrapper(*args, **kwargs):
                user_role_value = kwargs.get("user_role")
                if user_role_value is None:
                    return await func(*args, **kwargs)
                try:
                    role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
                except ValueError:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid role")

                if not rbac_manager.has_permission(role, permission):
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                return await func(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def require_any_permission(*permissions: Permission):
        """Decorator requiring any of the specified permissions."""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                user_role_value = kwargs.get("user_role")
                if user_role_value is None:
                    return await func(*args, **kwargs)
                try:
                    role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
                except ValueError:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid role")

                if not rbac_manager.has_any_permission(role, list(permissions)):
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                return await func(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def require_all_permissions(*permissions: Permission):
        """Decorator requiring all of the specified permissions."""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                user_role_value = kwargs.get("user_role")
                if user_role_value is None:
                    return await func(*args, **kwargs)
                try:
                    role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
                except ValueError:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid role")

                if not rbac_manager.has_all_permissions(role, list(permissions)):
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                return await func(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def require_role(*roles: Role):
        """Decorator requiring one of the specified roles."""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                user_role_value = kwargs.get("user_role")
                if user_role_value is None:
                    return await func(*args, **kwargs)
                try:
                    role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
                except ValueError:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid role")

                if role not in roles:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                return await func(*args, **kwargs)
            return wrapper
        return decorator


# Utility functions for common permission checks
def require_admin(func):
    """Decorator to require admin role."""
    async def wrapper(*args, **kwargs):
        user_role_value = kwargs.get("user_role")
        if user_role_value is None:
            return await func(*args, **kwargs)
        role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
        if role != Role.ADMIN:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
        return await func(*args, **kwargs)
    return wrapper


def require_manager_or_admin(func):
    """Decorator to require manager or admin role."""
    async def wrapper(*args, **kwargs):
        user_role_value = kwargs.get("user_role")
        if user_role_value is None:
            return await func(*args, **kwargs)
        role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
        if role not in (Role.MANAGER, Role.ADMIN):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Manager or admin required")
        return await func(*args, **kwargs)
    return wrapper


def require_grant_access(grant_id: str, operation: str):
    """Check if user can access a specific grant."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            user_role_value = kwargs.get("user_role")
            if user_role_value is None:
                return await func(*args, **kwargs)
            role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
            permission_map = {
                'create': Permission.GRANT_CREATE,
                'read': Permission.GRANT_READ,
                'update': Permission.GRANT_UPDATE,
                'delete': Permission.GRANT_DELETE,
                'list': Permission.GRANT_LIST,
                'publish': Permission.GRANT_PUBLISH,
                'archive': Permission.GRANT_ARCHIVE,
            }
            required = permission_map.get(operation.lower())
            if required and not rbac_manager.has_permission(role, required):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_application_access(application_id: str, operation: str):
    """Check if user can access a specific application."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            user_role_value = kwargs.get("user_role")
            if user_role_value is None:
                return await func(*args, **kwargs)
            role = Role(user_role_value) if not isinstance(user_role_value, Role) else user_role_value
            permission_map = {
                'create': Permission.APPLICATION_CREATE,
                'read': Permission.APPLICATION_READ,
                'update': Permission.APPLICATION_UPDATE,
                'delete': Permission.APPLICATION_DELETE,
                'list': Permission.APPLICATION_LIST,
                'review': Permission.APPLICATION_REVIEW,
                'approve': Permission.APPLICATION_APPROVE,
                'reject': Permission.APPLICATION_REJECT,
            }
            required = permission_map.get(operation.lower())
            if required and not rbac_manager.has_permission(role, required):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            return await func(*args, **kwargs)
        return wrapper
    return decorator