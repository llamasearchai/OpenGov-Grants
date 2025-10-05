"""Grant repository implementation."""

from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, date, timedelta

from sqlalchemy import select, and_, or_, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from ..models.database import Grant, GrantStatus, User
from ..core.exceptions import ResourceNotFoundError, DatabaseError
from .base_repository import AuditableRepository


class GrantRepository(AuditableRepository[Grant]):
    """Repository for grant operations."""

    def get_model_class(self):
        """Return the Grant model class."""
        return Grant

    async def get_by_grant_number(self, grant_number: str) -> Optional[Grant]:
        """Get grant by grant number."""
        try:
            result = await self.session.execute(
                select(Grant).where(Grant.grant_number == grant_number)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get grant by grant number: {str(e)}")

    async def get_by_opportunity_number(self, opportunity_number: str) -> Optional[Grant]:
        """Get grant by opportunity number."""
        try:
            result = await self.session.execute(
                select(Grant).where(Grant.opportunity_number == opportunity_number)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get grant by opportunity number: {str(e)}")

    async def get_by_cfda_number(self, cfda_number: str) -> Optional[Grant]:
        """Get grant by CFDA number."""
        try:
            result = await self.session.execute(
                select(Grant).where(Grant.cfda_number == cfda_number)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get grant by CFDA number: {str(e)}")

    async def get_active_grants(self, limit: int = 100, offset: int = 0) -> List[Grant]:
        """Get active grants with pagination."""
        try:
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.status.in_([GrantStatus.PUBLISHED, GrantStatus.ACTIVE]),
                        Grant.is_deleted == False
                    )
                )
                .order_by(Grant.close_date.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get active grants: {str(e)}")

    async def get_grants_by_funding_agency(self, agency: str, limit: int = 100, offset: int = 0) -> List[Grant]:
        """Get grants by funding agency."""
        try:
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.funding_agency == agency,
                        Grant.is_deleted == False
                    )
                )
                .order_by(Grant.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get grants by funding agency: {str(e)}")

    async def get_grants_closing_soon(self, days_ahead: int = 30) -> List[Grant]:
        """Get grants closing within specified days."""
        try:
            future_date = datetime.utcnow().date() + timedelta(days=days_ahead)
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.close_date.is_not(None),
                        Grant.close_date <= future_date,
                        Grant.status.in_([GrantStatus.PUBLISHED, GrantStatus.ACTIVE]),
                        Grant.is_deleted == False
                    )
                )
                .order_by(Grant.close_date.asc())
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get grants closing soon: {str(e)}")

    async def get_grants_by_amount_range(self, min_amount: float, max_amount: float, limit: int = 100) -> List[Grant]:
        """Get grants within amount range."""
        try:
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.min_amount.is_not(None),
                        Grant.max_amount.is_not(None),
                        Grant.min_amount >= min_amount,
                        Grant.max_amount <= max_amount,
                        Grant.is_deleted == False
                    )
                )
                .order_by(Grant.max_amount.desc())
                .limit(limit)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get grants by amount range: {str(e)}")

    async def search_grants(self, search_term: str, limit: int = 50) -> List[Grant]:
        """Search grants by title, description, or agency."""
        try:
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.is_deleted == False,
                        or_(
                            Grant.title.ilike(f"%{search_term}%"),
                            Grant.description.ilike(f"%{search_term}%"),
                            Grant.funding_agency.ilike(f"%{search_term}%"),
                            Grant.grant_number.ilike(f"%{search_term}%"),
                            Grant.opportunity_number.ilike(f"%{search_term}%")
                        )
                    )
                )
                .order_by(Grant.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to search grants: {str(e)}")

    async def get_grants_by_status(self, status: GrantStatus, limit: int = 100, offset: int = 0) -> List[Grant]:
        """Get grants by status."""
        try:
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.status == status,
                        Grant.is_deleted == False
                    )
                )
                .order_by(Grant.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get grants by status: {str(e)}")

    async def get_grants_created_by_user(self, user_id: UUID, limit: int = 100, offset: int = 0) -> List[Grant]:
        """Get grants created by specific user."""
        try:
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.created_by == user_id,
                        Grant.is_deleted == False
                    )
                )
                .order_by(Grant.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get grants created by user: {str(e)}")

    async def update_status(self, grant_id: UUID, status: GrantStatus, user_id: UUID) -> Grant:
        """Update grant status."""
        try:
            grant = await self.get_by_id(grant_id)
            if not grant:
                raise ResourceNotFoundError("Grant", str(grant_id))

            old_status = grant.status
            grant.status = status

            # Set timestamps based on status
            if status == GrantStatus.ACTIVE and grant.open_date is None:
                grant.open_date = datetime.utcnow()
            elif status == GrantStatus.CLOSED and grant.close_date is None:
                grant.close_date = datetime.utcnow()

            await self.session.flush()
            await self.session.refresh(grant)

            # Create audit log manually since this is a special update
            from ..models.database import AuditLog, AuditAction
            audit_log = AuditLog(
                user_id=user_id,
                action=AuditAction.UPDATE,
                resource_type="Grant",
                resource_id=str(grant_id),
                old_values={"status": old_status},
                new_values={"status": status}
            )
            self.session.add(audit_log)
            await self.session.flush()

            return grant
        except ResourceNotFoundError:
            raise
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to update grant status: {str(e)}")

    async def get_grant_statistics(self) -> Dict[str, Any]:
        """Get comprehensive grant statistics."""
        try:
            # Total grants
            total_result = await self.session.execute(
                select(func.count()).select_from(Grant).where(Grant.is_deleted == False)
            )
            total_grants = total_result.scalar()

            # Grants by status
            status_stats = {}
            for status in GrantStatus:
                result = await self.session.execute(
                    select(func.count()).select_from(Grant).where(
                        and_(Grant.status == status, Grant.is_deleted == False)
                    )
                )
                status_stats[status.value] = result.scalar()

            # Grants closing soon (next 30 days)
            future_date = datetime.utcnow().date() + timedelta(days=30)
            closing_soon_result = await self.session.execute(
                select(func.count()).select_from(Grant).where(
                    and_(
                        Grant.close_date.is_not(None),
                        Grant.close_date <= future_date,
                        Grant.status.in_([GrantStatus.PUBLISHED, GrantStatus.ACTIVE]),
                        Grant.is_deleted == False
                    )
                )
            )
            closing_soon = closing_soon_result.scalar()

            # Total funding amount
            funding_result = await self.session.execute(
                select(func.sum(Grant.total_funding)).where(
                    and_(Grant.total_funding.is_not(None), Grant.is_deleted == False)
                )
            )
            total_funding = funding_result.scalar() or 0

            return {
                "total_grants": total_grants,
                "status_breakdown": status_stats,
                "closing_soon": closing_soon,
                "total_funding": float(total_funding)
            }
        except Exception as e:
            raise DatabaseError(f"Failed to get grant statistics: {str(e)}")

    async def get_recent_grants(self, days: int = 7, limit: int = 20) -> List[Grant]:
        """Get grants created in the last N days."""
        try:
            since_date = datetime.utcnow() - timedelta(days=days)
            result = await self.session.execute(
                select(Grant)
                .where(
                    and_(
                        Grant.created_at >= since_date,
                        Grant.is_deleted == False
                    )
                )
                .order_by(Grant.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get recent grants: {str(e)}")