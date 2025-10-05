"""Application repository implementation."""

from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, date, timedelta

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.database import Application, ApplicationStatus, User, Grant
from ..core.exceptions import ResourceNotFoundError, DatabaseError
from .base_repository import AuditableRepository


class ApplicationRepository(AuditableRepository[Application]):
    """Repository for application operations."""

    def get_model_class(self):
        """Return the Application model class."""
        return Application

    async def get_by_grant_and_applicant(self, grant_id: UUID, applicant_id: UUID) -> Optional[Application]:
        """Get application by grant and applicant."""
        try:
            result = await self.session.execute(
                select(Application).where(
                    and_(
                        Application.grant_id == grant_id,
                        Application.applicant_id == applicant_id
                    )
                )
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get application by grant and applicant: {str(e)}")

    async def get_by_applicant(self, applicant_id: UUID, limit: int = 100, offset: int = 0) -> List[Application]:
        """Get applications by applicant."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.applicant_id == applicant_id,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get applications by applicant: {str(e)}")

    async def get_by_grant(self, grant_id: UUID, limit: int = 100, offset: int = 0) -> List[Application]:
        """Get applications by grant."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.grant_id == grant_id,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get applications by grant: {str(e)}")

    async def get_by_status(self, status: ApplicationStatus, limit: int = 100, offset: int = 0) -> List[Application]:
        """Get applications by status."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.status == status,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get applications by status: {str(e)}")

    async def get_submitted_applications(self, limit: int = 100, offset: int = 0) -> List[Application]:
        """Get submitted applications."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.status.in_([
                            ApplicationStatus.SUBMITTED,
                            ApplicationStatus.UNDER_REVIEW,
                            ApplicationStatus.APPROVED,
                            ApplicationStatus.REJECTED
                        ]),
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.submitted_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get submitted applications: {str(e)}")

    async def get_pending_review(self, limit: int = 100, offset: int = 0) -> List[Application]:
        """Get applications pending review."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.status == ApplicationStatus.UNDER_REVIEW,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.submitted_at.asc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get pending review applications: {str(e)}")

    async def get_approved_applications(self, limit: int = 100, offset: int = 0) -> List[Application]:
        """Get approved applications."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.status == ApplicationStatus.APPROVED,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.decision_date.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get approved applications: {str(e)}")

    async def search_applications(self, search_term: str, limit: int = 50) -> List[Application]:
        """Search applications by title or content."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.is_deleted == False,
                        or_(
                            Application.title.ilike(f"%{search_term}%"),
                            Application.project_summary.ilike(f"%{search_term}%"),
                            Application.project_description.ilike(f"%{search_term}%")
                        )
                    )
                )
                .order_by(Application.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to search applications: {str(e)}")

    async def update_status(self, application_id: UUID, status: ApplicationStatus, user_id: UUID, notes: Optional[str] = None) -> Application:
        """Update application status with review tracking."""
        try:
            application = await self.get_by_id(application_id)
            if not application:
                raise ResourceNotFoundError("Application", str(application_id))

            old_status = application.status
            application.status = status

            # Set timestamps based on status
            now = datetime.utcnow()
            if status == ApplicationStatus.SUBMITTED and application.submitted_at is None:
                application.submitted_at = now
            elif status == ApplicationStatus.UNDER_REVIEW and application.reviewed_at is None:
                application.reviewed_at = now
            elif status in [ApplicationStatus.APPROVED, ApplicationStatus.REJECTED] and application.decision_date is None:
                application.decision_date = now

            # Add reviewer notes if provided
            if notes:
                if application.reviewer_notes:
                    application.reviewer_notes += f"\n\n[{now.isoformat()}] {notes}"
                else:
                    application.reviewer_notes = f"[{now.isoformat()}] {notes}"

            await self.session.flush()
            await self.session.refresh(application)

            # Create audit log manually since this is a special update
            from ..models.database import AuditLog, AuditAction
            audit_log = AuditLog(
                user_id=user_id,
                action=AuditAction.UPDATE,
                resource_type="Application",
                resource_id=str(application_id),
                old_values={"status": old_status},
                new_values={"status": status},
                notes=notes
            )
            self.session.add(audit_log)
            await self.session.flush()

            return application
        except ResourceNotFoundError:
            raise
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to update application status: {str(e)}")

    async def get_applications_due_for_review(self, days_overdue: int = 7) -> List[Application]:
        """Get applications that have been under review for too long."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_overdue)
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.status == ApplicationStatus.UNDER_REVIEW,
                        Application.reviewed_at <= cutoff_date,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.reviewed_at.asc())
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get applications due for review: {str(e)}")

    async def get_application_statistics(self) -> Dict[str, Any]:
        """Get comprehensive application statistics."""
        try:
            # Total applications
            total_result = await self.session.execute(
                select(func.count()).select_from(Application).where(Application.is_deleted == False)
            )
            total_applications = total_result.scalar()

            # Applications by status
            status_stats = {}
            for status in ApplicationStatus:
                result = await self.session.execute(
                    select(func.count()).select_from(Application).where(
                        and_(Application.status == status, Application.is_deleted == False)
                    )
                )
                status_stats[status.value] = result.scalar()

            # Average review time (for completed applications)
            review_time_result = await self.session.execute(
                select(func.avg(func.julianday(Application.decision_date) - func.julianday(Application.reviewed_at)))
                .select_from(Application)
                .where(
                    and_(
                        Application.status.in_([ApplicationStatus.APPROVED, ApplicationStatus.REJECTED]),
                        Application.reviewed_at.is_not(None),
                        Application.decision_date.is_not(None),
                        Application.is_deleted == False
                    )
                )
            )
            avg_review_time = review_time_result.scalar()

            # Total requested funding
            funding_result = await self.session.execute(
                select(func.sum(Application.requested_amount)).where(
                    and_(Application.requested_amount.is_not(None), Application.is_deleted == False)
                )
            )
            total_requested = funding_result.scalar() or 0

            # Approval rate
            approved_result = await self.session.execute(
                select(func.count()).select_from(Application).where(
                    and_(Application.status == ApplicationStatus.APPROVED, Application.is_deleted == False)
                )
            )
            approved_count = approved_result.scalar()

            approval_rate = (approved_count / total_applications * 100) if total_applications > 0 else 0

            return {
                "total_applications": total_applications,
                "status_breakdown": status_stats,
                "average_review_time_days": float(avg_review_time or 0),
                "total_requested_funding": float(total_requested),
                "approval_rate_percent": float(approval_rate)
            }
        except Exception as e:
            raise DatabaseError(f"Failed to get application statistics: {str(e)}")

    async def get_recent_applications(self, days: int = 7, limit: int = 20) -> List[Application]:
        """Get applications created in the last N days."""
        try:
            since_date = datetime.utcnow() - timedelta(days=days)
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.created_at >= since_date,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get recent applications: {str(e)}")

    async def get_applications_by_amount_range(self, min_amount: float, max_amount: float, limit: int = 100) -> List[Application]:
        """Get applications within amount range."""
        try:
            result = await self.session.execute(
                select(Application)
                .where(
                    and_(
                        Application.requested_amount.is_not(None),
                        Application.requested_amount >= min_amount,
                        Application.requested_amount <= max_amount,
                        Application.is_deleted == False
                    )
                )
                .order_by(Application.requested_amount.desc())
                .limit(limit)
            )
            return list(result.scalars().all())
        except Exception as e:
            raise DatabaseError(f"Failed to get applications by amount range: {str(e)}")