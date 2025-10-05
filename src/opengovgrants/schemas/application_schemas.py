"""Application DTOs and schemas for OpenGov Grants."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, validator

from ..models.database import ApplicationStatus


class ApplicationBase(BaseModel):
    """Base application schema."""
    title: str = Field(..., min_length=1, max_length=500, description="Application title")
    project_summary: str = Field(..., min_length=1, description="Project summary")
    project_description: str = Field(..., min_length=1, description="Project description")
    budget_narrative: Optional[str] = Field(None, description="Budget narrative")
    timeline: Optional[str] = Field(None, description="Project timeline")

    requested_amount: Optional[float] = Field(None, ge=0, description="Requested funding amount")
    matching_funds: Optional[float] = Field(None, ge=0, description="Matching funds")
    other_funding_sources: Optional[str] = Field(None, description="Other funding sources")


class ApplicationCreate(ApplicationBase):
    """Schema for creating a new application."""
    grant_id: UUID = Field(..., description="Grant ID to apply for")


class ApplicationUpdate(BaseModel):
    """Schema for updating an application."""
    title: Optional[str] = Field(None, min_length=1, max_length=500, description="Application title")
    project_summary: Optional[str] = Field(None, min_length=1, description="Project summary")
    project_description: Optional[str] = Field(None, min_length=1, description="Project description")
    budget_narrative: Optional[str] = Field(None, description="Budget narrative")
    timeline: Optional[str] = Field(None, description="Project timeline")

    requested_amount: Optional[float] = Field(None, ge=0, description="Requested funding amount")
    matching_funds: Optional[float] = Field(None, ge=0, description="Matching funds")
    other_funding_sources: Optional[str] = Field(None, description="Other funding sources")


class ApplicationResponse(ApplicationBase):
    """Schema for application response."""
    id: UUID = Field(..., description="Application ID")
    grant_id: UUID = Field(..., description="Grant ID")
    applicant_id: UUID = Field(..., description="Applicant ID")

    status: ApplicationStatus = Field(..., description="Application status")
    submitted_at: Optional[datetime] = Field(None, description="Submission timestamp")
    reviewed_at: Optional[datetime] = Field(None, description="Review start timestamp")
    decision_date: Optional[datetime] = Field(None, description="Decision date")

    reviewer_notes: Optional[str] = Field(None, description="Reviewer notes")
    review_score: Optional[int] = Field(None, ge=0, le=100, description="Review score")
    funding_recommended: Optional[float] = Field(None, ge=0, description="Recommended funding")

    is_deleted: bool = Field(..., description="Is application deleted")
    created_by: UUID = Field(..., description="User who created the application")
    updated_by: Optional[UUID] = Field(None, description="User who last updated the application")

    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    # Computed fields
    days_under_review: Optional[int] = Field(None, description="Days under review")
    is_overdue: bool = Field(..., description="Is review overdue")
    total_project_cost: float = Field(..., description="Total project cost")

    class Config:
        from_attributes = True

    @validator('days_under_review', always=True)
    def calculate_days_under_review(cls, v, values):
        """Calculate days under review."""
        if 'reviewed_at' in values and values['reviewed_at'] and 'decision_date' not in values:
            reviewed_at = values['reviewed_at']
            if isinstance(reviewed_at, datetime):
                days = (datetime.utcnow() - reviewed_at).days
                return max(0, days)
        return None

    @validator('is_overdue', always=True)
    def calculate_is_overdue(cls, v, values):
        """Calculate if review is overdue."""
        days_under_review = values.get('days_under_review')
        return days_under_review is not None and days_under_review > 30

    @validator('total_project_cost', always=True)
    def calculate_total_project_cost(cls, v, values):
        """Calculate total project cost."""
        requested = values.get('requested_amount', 0) or 0
        matching = values.get('matching_funds', 0) or 0
        return requested + matching


class ApplicationListResponse(BaseModel):
    """Schema for application list response."""
    applications: List[ApplicationResponse] = Field(..., description="List of applications")
    total: int = Field(..., description="Total number of applications")
    limit: int = Field(..., description="Limit used for pagination")
    offset: int = Field(..., description="Offset used for pagination")


class ApplicationSearchResponse(BaseModel):
    """Schema for application search response."""
    applications: List[ApplicationResponse] = Field(..., description="List of matching applications")
    total: int = Field(..., description="Total number of matching applications")
    search_term: str = Field(..., description="Search term used")


class ApplicationStatisticsResponse(BaseModel):
    """Schema for application statistics response."""
    total_applications: int = Field(..., description="Total number of applications")
    status_breakdown: Dict[str, int] = Field(..., description="Applications grouped by status")
    average_review_time_days: float = Field(..., description="Average review time in days")
    total_requested_funding: float = Field(..., description="Total requested funding")
    approval_rate_percent: float = Field(..., description="Approval rate percentage")


class ApplicationFilterRequest(BaseModel):
    """Schema for application filtering request."""
    status: Optional[List[ApplicationStatus]] = Field(None, description="Filter by status")
    grant_id: Optional[UUID] = Field(None, description="Filter by grant ID")
    applicant_id: Optional[UUID] = Field(None, description="Filter by applicant ID")
    min_amount: Optional[float] = Field(None, ge=0, description="Minimum requested amount")
    max_amount: Optional[float] = Field(None, ge=0, description="Maximum requested amount")
    submitted_after: Optional[datetime] = Field(None, description="Submitted after date")
    submitted_before: Optional[datetime] = Field(None, description="Submitted before date")
    search_term: Optional[str] = Field(None, description="Search term")


class ApplicationStatusUpdateRequest(BaseModel):
    """Schema for application status update request."""
    status: ApplicationStatus = Field(..., description="New application status")
    reviewer_notes: Optional[str] = Field(None, description="Reviewer notes")
    review_score: Optional[int] = Field(None, ge=0, le=100, description="Review score")
    funding_recommended: Optional[float] = Field(None, ge=0, description="Recommended funding amount")


class ApplicationAttachmentResponse(BaseModel):
    """Schema for application attachment response."""
    id: UUID = Field(..., description="Attachment ID")
    filename: str = Field(..., description="Original filename")
    file_path: str = Field(..., description="File path")
    file_size: int = Field(..., description="File size in bytes")
    content_type: str = Field(..., description="Content type")
    description: Optional[str] = Field(None, description="Attachment description")
    uploaded_by: UUID = Field(..., description="User who uploaded")
    created_at: datetime = Field(..., description="Upload timestamp")

    class Config:
        from_attributes = True


class ApplicationWithAttachmentsResponse(ApplicationResponse):
    """Schema for application response with attachments."""
    attachments: List[ApplicationAttachmentResponse] = Field(default_factory=list, description="Application attachments")


class ApplicationSummaryResponse(BaseModel):
    """Schema for application summary response."""
    id: UUID = Field(..., description="Application ID")
    title: str = Field(..., description="Application title")
    grant_title: str = Field(..., description="Grant title")
    applicant_name: str = Field(..., description="Applicant name")
    requested_amount: Optional[float] = Field(None, description="Requested amount")
    status: ApplicationStatus = Field(..., description="Application status")
    submitted_at: Optional[datetime] = Field(None, description="Submission date")
    days_under_review: Optional[int] = Field(None, description="Days under review")
    is_overdue: bool = Field(..., description="Is review overdue")

    class Config:
        from_attributes = True


class ApplicationReviewRequest(BaseModel):
    """Schema for application review request."""
    application_id: UUID = Field(..., description="Application ID")
    review_score: int = Field(..., ge=0, le=100, description="Review score")
    reviewer_notes: str = Field(..., description="Reviewer notes")
    funding_recommended: Optional[float] = Field(None, ge=0, description="Recommended funding")
    decision: ApplicationStatus = Field(..., description="Review decision")


class ApplicationBulkActionRequest(BaseModel):
    """Schema for bulk application actions."""
    application_ids: List[UUID] = Field(..., description="Application IDs")
    action: str = Field(..., description="Action to perform")
    notes: Optional[str] = Field(None, description="Action notes")


class ApplicationExportRequest(BaseModel):
    """Schema for application export request."""
    application_ids: Optional[List[UUID]] = Field(None, description="Specific application IDs")
    status_filter: Optional[List[ApplicationStatus]] = Field(None, description="Status filter")
    date_from: Optional[datetime] = Field(None, description="From date")
    date_to: Optional[datetime] = Field(None, description="To date")
    include_attachments: bool = Field(default=False, description="Include attachments")
    format: str = Field(default="csv", description="Export format")


class ApplicationMetricsResponse(BaseModel):
    """Schema for application metrics response."""
    total_submitted: int = Field(..., description="Total submitted applications")
    total_approved: int = Field(..., description="Total approved applications")
    total_rejected: int = Field(..., description="Total rejected applications")
    total_under_review: int = Field(..., description="Total under review")
    average_processing_time: float = Field(..., description="Average processing time in days")
    approval_rate: float = Field(..., description="Approval rate percentage")
    total_funding_requested: float = Field(..., description="Total funding requested")
    total_funding_approved: float = Field(..., description="Total funding approved")
    funding_approval_rate: float = Field(..., description="Funding approval rate percentage")