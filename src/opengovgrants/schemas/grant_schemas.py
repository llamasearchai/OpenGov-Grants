"""Grant DTOs and schemas for OpenGov Grants."""

from datetime import datetime, date
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, validator

from ..models.database import GrantStatus


class GrantBase(BaseModel):
    """Base grant schema."""
    title: str = Field(..., min_length=1, max_length=500, description="Grant title")
    description: str = Field(..., min_length=1, description="Grant description")
    short_description: Optional[str] = Field(None, max_length=1000, description="Short description")

    funding_agency: str = Field(..., min_length=1, max_length=255, description="Funding agency")
    grant_number: Optional[str] = Field(None, max_length=100, description="Grant number")
    opportunity_number: Optional[str] = Field(None, max_length=100, description="Opportunity number")
    cfda_number: Optional[str] = Field(None, max_length=50, description="CFDA number")

    min_amount: Optional[float] = Field(None, ge=0, description="Minimum funding amount")
    max_amount: Optional[float] = Field(None, ge=0, description="Maximum funding amount")
    total_funding: Optional[float] = Field(None, ge=0, description="Total funding available")

    open_date: Optional[datetime] = Field(None, description="Grant opening date")
    close_date: Optional[datetime] = Field(None, description="Grant closing date")
    award_date: Optional[datetime] = Field(None, description="Award date")

    eligibility_criteria: Optional[str] = Field(None, description="Eligibility criteria")
    requirements: Optional[str] = Field(None, description="Requirements")
    contact_info: Optional[str] = Field(None, description="Contact information")


class GrantCreate(GrantBase):
    """Schema for creating a new grant."""
    status: GrantStatus = Field(default=GrantStatus.DRAFT, description="Grant status")


class GrantUpdate(BaseModel):
    """Schema for updating a grant."""
    title: Optional[str] = Field(None, min_length=1, max_length=500, description="Grant title")
    description: Optional[str] = Field(None, min_length=1, description="Grant description")
    short_description: Optional[str] = Field(None, max_length=1000, description="Short description")

    funding_agency: Optional[str] = Field(None, min_length=1, max_length=255, description="Funding agency")
    grant_number: Optional[str] = Field(None, max_length=100, description="Grant number")
    opportunity_number: Optional[str] = Field(None, max_length=100, description="Opportunity number")
    cfda_number: Optional[str] = Field(None, max_length=50, description="CFDA number")

    min_amount: Optional[float] = Field(None, ge=0, description="Minimum funding amount")
    max_amount: Optional[float] = Field(None, ge=0, description="Maximum funding amount")
    total_funding: Optional[float] = Field(None, ge=0, description="Total funding available")

    open_date: Optional[datetime] = Field(None, description="Grant opening date")
    close_date: Optional[datetime] = Field(None, description="Grant closing date")
    award_date: Optional[datetime] = Field(None, description="Award date")

    eligibility_criteria: Optional[str] = Field(None, description="Eligibility criteria")
    requirements: Optional[str] = Field(None, description="Requirements")
    contact_info: Optional[str] = Field(None, description="Contact information")
    status: Optional[GrantStatus] = Field(None, description="Grant status")


class GrantResponse(GrantBase):
    """Schema for grant response."""
    id: UUID = Field(..., description="Grant ID")
    status: GrantStatus = Field(..., description="Grant status")
    is_deleted: bool = Field(..., description="Is grant deleted")
    created_by: UUID = Field(..., description="User who created the grant")
    updated_by: Optional[UUID] = Field(None, description="User who last updated the grant")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    # Computed fields
    days_until_close: Optional[int] = Field(None, description="Days until closing date")
    is_open: bool = Field(..., description="Is grant currently open")
    is_closing_soon: bool = Field(..., description="Is grant closing within 30 days")

    class Config:
        from_attributes = True

    @validator('days_until_close', always=True)
    def calculate_days_until_close(cls, v, values):
        """Calculate days until close date."""
        if 'close_date' in values and values['close_date']:
            close_date = values['close_date'].date() if isinstance(values['close_date'], datetime) else values['close_date']
            days = (close_date - date.today()).days
            return max(0, days) if days >= 0 else None
        return None

    @validator('is_open', always=True)
    def calculate_is_open(cls, v, values):
        """Calculate if grant is currently open."""
        today = date.today()
        open_date = None
        close_date = None

        if 'open_date' in values and values['open_date']:
            open_date = values['open_date'].date() if isinstance(values['open_date'], datetime) else values['open_date']
        if 'close_date' in values and values['close_date']:
            close_date = values['close_date'].date() if isinstance(values['close_date'], datetime) else values['close_date']

        if open_date and close_date:
            return open_date <= today <= close_date
        elif open_date:
            return open_date <= today
        elif close_date:
            return today <= close_date
        return True

    @validator('is_closing_soon', always=True)
    def calculate_is_closing_soon(cls, v, values):
        """Calculate if grant is closing soon."""
        days_until_close = values.get('days_until_close')
        return days_until_close is not None and days_until_close <= 30


class GrantListResponse(BaseModel):
    """Schema for grant list response."""
    grants: List[GrantResponse] = Field(..., description="List of grants")
    total: int = Field(..., description="Total number of grants")
    limit: int = Field(..., description="Limit used for pagination")
    offset: int = Field(..., description="Offset used for pagination")


class GrantSearchResponse(BaseModel):
    """Schema for grant search response."""
    grants: List[GrantResponse] = Field(..., description="List of matching grants")
    total: int = Field(..., description="Total number of matching grants")
    search_term: str = Field(..., description="Search term used")


class GrantStatisticsResponse(BaseModel):
    """Schema for grant statistics response."""
    total_grants: int = Field(..., description="Total number of grants")
    status_breakdown: Dict[str, int] = Field(..., description="Grants grouped by status")
    closing_soon: int = Field(..., description="Grants closing within 30 days")
    total_funding: float = Field(..., description="Total funding amount")
    average_funding: float = Field(..., description="Average funding per grant")


class GrantFilterRequest(BaseModel):
    """Schema for grant filtering request."""
    status: Optional[List[GrantStatus]] = Field(None, description="Filter by status")
    funding_agency: Optional[str] = Field(None, description="Filter by funding agency")
    min_amount: Optional[float] = Field(None, ge=0, description="Minimum funding amount")
    max_amount: Optional[float] = Field(None, ge=0, description="Maximum funding amount")
    closing_within_days: Optional[int] = Field(None, ge=0, description="Closing within N days")
    search_term: Optional[str] = Field(None, description="Search term")


class GrantStatusUpdateRequest(BaseModel):
    """Schema for grant status update request."""
    status: GrantStatus = Field(..., description="New grant status")
    notes: Optional[str] = Field(None, description="Status change notes")


class GrantAttachmentResponse(BaseModel):
    """Schema for grant attachment response."""
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


class GrantWithAttachmentsResponse(GrantResponse):
    """Schema for grant response with attachments."""
    attachments: List[GrantAttachmentResponse] = Field(default_factory=list, description="Grant attachments")


class GrantSummaryResponse(BaseModel):
    """Schema for grant summary response."""
    id: UUID = Field(..., description="Grant ID")
    title: str = Field(..., description="Grant title")
    short_description: Optional[str] = Field(None, description="Short description")
    funding_agency: str = Field(..., description="Funding agency")
    max_amount: Optional[float] = Field(None, description="Maximum funding amount")
    close_date: Optional[datetime] = Field(None, description="Closing date")
    status: GrantStatus = Field(..., description="Grant status")
    days_until_close: Optional[int] = Field(None, description="Days until closing")
    is_closing_soon: bool = Field(..., description="Is closing soon")

    class Config:
        from_attributes = True