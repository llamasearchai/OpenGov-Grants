"""Data models for OpenGrants."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class GrantBase(BaseModel):
    """Base model for Grant."""

    name: str = Field(..., description="Grant name")
    description: str = Field(..., description="Grant description")


class GrantCreate(GrantBase):
    """Model for creating new Grant."""


class Grant(GrantBase):
    """Complete Grant model."""

    id: UUID = Field(default_factory=uuid4, description="Unique database identifier")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")

    class Config:
        from_attributes = True


class ApplicationBase(BaseModel):
    """Base model for Application."""

    title: str = Field(..., description="Application title")
    content: str = Field(..., description="Application content")


class ApplicationCreate(ApplicationBase):
    """Model for creating new Application."""


class Application(ApplicationBase):
    """Complete Application model."""

    id: UUID = Field(default_factory=uuid4, description="Unique database identifier")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")

    class Config:
        from_attributes = True


class ItemBase(BaseModel):
    """Base model for Item."""

    name: str = Field(..., description="Item name")
    description: str = Field(..., description="Item description")


class ItemCreate(ItemBase):
    """Model for creating new Item."""


class Item(ItemBase):
    """Complete Item model."""

    id: str = Field(..., description="Unique identifier")
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: str = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True