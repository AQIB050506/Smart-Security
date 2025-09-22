"""
Pydantic schemas for request/response validation.
"""
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List
from datetime import datetime


class UserBase(BaseModel):
    """Base user schema."""
    email: Optional[EmailStr] = None


class UserCreate(UserBase):
    """Schema for user creation."""
    password: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if v is not None and len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v


class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


class UserResponse(UserBase):
    """Schema for user response."""
    id: int
    hashed_id: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    """Schema for JWT token response."""
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Schema for token data."""
    user_id: Optional[int] = None


class ReportBase(BaseModel):
    """Base report schema."""
    text: Optional[str] = None
    link: Optional[str] = None


class ReportCreate(ReportBase):
    """Schema for report creation."""
    pass


class ReportResponse(ReportBase):
    """Schema for report response."""
    id: int
    user_id: int
    image_path: Optional[str] = None
    classification_result: Optional[str] = None
    confidence_score: Optional[str] = None
    blockchain_tx_hash: Optional[str] = None
    is_verified: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """Schema for report list response."""
    reports: List[ReportResponse]
    total: int
    page: int
    size: int


class LinkScanResult(BaseModel):
    """Schema for link scan result."""
    url: str
    is_safe: bool
    threat_type: Optional[str] = None
    confidence: Optional[float] = None
    details: Optional[str] = None


class AIAnalysisResult(BaseModel):
    """Schema for AI analysis result."""
    classification: str  # spam, scam, harassment, safe
    confidence: float
    details: Optional[str] = None

