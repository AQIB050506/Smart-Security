"""
Database models for the Security System application.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import hashlib
import secrets


class User(Base):
    """User model with hashed ID for anonymous reporting."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    hashed_id = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship to reports
    reports = relationship("Report", back_populates="user")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.hashed_id:
            # Generate a random salt and create hashed ID
            salt = secrets.token_hex(16)
            self.hashed_id = hashlib.sha256(f"{salt}{self.id or 0}".encode()).hexdigest()


class Report(Base):
    """Report model for storing security reports."""
    
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    text = Column(Text, nullable=True)
    link = Column(String(500), nullable=True)
    image_path = Column(String(500), nullable=True)
    classification_result = Column(String(50), nullable=True)  # spam, scam, harassment, safe
    confidence_score = Column(String(10), nullable=True)  # AI confidence score
    blockchain_tx_hash = Column(String(66), nullable=True)  # Ethereum transaction hash
    is_verified = Column(Boolean, default=False)  # Blockchain verification status
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship to user
    user = relationship("User", back_populates="reports")
    
    def get_content_hash(self):
        """
        Generate SHA256 hash of report content for blockchain storage.
        """
        content = f"{self.text or ''}{self.link or ''}{self.image_path or ''}{self.created_at}"
        return hashlib.sha256(content.encode()).hexdigest()

