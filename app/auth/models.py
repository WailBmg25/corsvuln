"""
Data models for authentication and session management
"""

from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel, Field


class User(BaseModel):
    """User model with authentication information"""
    username: str
    password_hash: str
    role: str  # "admin", "user", "victim"
    created_at: datetime = Field(default_factory=datetime.now)
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "admin",
                "password_hash": "hashed_password",
                "role": "admin",
                "created_at": "2024-01-01T00:00:00"
            }
        }


class Session(BaseModel):
    """Session model for managing user sessions"""
    session_id: str
    username: str
    created_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime
    
    def is_valid(self) -> bool:
        """Check if session is still valid (not expired)"""
        return datetime.now() < self.expires_at
    
    class Config:
        json_schema_extra = {
            "example": {
                "session_id": "abc123def456",
                "username": "admin",
                "created_at": "2024-01-01T00:00:00",
                "expires_at": "2024-01-01T01:00:00"
            }
        }
