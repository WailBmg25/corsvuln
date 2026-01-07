"""
Error response models for the CORS Vulnerability Demonstration Project
"""

from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class ErrorResponse(BaseModel):
    """
    Standard error response model
    Used for all error responses in the application
    """
    error: str
    details: Optional[str] = None
    timestamp: datetime
    path: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "error": "Authentication required",
                "details": "No valid session cookie found",
                "timestamp": "2024-01-01T00:00:00",
                "path": "/api/vuln/wildcard"
            }
        }
