"""
Data models for attack scripts and results.

This module defines the data structures used by attack scripts
to report their execution results and findings.
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict, field_serializer
from datetime import datetime


class AttackResult(BaseModel):
    """
    Result of an attack script execution.
    
    This model captures all relevant information about an attack
    execution, including success status, timing, stolen data,
    and educational notes.
    
    Attributes:
        attack_type: Type of attack executed (e.g., "wildcard", "reflection")
        success: Whether the attack successfully exploited the vulnerability
        duration_seconds: Time taken to execute the attack
        requests_sent: Number of HTTP requests sent during the attack
        stolen_data: Any sensitive data extracted during the attack
        vulnerable_endpoints: List of endpoints found to be vulnerable
        request_details: Details of requests sent (headers, body, etc.)
        response_details: Details of responses received (headers, body, etc.)
        educational_notes: Educational information about the vulnerability
    """
    
    attack_type: str = Field(
        description="Type of attack executed"
    )
    
    success: bool = Field(
        description="Whether the attack successfully exploited the vulnerability"
    )
    
    duration_seconds: float = Field(
        description="Time taken to execute the attack in seconds",
        ge=0
    )
    
    requests_sent: int = Field(
        description="Number of HTTP requests sent during the attack",
        ge=0
    )
    
    stolen_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Any sensitive data extracted during the attack"
    )
    
    vulnerable_endpoints: List[str] = Field(
        default_factory=list,
        description="List of endpoints found to be vulnerable"
    )
    
    request_details: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Details of requests sent (headers, body, method, etc.)"
    )
    
    response_details: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Details of responses received (status, headers, body, etc.)"
    )
    
    educational_notes: str = Field(
        default="",
        description="Educational information about the vulnerability and mitigation"
    )
    
    error: Optional[str] = Field(
        default=None,
        description="Error message if the attack failed"
    )
    
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp when the attack was executed"
    )
    
    @field_serializer('timestamp')
    def serialize_timestamp(self, timestamp: datetime, _info):
        """Serialize datetime to ISO format string"""
        return timestamp.isoformat()
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "attack_type": "wildcard",
                "success": True,
                "duration_seconds": 2.5,
                "requests_sent": 10,
                "stolen_data": {
                    "username": "victim",
                    "profile": {"email": "victim@example.com"}
                },
                "vulnerable_endpoints": ["/api/vuln/wildcard"],
                "request_details": [
                    {
                        "method": "GET",
                        "url": "/api/vuln/wildcard",
                        "headers": {"Origin": "http://evil.com"}
                    }
                ],
                "response_details": [
                    {
                        "status": 200,
                        "headers": {
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Credentials": "true"
                        }
                    }
                ],
                "educational_notes": "This vulnerability allows any origin to make authenticated requests."
            }
        }
    )
