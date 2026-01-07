"""
CORS Configuration Models
Defines configuration structures for custom CORS middleware
"""

from typing import List, Union, Dict
from pydantic import BaseModel, Field


class CORSConfig(BaseModel):
    """
    Configuration for CORS policy on a specific route or set of routes
    
    Attributes:
        allow_origins: List of allowed origins or "*" for wildcard
        allow_credentials: Whether to allow credentials (cookies, auth headers)
        allow_methods: List of allowed HTTP methods
        allow_headers: List of allowed request headers
        expose_headers: List of headers exposed to the client
        max_age: Maximum age for preflight cache in seconds
        vary_header: Whether to include Vary: Origin header
    """
    allow_origins: Union[List[str], str] = Field(
        default_factory=list,
        description="List of allowed origins or '*' for wildcard"
    )
    allow_credentials: bool = Field(
        default=False,
        description="Whether to allow credentials"
    )
    allow_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="Allowed HTTP methods"
    )
    allow_headers: List[str] = Field(
        default_factory=lambda: ["Content-Type", "Authorization"],
        description="Allowed request headers"
    )
    expose_headers: List[str] = Field(
        default_factory=list,
        description="Headers exposed to the client"
    )
    max_age: int = Field(
        default=600,
        description="Preflight cache duration in seconds"
    )
    vary_header: bool = Field(
        default=True,
        description="Whether to include Vary: Origin header"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "allow_origins": ["https://example.com", "https://trusted.com"],
                "allow_credentials": True,
                "allow_methods": ["GET", "POST"],
                "allow_headers": ["Content-Type"],
                "expose_headers": ["X-Custom-Header"],
                "max_age": 600,
                "vary_header": True
            }
        }


class RouteConfig(BaseModel):
    """
    Maps route patterns to CORS configurations
    
    Attributes:
        path_prefix: Route path prefix (e.g., "/api/vuln/wildcard")
        cors_config: CORS configuration for this route
    """
    path_prefix: str = Field(
        description="Route path prefix to match"
    )
    cors_config: CORSConfig = Field(
        description="CORS configuration for this route"
    )


# Route-to-config mapping structure
RouteConfigMapping = Dict[str, CORSConfig]


# Predefined CORS configurations for vulnerable endpoints
VULNERABLE_CONFIGS: RouteConfigMapping = {
    "/api/vuln/wildcard": CORSConfig(
        allow_origins="*",
        allow_credentials=True,
        vary_header=False
    ),
    "/api/vuln/reflection": CORSConfig(
        allow_origins=[],  # Will be dynamically set to reflect Origin header
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        vary_header=False
    ),
    "/api/vuln/null-origin": CORSConfig(
        allow_origins=["null"],
        allow_credentials=True,
        vary_header=False
    ),
    "/api/vuln/permissive": CORSConfig(
        allow_origins=[],  # Will use substring matching for "trusted.com"
        allow_credentials=True,
        vary_header=False
    ),
    "/api/vuln/vary": CORSConfig(
        allow_origins=["https://example.com", "https://trusted.com"],
        allow_credentials=True,
        vary_header=False  # Intentionally missing Vary header
    ),
}


# Predefined CORS configurations for secure endpoints
SECURE_CONFIGS: RouteConfigMapping = {
    "/api/sec/wildcard": CORSConfig(
        allow_origins=["https://example.com", "https://trusted.com"],
        allow_credentials=True,
        vary_header=True
    ),
    "/api/sec/reflection": CORSConfig(
        allow_origins=["https://example.com", "https://trusted.com"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        vary_header=True
    ),
    "/api/sec/null-origin": CORSConfig(
        allow_origins=["https://example.com", "https://trusted.com"],
        allow_credentials=True,
        vary_header=True
    ),
    "/api/sec/permissive": CORSConfig(
        allow_origins=["https://example.com", "https://trusted.com"],
        allow_credentials=True,
        vary_header=True
    ),
    "/api/sec/vary": CORSConfig(
        allow_origins=["https://example.com", "https://trusted.com"],
        allow_credentials=True,
        vary_header=True
    ),
}


# Combined route configuration mapping
ALL_ROUTE_CONFIGS: RouteConfigMapping = {
    **VULNERABLE_CONFIGS,
    **SECURE_CONFIGS
}
