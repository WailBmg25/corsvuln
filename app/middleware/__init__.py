"""Custom middleware for CORS and authentication"""

from app.middleware.cors_middleware import CustomCORSMiddleware
from app.middleware.cors_config import (
    CORSConfig,
    RouteConfig,
    RouteConfigMapping,
    VULNERABLE_CONFIGS,
    SECURE_CONFIGS,
    ALL_ROUTE_CONFIGS
)
from app.middleware.origin_validation import (
    exact_origin_match,
    substring_origin_match,
    whitelist_origin_validation,
    validate_origin_for_reflection,
    vulnerable_reflection,
    validate_origin_permissive,
    validate_origin_secure_permissive
)

__all__ = [
    "CustomCORSMiddleware",
    "CORSConfig",
    "RouteConfig",
    "RouteConfigMapping",
    "VULNERABLE_CONFIGS",
    "SECURE_CONFIGS",
    "ALL_ROUTE_CONFIGS",
    "exact_origin_match",
    "substring_origin_match",
    "whitelist_origin_validation",
    "validate_origin_for_reflection",
    "vulnerable_reflection",
    "validate_origin_permissive",
    "validate_origin_secure_permissive",
]
