"""
Custom CORS Middleware
Implements per-route CORS policies for vulnerable and secure endpoints
"""

from typing import Dict, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from app.middleware.cors_config import CORSConfig, RouteConfigMapping
from app.middleware.origin_validation import (
    vulnerable_reflection,
    validate_origin_permissive,
    whitelist_origin_validation,
    exact_origin_match
)


class CustomCORSMiddleware(BaseHTTPMiddleware):
    """
    Custom CORS middleware that applies different CORS policies per route
    
    This middleware allows fine-grained control over CORS policies for different
    endpoints, enabling demonstration of both vulnerable and secure configurations.
    
    Attributes:
        route_configs: Mapping of route paths to CORS configurations
    """
    
    def __init__(self, app: ASGIApp, route_configs: RouteConfigMapping):
        """
        Initialize CORS middleware with route-specific configurations
        
        Args:
            app: The ASGI application
            route_configs: Dictionary mapping route paths to CORSConfig objects
        """
        super().__init__(app)
        self.route_configs = route_configs
    
    def get_config_for_path(self, path: str) -> Optional[CORSConfig]:
        """
        Get CORS configuration for a specific path
        
        Matches the longest prefix in the route_configs dictionary.
        
        Args:
            path: The request path
            
        Returns:
            CORSConfig if a matching route is found, None otherwise
        """
        # Try exact match first
        if path in self.route_configs:
            return self.route_configs[path]
        
        # Try prefix matching (longest match wins)
        matching_configs = [
            (prefix, config) 
            for prefix, config in self.route_configs.items() 
            if path.startswith(prefix)
        ]
        
        if matching_configs:
            # Sort by prefix length (longest first) and return the config
            matching_configs.sort(key=lambda x: len(x[0]), reverse=True)
            return matching_configs[0][1]
        
        return None
    
    def determine_allowed_origin(
        self, 
        request_origin: Optional[str], 
        config: CORSConfig,
        path: str
    ) -> Optional[str]:
        """
        Determine the allowed origin based on the request and configuration
        
        This method implements different origin validation strategies based on
        the endpoint path (vulnerable vs secure).
        
        Args:
            request_origin: The Origin header from the request
            config: The CORS configuration for this route
            path: The request path
            
        Returns:
            The origin to include in Access-Control-Allow-Origin header, or None
        """
        if not request_origin:
            return None
        
        # Handle wildcard origin
        if config.allow_origins == "*":
            return "*"
        
        # Handle vulnerable reflection endpoint
        if path == "/api/vuln/reflection":
            # Vulnerable: reflect any origin without validation
            return vulnerable_reflection(request_origin)
        
        # Handle vulnerable permissive endpoint
        if path == "/api/vuln/permissive":
            # Vulnerable: accept any origin containing "trusted.com"
            return validate_origin_permissive(request_origin, "trusted.com")
        
        # Handle vulnerable null origin endpoint
        if path == "/api/vuln/null-origin":
            # Vulnerable: accept null origin
            if request_origin == "null":
                return "null"
            return None
        
        # Handle vulnerable vary endpoint
        if path == "/api/vuln/vary":
            # Accept origins from the list without proper Vary header
            if isinstance(config.allow_origins, list):
                if request_origin in config.allow_origins:
                    return request_origin
            return None
        
        # Handle secure endpoints with whitelist validation
        if path.startswith("/api/sec/"):
            if isinstance(config.allow_origins, list):
                # Secure: validate against whitelist with exact matching
                validated = whitelist_origin_validation(
                    request_origin, 
                    config.allow_origins,
                    allow_null=False  # Secure endpoints reject null
                )
                return validated
        
        # Default: validate against whitelist
        if isinstance(config.allow_origins, list):
            if exact_origin_match(request_origin, config.allow_origins):
                return request_origin
        
        return None
    
    def build_cors_headers(
        self,
        allowed_origin: Optional[str],
        config: CORSConfig,
        is_preflight: bool = False
    ) -> Dict[str, str]:
        """
        Build CORS headers based on configuration
        
        Args:
            allowed_origin: The allowed origin (or None)
            config: The CORS configuration
            is_preflight: Whether this is a preflight request
            
        Returns:
            Dictionary of CORS headers
        """
        headers = {}
        
        # Add Access-Control-Allow-Origin
        if allowed_origin:
            headers["Access-Control-Allow-Origin"] = allowed_origin
        
        # Add Access-Control-Allow-Credentials
        if config.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        
        # Add Vary header if configured
        if config.vary_header and allowed_origin and allowed_origin != "*":
            headers["Vary"] = "Origin"
        
        # Add preflight-specific headers
        if is_preflight:
            if config.allow_methods:
                headers["Access-Control-Allow-Methods"] = ", ".join(config.allow_methods)
            
            if config.allow_headers:
                headers["Access-Control-Allow-Headers"] = ", ".join(config.allow_headers)
            
            if config.max_age:
                headers["Access-Control-Max-Age"] = str(config.max_age)
        
        # Add exposed headers for actual requests
        if not is_preflight and config.expose_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(config.expose_headers)
        
        return headers
    
    async def handle_preflight(
        self,
        request: Request,
        config: CORSConfig,
        path: str
    ) -> Response:
        """
        Handle CORS preflight OPTIONS request
        
        Args:
            request: The request object
            config: The CORS configuration for this route
            path: The request path
            
        Returns:
            Response with appropriate CORS headers
        """
        request_origin = request.headers.get("origin")
        
        # Determine allowed origin
        allowed_origin = self.determine_allowed_origin(request_origin, config, path)
        
        # For secure null-origin endpoint, reject null origins with 403
        if path == "/api/sec/null-origin" and request_origin == "null":
            return JSONResponse(
                status_code=403,
                content={"error": "Null origin not allowed"},
                headers={"Content-Type": "application/json"}
            )
        
        # Build CORS headers
        cors_headers = self.build_cors_headers(allowed_origin, config, is_preflight=True)
        
        # Return preflight response
        return Response(
            status_code=200,
            headers=cors_headers
        )
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and apply CORS headers
        
        Args:
            request: The request object
            call_next: The next middleware or route handler
            
        Returns:
            Response with CORS headers applied
        """
        path = request.url.path
        
        # Get CORS configuration for this path
        config = self.get_config_for_path(path)
        
        # If no CORS config, pass through without CORS headers
        if not config:
            return await call_next(request)
        
        # Handle preflight OPTIONS request
        if request.method == "OPTIONS":
            return await self.handle_preflight(request, config, path)
        
        # Get request origin
        request_origin = request.headers.get("origin")
        
        # For secure null-origin endpoint, reject null origins with 403
        if path == "/api/sec/null-origin" and request_origin == "null":
            return JSONResponse(
                status_code=403,
                content={"error": "Null origin not allowed"},
                headers={"Content-Type": "application/json"}
            )
        
        # Determine allowed origin
        allowed_origin = self.determine_allowed_origin(request_origin, config, path)
        
        # Process the actual request
        response = await call_next(request)
        
        # Build and apply CORS headers
        cors_headers = self.build_cors_headers(allowed_origin, config, is_preflight=False)
        
        for header_name, header_value in cors_headers.items():
            response.headers[header_name] = header_value
        
        return response
