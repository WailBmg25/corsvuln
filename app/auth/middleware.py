"""
Authentication middleware for protecting endpoints
"""

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from app.auth.session_manager import session_store


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that validates session cookies on protected endpoints
    """
    
    def __init__(self, app, protected_paths: list = None):
        """
        Initialize authentication middleware
        
        Args:
            app: FastAPI application
            protected_paths: List of path prefixes that require authentication
        """
        super().__init__(app)
        self.protected_paths = protected_paths or [
            "/api/vuln/",
            "/api/sec/"
        ]
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and validate authentication for protected paths
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler in chain
            
        Returns:
            Response from next handler or 401 error
        """
        # Check if path requires authentication
        path = request.url.path
        requires_auth = any(path.startswith(prefix) for prefix in self.protected_paths)
        
        if requires_auth:
            # Get session ID from cookie
            session_id = request.cookies.get("session_id")
            
            if not session_id:
                # Import here to avoid circular dependency
                from app.error_handlers import unauthorized_handler
                return await unauthorized_handler(request, Exception("No session cookie found"))
            
            # Validate session
            user = session_store.validate_session(session_id)
            
            if not user:
                # Import here to avoid circular dependency
                from app.error_handlers import unauthorized_handler
                return await unauthorized_handler(request, Exception("Session validation failed"))
            
            # Attach user to request state for use in handlers
            request.state.user = user
        
        # Continue to next handler
        response = await call_next(request)
        return response


def get_current_user(request: Request):
    """
    Dependency to get current authenticated user from request state
    
    Args:
        request: FastAPI request object
        
    Returns:
        User object if authenticated
        
    Raises:
        HTTPException: 401 if not authenticated
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return request.state.user
