"""
Error handlers for the CORS Vulnerability Demonstration Project

Implements comprehensive error handling for:
- 400 Bad Request
- 401 Unauthorized (authentication errors)
- 403 Forbidden (CORS and authorization errors)
- 404 Not Found
- 500 Internal Server Error
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from datetime import datetime
from app.models.errors import ErrorResponse


async def bad_request_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle 400 Bad Request errors
    Typically validation errors or malformed requests
    """
    error_response = ErrorResponse(
        error="Bad Request",
        details=str(exc) if str(exc) else "Invalid request format or parameters",
        timestamp=datetime.now(),
        path=request.url.path
    )
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=error_response.model_dump(mode='json')
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handle FastAPI validation errors (422 -> 400)
    Provides detailed validation error information
    """
    error_details = "; ".join([
        f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
        for err in exc.errors()
    ])
    
    error_response = ErrorResponse(
        error="Validation Error",
        details=error_details,
        timestamp=datetime.now(),
        path=request.url.path
    )
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=error_response.model_dump(mode='json')
    )


async def unauthorized_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle 401 Unauthorized errors
    Authentication-related errors (missing or invalid credentials/sessions)
    
    Common scenarios:
    - Invalid username or password
    - Missing session cookie
    - Expired session
    """
    error_message = str(exc) if str(exc) else "Authentication required"
    
    # Map common authentication error messages
    if "invalid" in error_message.lower() and ("username" in error_message.lower() or "password" in error_message.lower()):
        error_message = "Invalid username or password"
    elif "session" in error_message.lower() and "expired" in error_message.lower():
        error_message = "Session expired"
    elif "authentication" in error_message.lower() or not str(exc):
        error_message = "Authentication required"
    
    error_response = ErrorResponse(
        error="Unauthorized",
        details=error_message,
        timestamp=datetime.now(),
        path=request.url.path
    )
    
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=error_response.model_dump(mode='json'),
        headers={"WWW-Authenticate": "Cookie"}
    )


async def forbidden_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle 403 Forbidden errors
    CORS-related errors and authorization failures
    
    Common scenarios:
    - Null origin not allowed
    - Origin not in whitelist
    - Insufficient permissions
    """
    error_message = str(exc) if str(exc) else "Access forbidden"
    
    # Map common CORS error messages
    if "null" in error_message.lower() and "origin" in error_message.lower():
        error_message = "Null origin not allowed"
    elif "origin" in error_message.lower() and "whitelist" in error_message.lower():
        error_message = "Origin not in whitelist"
    elif "permission" in error_message.lower():
        error_message = "Insufficient permissions"
    
    error_response = ErrorResponse(
        error="Forbidden",
        details=error_message,
        timestamp=datetime.now(),
        path=request.url.path
    )
    
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content=error_response.model_dump(mode='json')
    )


async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle 404 Not Found errors
    Endpoint or resource does not exist
    """
    error_response = ErrorResponse(
        error="Not Found",
        details=f"The requested endpoint does not exist",
        timestamp=datetime.now(),
        path=request.url.path
    )
    
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content=error_response.model_dump(mode='json')
    )


async def internal_server_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle 500 Internal Server Error
    Generic server errors (no stack traces in production)
    """
    # In production, don't expose internal error details
    # In development, you might want to include more information
    error_response = ErrorResponse(
        error="Internal Server Error",
        details="An unexpected error occurred. Please try again later.",
        timestamp=datetime.now(),
        path=request.url.path
    )
    
    # Log the actual error for debugging (in a real app, use proper logging)
    print(f"Internal Server Error: {exc}")
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(mode='json')
    )
