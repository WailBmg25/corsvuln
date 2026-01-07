"""
Authentication router for login and session management
"""

from fastapi import APIRouter, Response, HTTPException, status
from pydantic import BaseModel
from app.auth.session_manager import session_store


class LoginRequest(BaseModel):
    """Login request model"""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response model"""
    message: str
    username: str
    role: str


router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, response: Response):
    """
    Authenticate user and create session
    
    Args:
        request: Login credentials
        response: FastAPI response object for setting cookies
        
    Returns:
        Login response with user information
        
    Raises:
        HTTPException: 401 if credentials are invalid
    """
    # Attempt to create session
    session_id = session_store.create_session(request.username, request.password)
    
    if session_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Get user information
    user = session_store.validate_session(session_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session creation failed"
        )
    
    # Set session cookie with secure settings
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,  # Prevent JavaScript access
        samesite="lax",  # CSRF protection
        max_age=3600,  # 1 hour
        secure=False  # Set to True in production with HTTPS
    )
    
    return LoginResponse(
        message="Login successful",
        username=user.username,
        role=user.role
    )


@router.post("/logout")
async def logout(response: Response, session_id: str = None):
    """
    Logout user and destroy session
    
    Args:
        response: FastAPI response object for clearing cookies
        session_id: Session ID from cookie
        
    Returns:
        Logout confirmation message
    """
    if session_id:
        session_store.destroy_session(session_id)
    
    # Clear session cookie
    response.delete_cookie(key="session_id")
    
    return {"message": "Logout successful"}
