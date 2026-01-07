"""
Secure CORS Endpoints Router
Demonstrates proper CORS configurations and security best practices

These endpoints mirror the vulnerable endpoints but implement secure
CORS policies with proper origin validation, whitelist checking, and
appropriate header handling.
"""

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any
from app.middleware.origin_validation import (
    validate_origin_for_reflection,
    validate_origin_secure_permissive
)


# Create router with /api/sec prefix
router = APIRouter(
    prefix="/api/sec",
    tags=["secure"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Forbidden"}
    }
)


# Health check for secure endpoints
@router.get("/health")
async def secure_health() -> Dict[str, Any]:
    """
    Health check endpoint for secure routes
    
    Returns:
        Status information
    """
    return {
        "status": "operational",
        "endpoints": [
            "/api/sec/wildcard",
            "/api/sec/reflection",
            "/api/sec/null-origin",
            "/api/sec/permissive",
            "/api/sec/vary"
        ],
        "security": "These endpoints implement secure CORS configurations"
    }



@router.get("/wildcard")
async def wildcard_secure(request: Request) -> JSONResponse:
    """
    Secure implementation: Specific origin whitelist instead of wildcard
    
    This endpoint demonstrates the secure approach of using a specific
    origin whitelist instead of wildcard (*) when credentials are enabled.
    The CORS middleware will validate the origin against the whitelist.
    
    Reference: MISC 99, §2.1 (Secure Implementation)
    Requirements: 2.2
    
    Returns:
        User profile data if authenticated (same as vulnerable version)
    """
    # Get authenticated user from request state (set by auth middleware)
    user = request.state.user
    
    # Return user profile data (same data as vulnerable endpoint)
    profile_data = {
        "username": user.username,
        "role": user.role,
        "email": f"{user.username}@example.com",
        "api_key": f"key_{user.username}_secret123",
        "preferences": {
            "theme": "dark",
            "notifications": True
        },
        "security": "secure-wildcard-replacement",
        "educational_note": "This endpoint uses a specific origin whitelist instead of wildcard, preventing unauthorized cross-origin access"
    }
    
    return JSONResponse(content=profile_data)



@router.post("/reflection")
async def reflection_secure(request: Request) -> JSONResponse:
    """
    Secure implementation: Origin validation against whitelist
    
    This endpoint demonstrates the secure approach of validating origins
    against a predefined whitelist using exact string matching (including
    protocol and port) before reflecting them in CORS headers.
    
    Reference: MISC 99, §2.2 (Secure Implementation)
    Requirements: 2.3
    
    Returns:
        Banking transaction data if authenticated (same as vulnerable version)
    """
    # Get authenticated user from request state
    user = request.state.user
    
    # Get origin from request headers
    origin = request.headers.get("origin", "")
    
    # Validate origin against whitelist (defined in CORS config)
    # The CORS middleware handles the actual validation and header setting
    # This endpoint just needs to check if we should reject the request
    allowed_origins = ["https://example.com", "https://trusted.com"]
    
    # If origin is present but not in whitelist, reject with 403
    if origin and not validate_origin_for_reflection(origin, allowed_origins):
        raise HTTPException(
            status_code=403,
            detail="Origin not in whitelist"
        )
    
    # Parse request body if present
    try:
        body = await request.json()
    except:
        body = {}
    
    # Return sensitive banking transaction data (same as vulnerable endpoint)
    transaction_data = {
        "account_holder": user.username,
        "account_number": f"****{hash(user.username) % 10000:04d}",
        "balance": 15420.50,
        "recent_transactions": [
            {
                "id": "tx_001",
                "date": "2024-01-05",
                "description": "Salary deposit",
                "amount": 5000.00,
                "type": "credit"
            },
            {
                "id": "tx_002",
                "date": "2024-01-04",
                "description": "Rent payment",
                "amount": -1500.00,
                "type": "debit"
            },
            {
                "id": "tx_003",
                "date": "2024-01-03",
                "description": "Grocery shopping",
                "amount": -250.75,
                "type": "debit"
            }
        ],
        "security": "secure-origin-validation",
        "educational_note": "This endpoint validates origins against a whitelist using exact matching before allowing access"
    }
    
    return JSONResponse(content=transaction_data)



@router.get("/null-origin")
async def null_origin_secure(request: Request) -> JSONResponse:
    """
    Secure implementation: Explicit rejection of null origins
    
    This endpoint demonstrates the secure approach of explicitly rejecting
    null origins with a 403 Forbidden status. Null origins come from
    sandboxed iframes and should not be trusted.
    
    Reference: MISC 99, §2.3 (Secure Implementation)
    Requirements: 2.4
    
    Returns:
        API key management data if authenticated (same as vulnerable version)
        403 Forbidden if origin is "null"
    """
    # Get origin from request headers
    origin = request.headers.get("origin", "")
    
    # Explicitly reject null origins
    if origin == "null":
        raise HTTPException(
            status_code=403,
            detail="Null origin not allowed"
        )
    
    # Get authenticated user from request state
    user = request.state.user
    
    # Return sensitive API key management data (same as vulnerable endpoint)
    api_data = {
        "user": user.username,
        "api_keys": [
            {
                "key_id": "key_prod_001",
                "key_value": f"sk_live_{user.username}_abc123xyz789",
                "name": "Production API Key",
                "created": "2024-01-01",
                "permissions": ["read", "write", "delete"]
            },
            {
                "key_id": "key_test_002",
                "key_value": f"sk_test_{user.username}_def456uvw012",
                "name": "Test API Key",
                "created": "2024-01-02",
                "permissions": ["read"]
            }
        ],
        "webhook_secrets": [
            {
                "endpoint": "https://example.com/webhook",
                "secret": f"whsec_{user.username}_secret_token"
            }
        ],
        "security": "null-origin-rejection",
        "educational_note": "This endpoint explicitly rejects null origins with 403 status, preventing sandboxed iframe attacks"
    }
    
    return JSONResponse(content=api_data)



@router.get("/permissive")
async def permissive_secure(request: Request) -> JSONResponse:
    """
    Secure implementation: Exact string matching for origins
    
    This endpoint demonstrates the secure approach of performing exact
    string matching (including protocol and port) instead of substring
    matching. This prevents attackers from using domains like
    "attacker-trusted.com" to bypass validation.
    
    Reference: MISC 99, §2.4 (Secure Implementation)
    Requirements: 2.5
    
    Returns:
        Administrative settings data if authenticated (same as vulnerable version)
    """
    # Get origin from request headers
    origin = request.headers.get("origin", "")
    
    # Validate origin using exact matching (defined in CORS config)
    allowed_origins = ["https://example.com", "https://trusted.com"]
    
    # If origin is present but not exactly matching whitelist, reject with 403
    if origin and not validate_origin_secure_permissive(origin, allowed_origins):
        raise HTTPException(
            status_code=403,
            detail="Origin does not exactly match whitelist"
        )
    
    # Get authenticated user from request state
    user = request.state.user
    
    # Return sensitive administrative settings (same as vulnerable endpoint)
    admin_data = {
        "user": user.username,
        "role": user.role,
        "system_settings": {
            "database_url": "postgresql://admin:password@db.internal:5432/prod",
            "redis_url": "redis://cache.internal:6379",
            "secret_key": "super_secret_key_do_not_share",
            "encryption_key": "aes256_encryption_key_xyz",
            "admin_panel_url": "https://admin.internal.example.com"
        },
        "feature_flags": {
            "debug_mode": False,
            "maintenance_mode": False,
            "new_ui": True
        },
        "security_settings": {
            "mfa_enabled": True,
            "session_timeout": 3600,
            "password_policy": "strong"
        },
        "security": "exact-origin-matching",
        "educational_note": "This endpoint uses exact string matching including protocol and port, preventing substring-based bypass attacks"
    }
    
    return JSONResponse(content=admin_data)



@router.get("/vary")
async def vary_secure(request: Request) -> JSONResponse:
    """
    Secure implementation: Includes Vary: Origin header and cache control
    
    This endpoint demonstrates the secure approach of including the
    Vary: Origin header when serving different CORS headers based on
    the origin. This prevents cache poisoning attacks. Additionally,
    it includes cache control headers to prevent sensitive data caching.
    
    Reference: MISC 99, §3.1 (Secure Implementation)
    Requirements: 6.2, 6.3
    
    Returns:
        Cached content with proper cache control headers
    """
    # Get authenticated user from request state
    user = request.state.user
    
    # Return content with proper cache control (same data as vulnerable endpoint)
    cached_data = {
        "user": user.username,
        "content": {
            "title": "Sensitive Cached Content",
            "data": "This content is properly protected from cache poisoning",
            "timestamp": "2024-01-06T12:00:00Z",
            "user_specific_data": {
                "preferences": {"theme": "dark"},
                "private_notes": "These are private user notes",
                "session_info": f"Session for {user.username}"
            }
        },
        "cache_info": {
            "cacheable": False,
            "note": "With Vary: Origin and cache control, caches serve correct CORS headers"
        },
        "security": "vary-header-and-cache-control",
        "educational_note": "This endpoint includes Vary: Origin header and cache control headers to prevent cache poisoning"
    }
    
    # Create response with cache control headers
    response = JSONResponse(content=cached_data)
    
    # Add cache control headers to prevent sensitive data caching
    # Note: The Vary: Origin header is added by the CORS middleware
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    return response
