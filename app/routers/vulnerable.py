"""
Vulnerable CORS Endpoints Router
Demonstrates various CORS misconfigurations for educational purposes

WARNING: These endpoints contain intentional security vulnerabilities.
They should only be used in isolated educational environments.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from typing import Dict, Any


# Create router with /api/vuln prefix
router = APIRouter(
    prefix="/api/vuln",
    tags=["vulnerable"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Forbidden"}
    }
)


@router.get("/wildcard")
async def wildcard_vulnerability(request: Request) -> JSONResponse:
    """
    Vulnerability: Access-Control-Allow-Origin: * with credentials
    
    This endpoint demonstrates the dangerous combination of wildcard CORS
    with credentials enabled, allowing any origin to make authenticated requests.
    
    Reference: MISC 99, §2.1
    Requirements: 1.2
    
    Returns:
        User profile data if authenticated
    """
    # Get authenticated user from request state (set by auth middleware)
    user = request.state.user
    
    # Return user profile data
    profile_data = {
        "username": user.username,
        "role": user.role,
        "email": f"{user.username}@example.com",
        "api_key": f"key_{user.username}_secret123",
        "preferences": {
            "theme": "dark",
            "notifications": True
        },
        "vulnerability": "wildcard-with-credentials",
        "educational_note": "This endpoint uses Access-Control-Allow-Origin: * with credentials, allowing any origin to access authenticated data"
    }
    
    return JSONResponse(content=profile_data)


@router.post("/reflection")
async def reflection_vulnerability(request: Request) -> JSONResponse:
    """
    Vulnerability: Origin reflection without validation
    
    This endpoint reflects any Origin header value in Access-Control-Allow-Origin
    without validation, allowing any malicious origin to access authenticated data.
    
    Reference: MISC 99, §2.2
    Requirements: 1.3
    
    Returns:
        Banking transaction data
    """
    # Get authenticated user from request state
    user = request.state.user
    
    # Parse request body if present
    try:
        body = await request.json()
    except:
        body = {}
    
    # Return sensitive banking transaction data
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
        "vulnerability": "origin-reflection",
        "educational_note": "This endpoint reflects any Origin header without validation, allowing malicious origins to access sensitive data"
    }
    
    return JSONResponse(content=transaction_data)


@router.get("/null-origin")
async def null_origin_vulnerability(request: Request) -> JSONResponse:
    """
    Vulnerability: Accepts Origin: null
    
    This endpoint accepts requests from null origins (sandboxed iframes),
    which can be exploited by attackers using sandboxed contexts.
    
    Reference: MISC 99, §2.3
    Requirements: 1.4
    
    Returns:
        API key management data
    """
    # Get authenticated user from request state
    user = request.state.user
    
    # Return sensitive API key management data
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
        "vulnerability": "null-origin-acceptance",
        "educational_note": "This endpoint accepts Origin: null, which can be exploited via sandboxed iframes"
    }
    
    return JSONResponse(content=api_data)


@router.get("/permissive")
async def permissive_vulnerability(request: Request) -> JSONResponse:
    """
    Vulnerability: Permissive substring filtering
    
    This endpoint accepts any origin containing the substring "trusted.com",
    allowing attackers to use domains like "attacker-trusted.com" or
    "trusted.com.evil.com" to bypass the filter.
    
    Reference: MISC 99, §2.4
    Requirements: 1.5
    
    Returns:
        Administrative settings data
    """
    # Get authenticated user from request state
    user = request.state.user
    
    # Return sensitive administrative settings
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
        "vulnerability": "permissive-substring-filtering",
        "educational_note": "This endpoint uses substring matching for 'trusted.com', accepting malicious origins like 'attacker-trusted.com'"
    }
    
    return JSONResponse(content=admin_data)


@router.get("/vary")
async def vary_vulnerability(request: Request) -> JSONResponse:
    """
    Vulnerability: Missing Vary: Origin header
    
    This endpoint serves different CORS headers based on the origin but doesn't
    include the Vary: Origin header, which can lead to cache poisoning attacks.
    
    Reference: MISC 99, §3.1
    Requirements: 6.1
    
    Returns:
        Cached content that could be poisoned
    """
    # Get authenticated user from request state
    user = request.state.user
    
    # Return content that might be cached
    cached_data = {
        "user": user.username,
        "content": {
            "title": "Sensitive Cached Content",
            "data": "This content might be cached by intermediary proxies",
            "timestamp": "2024-01-06T12:00:00Z",
            "user_specific_data": {
                "preferences": {"theme": "dark"},
                "private_notes": "These are private user notes",
                "session_info": f"Session for {user.username}"
            }
        },
        "cache_info": {
            "cacheable": True,
            "max_age": 300,
            "note": "Without Vary: Origin, caches may serve wrong CORS headers"
        },
        "vulnerability": "missing-vary-header",
        "educational_note": "This endpoint doesn't include Vary: Origin, allowing cache poisoning attacks"
    }
    
    return JSONResponse(content=cached_data)


# Health check for vulnerable endpoints
@router.get("/health")
async def vulnerable_health() -> Dict[str, Any]:
    """
    Health check endpoint for vulnerable routes
    
    Returns:
        Status information
    """
    return {
        "status": "operational",
        "endpoints": [
            "/api/vuln/wildcard",
            "/api/vuln/reflection",
            "/api/vuln/null-origin",
            "/api/vuln/permissive",
            "/api/vuln/vary"
        ],
        "warning": "These endpoints contain intentional vulnerabilities for educational purposes"
    }
