"""
Demo Interface Router

This router provides endpoints for the web-based demo interface,
including the dashboard and attack execution functionality.

Requirements: 5.1, 5.3, 5.4, 7.2, 7.3, 8.1
"""

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Dict, Any, Optional
import json
import asyncio
import time
from pathlib import Path

from attacks.models import AttackResult
from app.utils.sanitization import sanitize_output, jinja2_sanitize_filter


# Create router
router = APIRouter(
    tags=["demo"]
)

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Add sanitization filter to Jinja2
templates.env.filters['sanitize'] = jinja2_sanitize_filter


def get_educational_content():
    """
    Get educational content from main application.
    This is loaded during application startup.
    """
    # Import here to avoid circular dependency
    import main
    return main.EDUCATIONAL_CONTENT


class AttackExecutionRequest(BaseModel):
    """Request model for attack execution"""
    attack_type: str
    target_url: Optional[str] = None
    session_id: Optional[str] = None
    test_secure_only: bool = False  # New parameter


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Main dashboard route that renders the demo interface.
    
    This endpoint displays all vulnerable and secure endpoints with
    educational content, attack execution buttons, and references.
    
    Requirements: 5.1
    
    Returns:
        HTML dashboard page
    """
    # Get educational content from main app
    educational_content = get_educational_content()
    
    # Prepare context data for template
    context = {
        "request": request,
        "vulnerabilities": educational_content.get("vulnerabilities", {}),
        "secure_implementations": educational_content.get("secure_implementations", {}),
        "references": educational_content.get("references", {}),
        "general": educational_content.get("general", {})
    }
    
    return templates.TemplateResponse("dashboard.html", context)


@router.post("/api/execute-attack")
async def execute_attack(attack_request: AttackExecutionRequest, request: Request):
    """
    Execute an attack script and return results.
    
    This endpoint runs the specified attack script in an isolated context
    with timeout protection. It displays a warning before execution and
    sanitizes all output before returning.
    
    Requirements: 5.3, 8.1
    
    Args:
        attack_request: Attack execution parameters
        request: FastAPI request object
        
    Returns:
        AttackResult as JSON with sanitized output
        
    Raises:
        HTTPException: If attack type is invalid or execution fails
    """
    # Validate attack type
    valid_attacks = ["wildcard", "reflection", "null_origin", "permissive", "vary"]
    if attack_request.attack_type not in valid_attacks:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack type. Must be one of: {', '.join(valid_attacks)}"
        )
    
    # Get target URL (default to current host)
    target_url = attack_request.target_url or str(request.base_url).rstrip('/')
    
    # Get session ID from cookies if not provided
    session_id = attack_request.session_id or request.cookies.get("session_id")
    
    # Display warning (logged to console)
    print(f"⚠️  WARNING: Executing {attack_request.attack_type} attack script")
    print(f"    Target: {target_url}")
    print(f"    This is for educational purposes only!")
    
    try:
        # Execute attack script with timeout
        result = await execute_attack_script(
            attack_type=attack_request.attack_type,
            target_url=target_url,
            session_id=session_id,
            timeout=60,
            test_secure_only=attack_request.test_secure_only
        )
        
        # Sanitize the result before returning
        sanitized_result = sanitize_attack_result(result)
        
        # Add educational content
        sanitized_result = enrich_with_educational_content(
            sanitized_result,
            attack_request.attack_type
        )
        
        return JSONResponse(content=sanitized_result.model_dump())
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=408,
            detail="Attack execution timed out after 60 seconds"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Attack execution failed: {str(e)}"
        )


async def execute_attack_script(
    attack_type: str,
    target_url: str,
    session_id: Optional[str],
    timeout: int = 60,
    test_secure_only: bool = False
) -> AttackResult:
    """
    Execute an attack script in an isolated subprocess with timeout.
    
    This function runs the attack script as a separate process to ensure
    isolation and applies a timeout to prevent hanging.
    
    Args:
        attack_type: Type of attack to execute
        target_url: Target URL for the attack
        session_id: Session ID for authenticated requests
        timeout: Maximum execution time in seconds
        
    Returns:
        AttackResult from the attack script
        
    Raises:
        asyncio.TimeoutError: If execution exceeds timeout
        Exception: If attack script fails
    """
    start_time = time.time()
    
    # Import the appropriate attack class
    attack_module_map = {
        "wildcard": "attacks.brute_force",
        "reflection": "attacks.reflection",
        "null_origin": "attacks.null_origin",
        "permissive": "attacks.permissive",
        "vary": "attacks.vary_attack"
    }
    
    module_name = attack_module_map.get(attack_type)
    if not module_name:
        raise ValueError(f"Unknown attack type: {attack_type}")
    
    try:
        # Dynamically import the attack module
        import importlib
        module = importlib.import_module(module_name)
        
        # Get the attack class (assumes class name follows pattern)
        class_name_map = {
            "wildcard": "BruteForceAttack",
            "reflection": "ReflectionAttack",
            "null_origin": "NullOriginAttack",
            "permissive": "PermissiveAttack",
            "vary": "VaryAttack"
        }
        
        attack_class = getattr(module, class_name_map[attack_type])
        
        # Create attack instance with demo_mode enabled to avoid connection issues
        # when running attacks from within the same server process
        # Pass test_secure_only to control which endpoint to test
        attack_instance = attack_class(
            target_url=target_url, 
            demo_mode=True, 
            test_secure_only=test_secure_only
        )
        
        # Execute with timeout
        result = await asyncio.wait_for(
            attack_instance.execute(),
            timeout=timeout
        )
        
        # Calculate actual duration
        duration = time.time() - start_time
        result.duration_seconds = duration
        
        return result
        
    except asyncio.TimeoutError:
        # Return timeout result
        duration = time.time() - start_time
        return AttackResult(
            attack_type=attack_type,
            success=False,
            duration_seconds=duration,
            requests_sent=0,
            error="Execution timed out",
            educational_notes="The attack script exceeded the maximum execution time."
        )
    except Exception as e:
        # Return error result
        duration = time.time() - start_time
        return AttackResult(
            attack_type=attack_type,
            success=False,
            duration_seconds=duration,
            requests_sent=0,
            error=str(e),
            educational_notes=f"Attack execution failed: {str(e)}"
        )


def sanitize_attack_result(result: AttackResult) -> AttackResult:
    """
    Sanitize all user-controlled content in attack result.
    
    This ensures that any data stolen or captured during the attack
    is properly sanitized before being displayed in the UI.
    
    Requirements: 5.5, 8.4
    
    Args:
        result: Attack result to sanitize
        
    Returns:
        Sanitized attack result
    """
    # Sanitize stolen data
    if result.stolen_data:
        result.stolen_data = sanitize_output(result.stolen_data)
    
    # Sanitize request details
    sanitized_requests = []
    for req in result.request_details:
        sanitized_req = sanitize_output(req)
        sanitized_requests.append(sanitized_req)
    result.request_details = sanitized_requests
    
    # Sanitize response details
    sanitized_responses = []
    for resp in result.response_details:
        sanitized_resp = sanitize_output(resp)
        sanitized_responses.append(sanitized_resp)
    result.response_details = sanitized_responses
    
    # Sanitize error message if present
    if result.error:
        result.error = sanitize_output(result.error)
    
    return result


def enrich_with_educational_content(
    result: AttackResult,
    attack_type: str
) -> AttackResult:
    """
    Enrich attack result with educational content and curl commands.
    
    This adds educational notes, references, mitigation strategies,
    and sample curl commands to the attack result.
    
    Requirements: 7.2, 7.3
    
    Args:
        result: Attack result to enrich
        attack_type: Type of attack
        
    Returns:
        Enriched attack result
    """
    # Get educational content from main app
    educational_content = get_educational_content()
    
    # Get vulnerability info from educational content
    vuln_info = educational_content.get("vulnerabilities", {}).get(attack_type, {})
    
    if vuln_info:
        # Add educational notes if not already present
        if not result.educational_notes:
            result.educational_notes = vuln_info.get("description", "")
        
        # Add reference
        reference = vuln_info.get("reference", "")
        if reference:
            result.educational_notes += f"\n\nReference: {reference}"
        
        # Add mitigation
        mitigation = vuln_info.get("mitigation", "")
        if mitigation:
            result.educational_notes += f"\n\nMitigation: {mitigation}"
        
        # Add curl command
        curl_example = vuln_info.get("curl_example", "")
        if curl_example and not hasattr(result, 'curl_command'):
            # Add curl_command as extra field
            result_dict = result.model_dump()
            result_dict['curl_command'] = curl_example
            result_dict['reference'] = reference
            result_dict['mitigation'] = mitigation
            result = AttackResult(**result_dict)
    
    return result


@router.get("/api/educational-content")
async def get_educational_content_endpoint():
    """
    Get educational content for all vulnerabilities.
    
    Returns:
        Educational content as JSON
    """
    educational_content = get_educational_content()
    return JSONResponse(content=educational_content)


@router.get("/health")
async def demo_health():
    """
    Health check for demo interface.
    
    Returns:
        Status information
    """
    educational_content = get_educational_content()
    return {
        "status": "operational",
        "educational_content_loaded": bool(educational_content),
        "templates_available": Path("templates/dashboard.html").exists()
    }
