"""
Origin Validation Utilities
Functions for validating origins against CORS policies
"""

from typing import List, Optional
from urllib.parse import urlparse


def exact_origin_match(origin: str, allowed_origins: List[str]) -> bool:
    """
    Perform exact origin matching including protocol, domain, and port
    
    This is the secure implementation that validates origins against a whitelist
    using exact string matching. Protocol, domain, and port must all match exactly.
    
    Args:
        origin: The origin to validate (e.g., "https://example.com:443")
        allowed_origins: List of allowed origins
        
    Returns:
        True if origin exactly matches an allowed origin, False otherwise
        
    Examples:
        >>> exact_origin_match("https://example.com", ["https://example.com"])
        True
        >>> exact_origin_match("http://example.com", ["https://example.com"])
        False
        >>> exact_origin_match("https://example.com:8080", ["https://example.com"])
        False
    """
    if not origin or not allowed_origins:
        return False
    
    # Normalize origins by parsing and reconstructing
    try:
        origin_parsed = urlparse(origin)
        origin_normalized = f"{origin_parsed.scheme}://{origin_parsed.netloc}"
        
        for allowed in allowed_origins:
            allowed_parsed = urlparse(allowed)
            allowed_normalized = f"{allowed_parsed.scheme}://{allowed_parsed.netloc}"
            
            if origin_normalized == allowed_normalized:
                return True
                
    except Exception:
        # If parsing fails, fall back to exact string comparison
        return origin in allowed_origins
    
    return False


def substring_origin_match(origin: str, substring: str) -> bool:
    """
    Perform substring matching on origin (VULNERABLE IMPLEMENTATION)
    
    This is an intentionally vulnerable implementation that accepts any origin
    containing a specific substring. This allows attackers to bypass CORS
    restrictions by registering domains like "attacker-trusted.com" when
    the substring is "trusted.com".
    
    WARNING: This is for educational purposes only. Never use substring
    matching for origin validation in production code.
    
    Args:
        origin: The origin to validate
        substring: The substring to search for in the origin
        
    Returns:
        True if origin contains the substring, False otherwise
        
    Examples:
        >>> substring_origin_match("https://trusted.com", "trusted.com")
        True
        >>> substring_origin_match("https://attacker-trusted.com", "trusted.com")
        True  # VULNERABLE!
        >>> substring_origin_match("https://trusted.com.evil.com", "trusted.com")
        True  # VULNERABLE!
    """
    if not origin or not substring:
        return False
    
    return substring in origin


def whitelist_origin_validation(
    origin: str, 
    allowed_origins: List[str],
    allow_null: bool = False
) -> Optional[str]:
    """
    Validate origin against whitelist and return the origin if valid
    
    This is the secure implementation that should be used in production.
    It performs exact matching and optionally handles null origins.
    
    Args:
        origin: The origin to validate
        allowed_origins: List of allowed origins
        allow_null: Whether to allow "null" origin (default: False)
        
    Returns:
        The origin if valid, None otherwise
        
    Examples:
        >>> whitelist_origin_validation("https://example.com", ["https://example.com"])
        'https://example.com'
        >>> whitelist_origin_validation("https://evil.com", ["https://example.com"])
        None
        >>> whitelist_origin_validation("null", ["https://example.com"], allow_null=True)
        'null'
    """
    if not origin:
        return None
    
    # Handle null origin
    if origin == "null":
        return "null" if allow_null else None
    
    # Validate against whitelist using exact matching
    if exact_origin_match(origin, allowed_origins):
        return origin
    
    return None


def validate_origin_for_reflection(
    origin: str,
    allowed_origins: List[str]
) -> Optional[str]:
    """
    Validate origin for reflection endpoints (secure implementation)
    
    This function is used by secure reflection endpoints to validate
    origins before reflecting them in the Access-Control-Allow-Origin header.
    
    Args:
        origin: The origin to validate
        allowed_origins: List of allowed origins
        
    Returns:
        The origin if it's in the whitelist, None otherwise
    """
    return whitelist_origin_validation(origin, allowed_origins, allow_null=False)


def vulnerable_reflection(origin: str) -> str:
    """
    Vulnerable origin reflection (VULNERABLE IMPLEMENTATION)
    
    This function blindly reflects any origin value without validation.
    This is for educational purposes to demonstrate the vulnerability.
    
    WARNING: Never use this in production. Always validate origins
    against a whitelist.
    
    Args:
        origin: The origin to reflect
        
    Returns:
        The same origin value (reflected)
        
    Examples:
        >>> vulnerable_reflection("https://evil.com")
        'https://evil.com'
        >>> vulnerable_reflection("null")
        'null'
    """
    return origin if origin else ""


def validate_origin_permissive(
    origin: str,
    substring: str
) -> Optional[str]:
    """
    Validate origin using permissive substring matching (VULNERABLE)
    
    This is the vulnerable implementation used by the permissive endpoint.
    It accepts any origin containing the specified substring.
    
    Args:
        origin: The origin to validate
        substring: The substring to search for
        
    Returns:
        The origin if it contains the substring, None otherwise
    """
    if substring_origin_match(origin, substring):
        return origin
    return None


def validate_origin_secure_permissive(
    origin: str,
    allowed_origins: List[str]
) -> Optional[str]:
    """
    Validate origin using exact matching (secure implementation)
    
    This is the secure version used by the secure permissive endpoint.
    It performs exact string matching including protocol and port.
    
    Args:
        origin: The origin to validate
        allowed_origins: List of allowed origins
        
    Returns:
        The origin if it exactly matches an allowed origin, None otherwise
    """
    return whitelist_origin_validation(origin, allowed_origins, allow_null=False)
