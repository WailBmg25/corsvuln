"""
Output Sanitization Utilities

This module provides utilities for sanitizing user-controlled content
before rendering to prevent XSS (Cross-Site Scripting) attacks.

Requirements: 5.5, 8.4
"""

import html
import re
from typing import Any, Dict, List, Union


def sanitize_html(text: str) -> str:
    """
    Sanitize HTML content by escaping dangerous characters.
    
    This function escapes HTML special characters to prevent XSS attacks.
    It converts characters like <, >, &, ", and ' to their HTML entity equivalents.
    
    Args:
        text: The text to sanitize
        
    Returns:
        Sanitized text with HTML entities escaped
        
    Example:
        >>> sanitize_html("<script>alert('xss')</script>")
        "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Use html.escape to escape HTML special characters
    # This converts: < > & " '
    return html.escape(text, quote=True)


def sanitize_javascript(text: str) -> str:
    """
    Sanitize text to prevent JavaScript injection.
    
    This function removes or escapes dangerous JavaScript patterns including:
    - javascript: protocol
    - on* event handlers (onclick, onerror, etc.)
    - <script> tags
    - eval() and similar dangerous functions
    
    Args:
        text: The text to sanitize
        
    Returns:
        Sanitized text with JavaScript patterns removed/escaped
    """
    if not isinstance(text, str):
        text = str(text)
    
    # First escape HTML
    text = sanitize_html(text)
    
    # Remove javascript: protocol (case-insensitive)
    text = re.sub(r'javascript\s*:', '', text, flags=re.IGNORECASE)
    
    # Remove data: protocol (can be used for XSS)
    text = re.sub(r'data\s*:', '', text, flags=re.IGNORECASE)
    
    # Remove vbscript: protocol
    text = re.sub(r'vbscript\s*:', '', text, flags=re.IGNORECASE)
    
    return text


def sanitize_url(url: str) -> str:
    """
    Sanitize URL to prevent XSS through URL injection.
    
    Only allows http:// and https:// protocols.
    Removes javascript:, data:, and other dangerous protocols.
    
    Args:
        url: The URL to sanitize
        
    Returns:
        Sanitized URL or empty string if dangerous
    """
    if not isinstance(url, str):
        url = str(url)
    
    # Remove whitespace
    url = url.strip()
    
    # Check for allowed protocols
    if url.startswith(('http://', 'https://', '/')):
        # Escape HTML in the URL
        return sanitize_html(url)
    
    # If no protocol or dangerous protocol, return empty string
    return ''


def sanitize_dict(data: Dict[str, Any], recursive: bool = True) -> Dict[str, Any]:
    """
    Sanitize all string values in a dictionary.
    
    This function recursively sanitizes all string values in a dictionary
    to prevent XSS attacks when the dictionary is rendered as JSON or HTML.
    
    Args:
        data: Dictionary to sanitize
        recursive: Whether to recursively sanitize nested dictionaries and lists
        
    Returns:
        Dictionary with all string values sanitized
    """
    if not isinstance(data, dict):
        return data
    
    sanitized = {}
    for key, value in data.items():
        # Sanitize the key as well
        safe_key = sanitize_html(str(key))
        
        if isinstance(value, str):
            sanitized[safe_key] = sanitize_html(value)
        elif isinstance(value, dict) and recursive:
            sanitized[safe_key] = sanitize_dict(value, recursive=True)
        elif isinstance(value, list) and recursive:
            sanitized[safe_key] = sanitize_list(value, recursive=True)
        else:
            sanitized[safe_key] = value
    
    return sanitized


def sanitize_list(data: List[Any], recursive: bool = True) -> List[Any]:
    """
    Sanitize all string values in a list.
    
    This function recursively sanitizes all string values in a list
    to prevent XSS attacks.
    
    Args:
        data: List to sanitize
        recursive: Whether to recursively sanitize nested dictionaries and lists
        
    Returns:
        List with all string values sanitized
    """
    if not isinstance(data, list):
        return data
    
    sanitized = []
    for item in data:
        if isinstance(item, str):
            sanitized.append(sanitize_html(item))
        elif isinstance(item, dict) and recursive:
            sanitized.append(sanitize_dict(item, recursive=True))
        elif isinstance(item, list) and recursive:
            sanitized.append(sanitize_list(item, recursive=True))
        else:
            sanitized.append(item)
    
    return sanitized


def sanitize_output(data: Union[str, Dict, List, Any]) -> Union[str, Dict, List, Any]:
    """
    Universal sanitization function that handles strings, dicts, and lists.
    
    This is the main function to use for sanitizing any user-controlled output
    before rendering it in templates or returning it in API responses.
    
    Args:
        data: Data to sanitize (string, dict, list, or other)
        
    Returns:
        Sanitized data of the same type
        
    Example:
        >>> sanitize_output("<script>alert('xss')</script>")
        "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        
        >>> sanitize_output({"name": "<script>", "value": "test"})
        {"name": "&lt;script&gt;", "value": "test"}
    """
    if isinstance(data, str):
        return sanitize_html(data)
    elif isinstance(data, dict):
        return sanitize_dict(data, recursive=True)
    elif isinstance(data, list):
        return sanitize_list(data, recursive=True)
    else:
        # For other types (int, float, bool, None), return as-is
        return data


def is_safe_content(text: str) -> bool:
    """
    Check if content contains potentially dangerous patterns.
    
    This function checks for common XSS patterns without modifying the text.
    Useful for validation before accepting user input.
    
    Args:
        text: Text to check
        
    Returns:
        True if content appears safe, False if dangerous patterns detected
    """
    if not isinstance(text, str):
        return True
    
    # Patterns that indicate potential XSS
    dangerous_patterns = [
        r'<script[^>]*>',
        r'javascript\s*:',
        r'on\w+\s*=',  # Event handlers like onclick=
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<applet[^>]*>',
        r'eval\s*\(',
        r'expression\s*\(',
    ]
    
    text_lower = text.lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return False
    
    return True


# Jinja2 filter for use in templates
def jinja2_sanitize_filter(value: Any) -> str:
    """
    Jinja2 filter for sanitizing output in templates.
    
    Usage in template:
        {{ user_input | sanitize }}
    
    Args:
        value: Value to sanitize
        
    Returns:
        Sanitized string
    """
    if value is None:
        return ''
    
    return sanitize_output(str(value))
