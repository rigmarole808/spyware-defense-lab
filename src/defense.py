"""
Cybersecurity defense module for Spyware Defense Lab.

This module provides security functions for:
- Target validation and access control
- Sensitive data redaction
- Network scanning stubs
- API vulnerability testing mocks
"""

import os
from typing import Dict, List, Any, Optional


def is_allowed_target(target: str) -> bool:
    """
    Check if a target is in the allowed targets list.
    
    Args:
        target: The target to check (e.g., IP address or hostname)
        
    Returns:
        True if the target is allowed, False otherwise
    """
    allowed_targets = os.environ.get("ALLOWED_TARGETS", "")
    if not allowed_targets:
        return False
    
    allowed_list = [t.strip() for t in allowed_targets.split(",")]
    return target in allowed_list


def redact_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove sensitive information from data dictionaries.
    
    Args:
        data: Dictionary that may contain sensitive keys
        
    Returns:
        New dictionary with sensitive keys removed
    """
    redacted = data.copy()
    
    # Remove API keys and other sensitive fields
    sensitive_keys = ["api_key", "password", "secret", "token"]
    
    for key in sensitive_keys:
        if key in redacted:
            del redacted[key]
    
    return redacted


def stub_scan_network(target: str) -> Dict[str, Any]:
    """
    Stub function for network scanning (for testing purposes only).
    
    Args:
        target: The target to scan
        
    Returns:
        Dictionary with scan results or error
    """
    # Default safe targets
    default_safe_targets = ["127.0.0.1", "localhost", "::1"]
    
    # Check if target is explicitly allowed or is a default safe target
    allowed_targets = os.environ.get("ALLOWED_TARGETS", "")
    if allowed_targets:
        allowed_list = [t.strip() for t in allowed_targets.split(",")]
        if target not in allowed_list and target not in default_safe_targets:
            return {"error": "Target not in allowed list"}
    elif target not in default_safe_targets:
        return {"error": "Target not in allowed list"}
    
    # Stub implementation - returns mock data
    return {
        "target": target,
        "open_ports": [80, 443, 22],
        "status": "scan_complete"
    }


def mock_test_api_vulnerabilities(
    url: str,
    api_key: Optional[str],
    prompts: List[str]
) -> Dict[str, Any]:
    """
    Mock function for testing API vulnerabilities.
    
    Args:
        url: The API endpoint URL to test
        api_key: API key for authentication (required)
        prompts: List of test prompts
        
    Returns:
        Dictionary with vulnerability test results or error
    """
    if not api_key:
        return {"error": "API key is required"}
    
    # Mock implementation - returns simulated results
    return {
        "url": url,
        "vulnerabilities": [],
        "leaks": [],
        "prompts_tested": len(prompts),
        "status": "completed"
    }
