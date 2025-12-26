"""
Cybersecurity defense module for Spyware Defense Lab.

This module provides security functions for:
- Target validation and access control
- Sensitive data redaction
- Network scanning stubs
- API vulnerability testing mocks
"""

import os
from typing import Dict, List, Any, Optional, Set


# Default safe targets that are always allowed
DEFAULT_SAFE_TARGETS = {"127.0.0.1", "localhost", "::1"}


def _get_allowed_targets() -> Set[str]:
    """
    Get the set of allowed targets from environment variables and defaults.
    
    Returns:
        Set of allowed target strings
    """
    allowed = set(DEFAULT_SAFE_TARGETS)
    
    env_targets = os.environ.get("ALLOWED_TARGETS", "")
    if env_targets:
        allowed.update(t.strip() for t in env_targets.split(",") if t.strip())
    
    return allowed


def is_allowed_target(target: str) -> bool:
    """
    Check if a target is in the allowed targets list.
    
    Args:
        target: The target to check (e.g., IP address or hostname)
        
    Returns:
        True if the target is allowed, False otherwise
    """
    # Only check explicit allowed list from environment
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
    
    # Get sensitive keys from environment or use defaults
    env_sensitive_keys = os.environ.get("SENSITIVE_KEYS", "")
    if env_sensitive_keys:
        sensitive_keys = [k.strip() for k in env_sensitive_keys.split(",") if k.strip()]
    else:
        # Default sensitive fields
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
    allowed_targets = _get_allowed_targets()
    
    if target not in allowed_targets:
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
