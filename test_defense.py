import pytest
from src.defense import (
    is_allowed_target,
    redact_sensitive,
    stub_scan_network,
    mock_test_api_vulnerabilities
)

def test_is_allowed_target_exact_match(monkeypatch):
    monkeypatch.setenv("ALLOWED_TARGETS", "127.0.0.1,localhost")
    assert is_allowed_target("127.0.0.1")
    assert is_allowed_target("localhost")
    assert not is_allowed_target("malicious.com")

def test_redact_sensitive_removes_api_key():
    data = {"api_key": "sk-1234567890abcdef"}
    redacted = redact_sensitive(data)
    assert "api_key" not in redacted
    assert "[REDACTED_API_KEY]" not in str(redacted)

def test_stub_scan_network_allowed():
    result = stub_scan_network("127.0.0.1")
    assert "open_ports" in result
    assert isinstance(result["open_ports"], list)

def test_stub_scan_network_disallowed():
    result = stub_scan_network("malicious.com")
    assert "error" in result

def test_mock_test_api_vulnerabilities_with_api_key():
    fake_api_key = "sk-testkey123"
    prompts = ["Explain API key rotation best practices"]
    result = mock_test_api_vulnerabilities("http://fake-url", fake_api_key, prompts)
    assert "vulnerabilities" in result
    assert "leaks" in result

def test_mock_test_api_vulnerabilities_missing_api_key():
    result = mock_test_api_vulnerabilities("http://fake-url", None, ["test"])
    assert "error" in result