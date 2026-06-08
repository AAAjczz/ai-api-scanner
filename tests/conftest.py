"""Shared fixtures for scanner tests."""

import sys
import os
import pytest
import responses as _responses

# Ensure the src package is importable even when running tests directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_api_scanner.core.engine import Scanner
from ai_api_scanner.core.result import RuleResult, Status, Finding


FAKE_TARGET = "https://api.example.com/v1"


@pytest.fixture
def scanner():
    """A Scanner pointed at a fake target with a test API key."""
    return Scanner(
        target=FAKE_TARGET,
        api_key="sk-test-key-1234",
        timeout=3.0,
    )


@pytest.fixture
def scanner_no_key():
    """A Scanner without an API key."""
    return Scanner(
        target=FAKE_TARGET,
        api_key=None,
        timeout=3.0,
    )


@pytest.fixture
def mock_responses():
    """Start and stop responses mock context."""
    with _responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def pass_result():
    """A pre-built PASS result."""
    return RuleResult(
        rule_id="test-rule",
        rule_name="Test Rule",
        status=Status.PASS,
        summary="All good.",
    )


@pytest.fixture
def fail_result():
    """A pre-built FAIL result."""
    return RuleResult(
        rule_id="test-rule",
        rule_name="Test Rule",
        status=Status.FAIL,
        summary="Something is broken.",
        findings=[Finding(detail="Bad thing happened", evidence="HTTP 500")],
        suggestion="Fix it.",
    )


@pytest.fixture
def warn_result():
    """A pre-built WARN result."""
    return RuleResult(
        rule_id="test-rule",
        rule_name="Test Rule",
        status=Status.WARN,
        summary="Minor issues.",
        findings=[Finding(detail="Minor thing", evidence="HTTP 400")],
        suggestion="Maybe fix it.",
    )
