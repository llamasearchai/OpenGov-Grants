"""Pytest configuration and fixtures for OpenGov-Grants tests."""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure the src directory is on sys.path for imports like `import opengovgrants`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from opengovgrants.web.app import app


@pytest.fixture
def client():
    """FastAPI test client fixture."""
    with TestClient(app) as test_client:
        yield test_client

@pytest.fixture
def cli_runner():
    """CLI test runner fixture."""
    from click.testing import CliRunner
    return CliRunner()


