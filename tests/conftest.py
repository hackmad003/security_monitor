"""
Pytest configuration and shared fixtures
"""

import sys
from pathlib import Path
import pytest
import tempfile
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file for tests"""
    def _create_temp_file(filename, content=""):
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path
    return _create_temp_file


@pytest.fixture
def sample_credentials():
    """Sample credentials for testing"""
    return {
        'username': 'testuser',
        'password': 'TestPass123!',
        'server': 'testserver.local'
    }


@pytest.fixture
def dangerous_inputs():
    """Collection of dangerous input strings for injection testing"""
    return [
        ("test;rm -rf /", "semicolon"),
        ("test&whoami", "ampersand"),
        ("test|cat /etc/passwd", "pipe"),
        ("test$USER", "dollar sign"),
        ("test`whoami`", "backtick"),
        ("test<script>", "less than"),
        ("test>output.txt", "greater than"),
    ]
