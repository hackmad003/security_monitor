# Security Monitor Test Suite

This directory contains the comprehensive test suite for the Security Monitor project.

## Test Structure

The tests are organized to mirror the source code structure:

```
tests/
├── conftest.py                    # Shared fixtures and configuration
├── test_auth/                     # Authentication tests
│   ├── test_jwt_handler.py        # JWT token and authentication
│   └── test_user_store.py         # User management
├── test_core/                     # Core functionality tests
│   └── test_remote_event_reader.py # Remote event reading
├── test_storage/                  # Storage and database tests
│   └── test_query_validator.py    # NoSQL injection prevention
├── test_utils/                    # Utility tests
│   ├── test_config.py             # Configuration loading
│   ├── test_rate_limiter.py       # API rate limiting
│   └── test_secure_credentials.py # Credential validation and storage
├── test_notifications/            # Notification tests
│   └── test_splunk_sender.py      # Splunk integration
├── test_integration/              # Integration tests
│   └── test_input_validation.py   # Cross-module validation
└── legacy/                        # Original monolithic test files
    ├── test_security_fixes.py     # SEC-001, SEC-002, SEC-003
    └── test_phase2_fixes.py       # SEC-004, SEC-006, SEC-007

```

## Running Tests

### Run All Tests
```powershell
pytest
```

### Run Specific Test Module
```powershell
# Test authentication
pytest tests/test_auth/

# Test utilities
pytest tests/test_utils/

# Test storage
pytest tests/test_storage/
```

### Run Specific Test File
```powershell
pytest tests/test_auth/test_jwt_handler.py
```

### Run Specific Test Class or Function
```powershell
# Run specific class
pytest tests/test_auth/test_jwt_handler.py::TestJWTAuthentication

# Run specific test
pytest tests/test_auth/test_jwt_handler.py::TestJWTAuthentication::test_password_hashing
```

### Run with Coverage
```powershell
pytest --cov=security_monitor --cov-report=html
```

### Run with Verbose Output
```powershell
pytest -v
```

### Run Tests Matching Pattern
```powershell
# Run all tests with "validation" in the name
pytest -k validation

# Run all tests with "security" in the name
pytest -k security
```

## Test Categories

### Security Tests
Tests that verify security fixes and protections:
- **SEC-001**: Command injection prevention
- **SEC-002**: Secure credential storage
- **SEC-003**: API authentication
- **SEC-004**: XSS prevention
- **SEC-006**: SSL verification
- **SEC-007**: NoSQL injection prevention

### Unit Tests
Tests for individual components in isolation:
- Authentication (`test_auth/`)
- Utilities (`test_utils/`)
- Storage (`test_storage/`)
- Notifications (`test_notifications/`)

### Integration Tests
Tests that verify multiple components working together:
- Input validation across modules
- End-to-end workflows

## Writing New Tests

### Test File Naming
- Test files should start with `test_`
- Test files should match the module they test
- Example: `security_monitor/utils/config.py` → `tests/test_utils/test_config.py`

### Test Class Naming
- Test classes should start with `Test`
- Use descriptive names that indicate what's being tested
- Example: `class TestJWTAuthentication:`

### Test Function Naming
- Test functions should start with `test_`
- Use descriptive names that explain the test case
- Example: `def test_password_hashing():`

### Using Fixtures
Shared fixtures are defined in `conftest.py`:

```python
def test_example(temp_dir, sample_credentials):
    # temp_dir: temporary directory for test files
    # sample_credentials: sample username/password dict
    pass
```

### Example Test
```python
import pytest
from security_monitor.auth.jwt_handler import hash_password, verify_password

class TestPasswordHashing:
    """Test password hashing functionality"""
    
    def test_password_is_hashed(self):
        """Test that passwords are properly hashed"""
        password = "SecurePass123!"
        hashed = hash_password(password)
        
        assert hashed != password
        assert hashed.startswith('$2b$')
    
    def test_password_verification(self):
        """Test password verification works correctly"""
        password = "SecurePass123!"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
        assert verify_password("WrongPass", hashed) is False
```

## Test Requirements

Tests require the following packages (install with `pip install -r requirements.txt`):
- `pytest>=7.0.0`
- `pytest-asyncio>=0.21.0`
- `pytest-cov` (optional, for coverage reports)

## Continuous Integration

Tests should pass before merging any pull requests. The test suite is designed to:
- Run quickly (< 30 seconds for full suite)
- Be reliable (no flaky tests)
- Provide clear error messages
- Test security-critical functionality thoroughly

## Legacy Tests

The original monolithic test files are preserved in `tests/legacy/`:
- `test_security_fixes.py` - Original security fix tests
- `test_phase2_fixes.py` - Phase 2 security tests

These are kept for reference but the new organized structure should be used for new tests.

## Test Coverage Goals

- **Critical security code**: 100% coverage
- **Core functionality**: 90%+ coverage
- **Utilities**: 80%+ coverage
- **Overall project**: 75%+ coverage

## Troubleshooting

### Tests failing with import errors
Make sure you're running from the project root directory:
```powershell
cd /path/to/security-monitor
pytest
```

### Temporary files not cleaned up
The `temp_dir` fixture automatically cleans up after each test. If manual cleanup is needed:
```python
import tempfile
import shutil

def test_example():
    tmpdir = tempfile.mkdtemp()
    try:
        # Your test code
        pass
    finally:
        shutil.rmtree(tmpdir)
```

## Contributing

When adding new features:
1. Write tests first (TDD approach recommended)
2. Ensure tests cover edge cases and error conditions
3. Run full test suite before committing
4. Update this README if adding new test categories
