"""
Security Fixes Test Suite
Tests for SEC-001, SEC-002, and SEC-003 fixes
"""

import sys
from pathlib import Path
import pytest
import tempfile
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_monitor.utils.secure_credentials import SecureCredentialStore, CredentialValidator
from security_monitor.auth.jwt_handler import create_access_token, verify_password, hash_password
from security_monitor.auth.user_store import UserStore


class TestSEC001_CommandInjectionFix:
    """Test fixes for SEC-001: Command Injection vulnerability"""
    
    def test_credential_validator_blocks_dangerous_characters(self):
        """Test that dangerous characters are blocked"""
        validator = CredentialValidator()
        
        # Test dangerous characters
        dangerous_inputs = [
            ("test;rm -rf /", "semicolon"),
            ("test&whoami", "ampersand"),
            ("test|cat /etc/passwd", "pipe"),
            ("test$USER", "dollar sign"),
            ("test`whoami`", "backtick"),
            ("test<script>", "less than"),
            ("test>output.txt", "greater than"),
        ]
        
        for dangerous_input, description in dangerous_inputs:
            with pytest.raises(ValueError, match="dangerous character"):
                validator.validate_credential_input(dangerous_input, f"test_{description}")
    
    def test_credential_validator_allows_safe_characters(self):
        """Test that safe characters are allowed"""
        validator = CredentialValidator()
        
        safe_inputs = [
            "Administrator",
            "user123",
            "MyPassword123!",
            "Test_User-01",
        ]
        
        for safe_input in safe_inputs:
            # Should not raise exception
            validator.validate_credential_input(safe_input, "test_field")
    
    def test_hostname_validation(self):
        """Test hostname validation"""
        validator = CredentialValidator()
        
        # Valid hostnames
        valid_hostnames = [
            "localhost",
            "server01",
            "dc-01.domain.local",
            "192.168.1.100",
        ]
        
        for hostname in valid_hostnames:
            validator.validate_hostname(hostname)
        
        # Invalid hostnames
        invalid_hostnames = [
            "test;whoami",
            "test|cat",
            "test&echo",
            "test<script>",
        ]
        
        for hostname in invalid_hostnames:
            with pytest.raises(ValueError):
                validator.validate_hostname(hostname)
    
    def test_powershell_sanitization(self):
        """Test PowerShell string sanitization"""
        validator = CredentialValidator()
        
        # Test single quote escaping
        test_input = "O'Brien's Password"
        sanitized = validator.sanitize_for_powershell(test_input)
        assert sanitized == "O''Brien''s Password"
    
    def test_remote_event_reader_validates_inputs(self):
        """Test that RemoteEventReader validates all inputs"""
        from security_monitor.core.remote_event_reader import RemoteEventReader
        
        # Should raise ValueError for dangerous characters
        with pytest.raises(ValueError):
            RemoteEventReader("server;whoami", "admin", "password")
        
        with pytest.raises(ValueError):
            RemoteEventReader("server", "admin;whoami", "password")
        
        with pytest.raises(ValueError):
            RemoteEventReader("server", "admin", "pass;whoami")
        
        # Should accept valid inputs
        reader = RemoteEventReader("localhost", "Administrator", "ValidPassword123!")
        assert reader.server == "localhost"
        assert reader.username == "Administrator"


class TestSEC002_SecureCredentialStorage:
    """Test fixes for SEC-002: Plaintext credential storage"""
    
    def test_credential_store_creates_encrypted_storage(self):
        """Test that credential store creates encrypted files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SecureCredentialStore(storage_dir=Path(tmpdir))
            
            # Check that key file was created
            assert store.key_file.exists()
            
            # Store credentials
            store.store_credentials("test_target", "admin", "password123")
            
            # Check that encrypted credentials file exists
            assert store.creds_file.exists()
            
            # Verify file is not plaintext (should be encrypted)
            encrypted_content = store.creds_file.read_bytes()
            assert b"admin" not in encrypted_content
            assert b"password123" not in encrypted_content
    
    def test_credential_store_encryption_decryption(self):
        """Test that credentials can be encrypted and decrypted"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SecureCredentialStore(storage_dir=Path(tmpdir))
            
            # Store credentials
            store.store_credentials("target1", "user1", "pass1")
            store.store_credentials("target2", "user2", "pass2")
            
            # Retrieve credentials
            creds1 = store.get_credentials("target1")
            assert creds1 is not None
            assert creds1['username'] == "user1"
            assert creds1['password'] == "pass1"
            
            creds2 = store.get_credentials("target2")
            assert creds2 is not None
            assert creds2['username'] == "user2"
            assert creds2['password'] == "pass2"
    
    def test_credential_store_deletion(self):
        """Test credential deletion"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SecureCredentialStore(storage_dir=Path(tmpdir))
            
            store.store_credentials("target1", "user1", "pass1")
            assert store.get_credentials("target1") is not None
            
            # Delete credentials
            result = store.delete_credentials("target1")
            assert result is True
            
            # Verify deleted
            assert store.get_credentials("target1") is None
    
    def test_config_uses_secure_storage(self):
        """Test that Config class uses secure credential storage"""
        from security_monitor.utils.config import Config
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            
            # Should have credential store
            assert hasattr(config, 'credential_store')
            assert isinstance(config.credential_store, SecureCredentialStore)


class TestSEC003_APIAuthentication:
    """Test fixes for SEC-003: API Authentication"""
    
    def test_jwt_token_creation(self):
        """Test JWT token creation"""
        token = create_access_token(data={"sub": "testuser"})
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_password_hashing(self):
        """Test password hashing"""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Verify hash is different from password
        assert hashed != password
        
        # Verify hash verification works
        assert verify_password(password, hashed) is True
        assert verify_password("WrongPassword", hashed) is False
    
    def test_user_store_creates_default_admin(self):
        """Test that user store creates default admin user"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "users.json"
            store = UserStore(storage_path=storage_path)
            
            # Should have created default admin
            admin = store.get_user("admin")
            assert admin is not None
            assert "admin" in admin.get('roles', [])
    
    def test_user_store_create_and_authenticate(self):
        """Test user creation and authentication"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "users.json"
            store = UserStore(storage_path=storage_path)
            
            # Create user
            result = store.create_user("testuser", "TestPass123!", roles=['viewer'])
            assert result is True
            
            # Get user
            user = store.get_user("testuser")
            assert user is not None
            assert user['username'] == "testuser"
            assert 'viewer' in user['roles']
            
            # Verify password
            from security_monitor.auth.jwt_handler import authenticate_user
            auth_result = authenticate_user("testuser", "TestPass123!", store)
            assert auth_result is not None
            
            # Wrong password should fail
            auth_result = authenticate_user("testuser", "WrongPassword", store)
            assert auth_result is None
    
    def test_user_store_prevents_duplicate_users(self):
        """Test that duplicate usernames are prevented"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "users.json"
            store = UserStore(storage_path=storage_path)
            
            # Create first user
            result = store.create_user("testuser", "password1")
            assert result is True
            
            # Try to create duplicate
            result = store.create_user("testuser", "password2")
            assert result is False
    
    def test_user_store_password_change(self):
        """Test password change functionality"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "users.json"
            store = UserStore(storage_path=storage_path)
            
            store.create_user("testuser", "OldPassword123!")
            
            # Change password
            result = store.change_password("testuser", "NewPassword456!")
            assert result is True
            
            # Verify old password doesn't work
            from security_monitor.auth.jwt_handler import authenticate_user
            auth_result = authenticate_user("testuser", "OldPassword123!", store)
            assert auth_result is None
            
            # Verify new password works
            auth_result = authenticate_user("testuser", "NewPassword456!", store)
            assert auth_result is not None
    
    def test_user_store_prevents_deleting_last_admin(self):
        """Test that last admin cannot be deleted"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "users.json"
            store = UserStore(storage_path=storage_path)
            
            # Only admin user exists
            result = store.delete_user("admin")
            assert result is False  # Should prevent deletion


class TestInputValidation:
    """Test input validation on API endpoints"""
    
    def test_pydantic_model_validation(self):
        """Test that Pydantic models validate inputs"""
        from security_monitor.dashboard.web_dashboard_secure import TargetCreate, MonitoringParams
        
        # Valid target
        target = TargetCreate(
            name="server01",
            hostname="192.168.1.100",
            username="admin",
            password="ValidPass123!"
        )
        assert target.name == "server01"
        
        # Invalid target name (special characters)
        with pytest.raises(Exception):  # Pydantic validation error
            TargetCreate(
                name="server;whoami",
                hostname="192.168.1.100",
                username="admin",
                password="ValidPass123!"
            )
        
        # Invalid password (too short)
        with pytest.raises(Exception):
            TargetCreate(
                name="server01",
                hostname="192.168.1.100",
                username="admin",
                password="short"
            )
        
        # Valid monitoring params
        params = MonitoringParams(interval=30, events_per_check=100)
        assert params.interval == 30
        
        # Invalid interval (too low)
        with pytest.raises(Exception):
            MonitoringParams(interval=5, events_per_check=100)
        
        # Invalid interval (too high)
        with pytest.raises(Exception):
            MonitoringParams(interval=5000, events_per_check=100)


def test_gitignore_protects_sensitive_files():
    """Test that .gitignore includes sensitive files"""
    gitignore_path = Path(__file__).parent.parent / ".gitignore"
    
    if gitignore_path.exists():
        gitignore_content = gitignore_path.read_text()
        
        # Check for sensitive patterns
        assert ".env" in gitignore_content
        assert ".security_monitor/" in gitignore_content or "security_monitor" in gitignore_content
        assert "*.enc" in gitignore_content or ".enc" in gitignore_content
        assert "key.bin" in gitignore_content or "*.key" in gitignore_content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
