"""
JWT Handler Tests
Tests for JWT token generation, validation, and authentication
"""

import pytest
from src.auth.jwt_handler import create_access_token, verify_password, hash_password, authenticate_user
from src.auth.user_store import UserStore


class TestJWTAuthentication:
    """Test JWT authentication functionality"""
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "SecurePassword123!"
        hashed = hash_password(password)
        
        # Verify hash is different from password
        assert hashed != password
        assert hashed.startswith('$2b$')
        
        # Verify correct password
        assert verify_password(password, hashed) is True
        
        # Verify incorrect password
        assert verify_password("WrongPassword", hashed) is False
    
    def test_jwt_token_creation(self):
        """Test JWT token creation"""
        token = create_access_token(data={"sub": "testuser"})
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_authentication_with_valid_credentials(self, temp_dir):
        """Test user authentication with valid credentials"""
        storage_path = temp_dir / "users.json"
        store = UserStore(storage_path=storage_path)
        
        # Create test user
        store.create_user("testuser", "TestPass123!")
        
        # Verify password
        auth_result = authenticate_user("testuser", "TestPass123!", store)
        assert auth_result is not None
        
        # Wrong password should fail
        auth_result = authenticate_user("testuser", "WrongPassword", store)
        assert auth_result is None
    
    def test_authentication_with_nonexistent_user(self, temp_dir):
        """Test authentication fails for non-existent user"""
        storage_path = temp_dir / "users.json"
        store = UserStore(storage_path=storage_path)
        
        auth_result = authenticate_user("nonexistent", "password", store)
        assert auth_result is None
