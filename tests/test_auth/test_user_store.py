"""
User Store Tests
Tests for user management and storage
"""

import pytest
from pathlib import Path
from src.auth.user_store import UserStore


class TestUserStore:
    """Test user store functionality"""
    
    def test_create_user(self, temp_dir):
        """Test user creation"""
        storage_path = temp_dir / "users.json"
        store = UserStore(storage_path=storage_path)
        
        result = store.create_user("testuser", "TestPassword123!")
        assert result is True
        
        # Verify user exists
        user = store.get_user("testuser")
        assert user is not None
        assert user['username'] == "testuser"
        assert 'viewer' in user['roles']
    
    def test_user_store_prevents_duplicate_users(self, temp_dir):
        """Test that duplicate usernames are prevented"""
        storage_path = temp_dir / "users.json"
        store = UserStore(storage_path=storage_path)
        
        # Create first user
        result = store.create_user("testuser", "password1")
        assert result is True
        
        # Try to create duplicate
        result = store.create_user("testuser", "password2")
        assert result is False
    
    def test_user_store_password_change(self, temp_dir):
        """Test password change functionality"""
        from src.auth.jwt_handler import authenticate_user
        
        storage_path = temp_dir / "users.json"
        store = UserStore(storage_path=storage_path)
        
        store.create_user("testuser", "OldPassword123!")
        
        # Change password
        result = store.change_password("testuser", "NewPassword456!")
        assert result is True
        
        # Verify old password doesn't work
        auth_result = authenticate_user("testuser", "OldPassword123!", store)
        assert auth_result is None
        
        # Verify new password works
        auth_result = authenticate_user("testuser", "NewPassword456!", store)
        assert auth_result is not None
    
    def test_user_roles(self, temp_dir):
        """Test user role management"""
        storage_path = temp_dir / "users.json"
        store = UserStore(storage_path=storage_path)
        
        store.create_user("testuser", "password")
        user = store.get_user("testuser")
        
        # Default role should be viewer
        assert 'viewer' in user['roles']
        
        # Update user with admin role
        store.update_user("testuser", roles=["admin", "viewer"])
        user = store.get_user("testuser")
        assert 'admin' in user['roles']
        assert 'viewer' in user['roles']
