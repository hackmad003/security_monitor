"""
Remote Event Reader Tests
Tests for remote Windows event log reading with security validations
"""

import pytest
from src.core.remote_event_reader import RemoteEventReader


class TestRemoteEventReaderSecurity:
    """Test remote event reader input validation and security"""
    
    def test_validates_server_input(self):
        """Test that RemoteEventReader validates server input"""
        # Should raise ValueError for dangerous characters
        with pytest.raises(ValueError):
            RemoteEventReader("server;whoami", "admin", "password")
        
        with pytest.raises(ValueError):
            RemoteEventReader("server|cat", "admin", "password")
        
        with pytest.raises(ValueError):
            RemoteEventReader("server&echo", "admin", "password")
    
    def test_validates_username_input(self):
        """Test that RemoteEventReader validates username input"""
        with pytest.raises(ValueError):
            RemoteEventReader("server", "admin;whoami", "password")
        
        with pytest.raises(ValueError):
            RemoteEventReader("server", "admin|cat", "password")
    
    def test_validates_password_input(self):
        """Test that RemoteEventReader validates password input"""
        with pytest.raises(ValueError):
            RemoteEventReader("server", "admin", "pass;whoami")
    
    def test_accepts_valid_inputs(self):
        """Test that valid inputs are accepted"""
        # Should not raise exception (though connection may fail)
        try:
            reader = RemoteEventReader("localhost", "Administrator", "ValidPass123!")
            assert reader is not None
        except Exception as e:
            # Connection errors are okay, we're testing validation
            if "dangerous character" in str(e):
                pytest.fail("Valid input was rejected")
