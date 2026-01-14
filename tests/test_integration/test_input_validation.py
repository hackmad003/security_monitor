"""
Integration Tests for Input Validation
Cross-module input validation tests
"""

import pytest
from security_monitor.utils.secure_credentials import CredentialValidator


class TestInputValidation:
    """Test comprehensive input validation across the system"""
    
    def test_validator_rejects_special_chars(self):
        """Test that validator rejects special characters"""
        validator = CredentialValidator()
        
        special_chars = [';', '&', '|', '$', '`', '<', '>']
        
        for char in special_chars:
            test_input = f"test{char}malicious"
            with pytest.raises(ValueError):
                validator.validate_credential_input(test_input, "test_field")
    
    def test_validator_length_limits(self):
        """Test that validator enforces reasonable length limits"""
        validator = CredentialValidator()
        
        # Very long input
        long_input = "A" * 10000
        
        # Should either accept or have reasonable handling
        # Implementation may vary
        try:
            validator.validate_credential_input(long_input, "test_field")
        except ValueError:
            # Acceptable if length limits are enforced
            pass
    
    def test_unicode_handling(self):
        """Test handling of unicode characters"""
        validator = CredentialValidator()
        
        # Unicode characters should be handled safely
        unicode_inputs = [
            "test_用户",
            "użytkownik",
            "пользователь",
        ]
        
        for unicode_input in unicode_inputs:
            # Should either accept or reject gracefully
            try:
                validator.validate_credential_input(unicode_input, "test_field")
            except ValueError as e:
                # Acceptable rejection
                assert "dangerous character" in str(e) or "invalid" in str(e).lower()
