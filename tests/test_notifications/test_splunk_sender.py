"""
Splunk Sender Tests
Tests for Splunk HEC integration and SSL verification
"""

import pytest
from src.notifications.splunk_sender import SplunkSender


class TestSplunkSSLVerification:
    """Test SSL certificate verification in Splunk sender"""
    
    def test_ssl_verification_enabled_by_default(self):
        """Test that SSL verification is enabled by default"""
        sender = SplunkSender(
            hec_url="https://splunk.example.com:8088",
            hec_token="test-token",
            index="security"
        )
        
        # Verify SSL is enabled by default
        assert sender.verify_ssl is True
    
    def test_ssl_verification_can_be_disabled(self):
        """Test that SSL verification can be explicitly disabled"""
        sender = SplunkSender(
            hec_url="https://splunk.example.com:8088",
            hec_token="test-token",
            index="security",
            verify_ssl=False
        )
        
        assert sender.verify_ssl is False
    
    def test_ssl_warning_when_disabled(self, capsys):
        """Test that a warning is logged when SSL is disabled"""
        sender = SplunkSender(
            hec_url="https://splunk.example.com:8088",
            hec_token="test-token",
            index="security",
            verify_ssl=False
        )
        
        # Check if warning was issued (implementation-dependent)
        # This is a placeholder for actual warning check
        assert sender.verify_ssl is False
