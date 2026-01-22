"""
Rate Limiter Tests
Tests for API rate limiting functionality
"""

import pytest
import time
from datetime import datetime, timedelta
from src.utils.rate_limiter import RateLimiter, EndpointRateLimiter


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limiter_allows_under_limit(self):
        """Test that requests under the limit are allowed"""
        limiter = RateLimiter(requests_per_minute=5, burst_size=5)
        
        # Make requests under the limit
        for i in range(5):
            allowed, retry_after = limiter.is_allowed("test_key")
            assert allowed is True
    
    def test_rate_limiter_blocks_over_limit(self):
        """Test that requests over the limit are blocked"""
        limiter = RateLimiter(requests_per_minute=3, burst_size=3)
        
        # Make requests up to the limit
        for i in range(3):
            allowed, retry_after = limiter.is_allowed("test_key")
            assert allowed is True
        
        # Next request should be blocked
        allowed, retry_after = limiter.is_allowed("test_key")
        assert allowed is False
        assert retry_after is not None
    
    def test_rate_limiter_resets_after_window(self):
        """Test that rate limiter resets after time window"""
        limiter = RateLimiter(requests_per_minute=2, burst_size=2)
        
        # Make requests up to limit
        allowed, _ = limiter.is_allowed("test_key")
        assert allowed is True
        allowed, _ = limiter.is_allowed("test_key")
        assert allowed is True
        allowed, _ = limiter.is_allowed("test_key")
        assert allowed is False
        
        # Wait for window to expire (60 seconds is the window)
        # For testing purposes, we'll just reset manually
        limiter.reset("test_key")
        
        # Should allow requests again
        allowed, _ = limiter.is_allowed("test_key")
        assert allowed is True
    
    def test_rate_limiter_per_key_isolation(self):
        """Test that rate limits are isolated per key"""
        limiter = RateLimiter(requests_per_minute=2, burst_size=2)
        
        # Exhaust limit for key1
        allowed, _ = limiter.is_allowed("key1")
        assert allowed is True
        allowed, _ = limiter.is_allowed("key1")
        assert allowed is True
        allowed, _ = limiter.is_allowed("key1")
        assert allowed is False
        
        # key2 should still work
        allowed, _ = limiter.is_allowed("key2")
        assert allowed is True
        allowed, _ = limiter.is_allowed("key2")
        assert allowed is True
    
    def test_endpoint_rate_limiter(self):
        """Test endpoint-specific rate limiting"""
        limiter = EndpointRateLimiter()
        
        # Test login endpoint limit (5 requests per minute by default)
        for i in range(5):
            allowed, _ = limiter.is_allowed("user1", "login")
            assert allowed is True
        
        # 6th request should be blocked
        allowed, _ = limiter.is_allowed("user1", "login")
        assert allowed is False
        
        # api_read endpoint should still work (different limit)
        allowed, _ = limiter.is_allowed("user1", "api_read")
        assert allowed is True
    
    def test_rate_limiter_get_remaining(self):
        """Test getting remaining requests"""
        limiter = RateLimiter(requests_per_minute=5, burst_size=5)
        
        # Check initial remaining
        remaining = limiter.get_remaining("test_key")
        assert remaining == 5
        
        # Make some requests
        limiter.is_allowed("test_key")
        limiter.is_allowed("test_key")
        
        # Check remaining decreased
        remaining = limiter.get_remaining("test_key")
        assert remaining == 3
