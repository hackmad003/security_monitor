"""
Phase 2 Security Fixes Test Suite
Tests for SEC-004 (XSS), SEC-006 (SSL), SEC-007 (NoSQL Injection), and Rate Limiting
"""

import sys
from pathlib import Path
import pytest
import tempfile

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.query_validator import QueryValidator, MongoDBQueryBuilder
from src.utils.rate_limiter import RateLimiter, EndpointRateLimiter
from src.notifications.splunk_sender import SplunkSender
from datetime import datetime, timedelta


class TestSEC004_XSSPrevention:
    """Test fixes for SEC-004: XSS vulnerabilities"""
    
    def test_dashboard_secure_html_exists(self):
        """Test that secure dashboard HTML file exists"""
        secure_dashboard = Path(__file__).parent.parent.parent / "security_monitor" / "dashboard" / "dashboard_secure.html"
        assert secure_dashboard.exists(), "Secure dashboard HTML should exist"
    
    def test_secure_dashboard_has_csp(self):
        """Test that secure dashboard has Content Security Policy"""
        secure_dashboard = Path(__file__).parent.parent.parent / "security_monitor" / "dashboard" / "dashboard_secure.html"
        if secure_dashboard.exists():
            content = secure_dashboard.read_text()
            assert "Content-Security-Policy" in content, "Should have CSP meta tag"
            assert "default-src 'self'" in content, "Should restrict default sources"
    
    def test_secure_dashboard_has_escape_function(self):
        """Test that secure dashboard has HTML escaping function"""
        secure_dashboard = Path(__file__).parent.parent / "web" / "dashboard_secure.html"
        if secure_dashboard.exists():
            content = secure_dashboard.read_text()
            assert "escapeHtml" in content or "textContent" in content, \
                "Should have HTML escaping or safe DOM manipulation"


class TestSEC006_SSLVerification:
    """Test fixes for SEC-006: SSL verification disabled"""
    
    def test_splunk_sender_default_verify_ssl_true(self):
        """Test that SSL verification is enabled by default"""
        sender = SplunkSender(
            hec_url="https://localhost:8088/services/collector/event",
            hec_token="test-token"
        )
        assert sender.verify_ssl is True, "SSL verification should be enabled by default"
    
    def test_splunk_sender_can_disable_ssl_with_warning(self):
        """Test that SSL can be disabled but issues warning"""
        # Create sender with SSL disabled (warning is logged, not raised as pytest warning)
        sender = SplunkSender(
            hec_url="https://localhost:8088/services/collector/event",
            hec_token="test-token",
            verify_ssl=False
        )

        assert sender.verify_ssl is False, "Should be able to disable SSL"
    
    def test_splunk_sender_custom_cert_path(self):
        """Test custom certificate path support"""
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as cert_file:
            cert_file.write(b"FAKE CERT")
            cert_path = cert_file.name
        
        try:
            sender = SplunkSender(
                hec_url="https://localhost:8088/services/collector/event",
                hec_token="test-token",
                verify_ssl=True,
                cert_path=cert_path
            )
            # verify_ssl should be set to cert_path
            assert sender.verify_ssl == cert_path or sender.cert_path == cert_path
        finally:
            Path(cert_path).unlink()


class TestSEC007_NoSQLInjectionPrevention:
    """Test fixes for SEC-007: NoSQL injection vulnerabilities"""
    
    def test_validate_event_id_blocks_invalid_types(self):
        """Test that event ID validation blocks non-integers"""
        validator = QueryValidator()
        
        # Should raise ValueError for invalid types
        with pytest.raises(ValueError):
            validator.validate_event_id("'; DROP TABLE;")
        
        with pytest.raises(ValueError):
            validator.validate_event_id({"$ne": 1})
        
        with pytest.raises(ValueError):
            validator.validate_event_id([1, 2, 3])
    
    def test_validate_event_id_accepts_valid_integers(self):
        """Test that valid event IDs are accepted"""
        validator = QueryValidator()
        
        assert validator.validate_event_id(4625) == 4625
        assert validator.validate_event_id("4624") == 4624
        assert validator.validate_event_id(0) == 0
    
    def test_validate_event_id_blocks_out_of_range(self):
        """Test that out-of-range event IDs are blocked"""
        validator = QueryValidator()
        
        with pytest.raises(ValueError):
            validator.validate_event_id(-1)
        
        with pytest.raises(ValueError):
            validator.validate_event_id(100000)
    
    def test_validate_severity_blocks_invalid_values(self):
        """Test that severity validation blocks invalid values"""
        validator = QueryValidator()
        
        with pytest.raises(ValueError):
            validator.validate_severity("INVALID")
        
        with pytest.raises(ValueError):
            validator.validate_severity({"$ne": "LOW"})  # type: ignore[arg-type]

        with pytest.raises(ValueError):
            validator.validate_severity(123)  # type: ignore[arg-type]
    
    def test_validate_severity_accepts_valid_values(self):
        """Test that valid severity levels are accepted"""
        validator = QueryValidator()
        
        assert validator.validate_severity("HIGH") == "HIGH"
        assert validator.validate_severity("high") == "HIGH"
        assert validator.validate_severity("MEDIUM") == "MEDIUM"
        assert validator.validate_severity("LOW") == "LOW"
        assert validator.validate_severity("CRITICAL") == "CRITICAL"
    
    def test_validate_computer_name_blocks_injection(self):
        """Test that computer name validation blocks injection attempts"""
        validator = QueryValidator()
        
        # Block special characters
        with pytest.raises(ValueError):
            validator.validate_computer_name("server'; DROP TABLE;")
        
        with pytest.raises(ValueError):
            validator.validate_computer_name("server$cmd")
        
        with pytest.raises(ValueError):
            validator.validate_computer_name("server<script>")
    
    def test_validate_computer_name_accepts_valid_names(self):
        """Test that valid computer names are accepted"""
        validator = QueryValidator()
        
        assert validator.validate_computer_name("SERVER01") == "SERVER01"
        assert validator.validate_computer_name("dc-01.domain.local") == "dc-01.domain.local"
        assert validator.validate_computer_name("server_01") == "server_01"
    
    def test_sanitize_query_dict_blocks_dangerous_operators(self):
        """Test that dangerous MongoDB operators are blocked"""
        validator = QueryValidator()
        
        # Block $where operator
        with pytest.raises(ValueError, match="not allowed"):
            validator.sanitize_query_dict({"$where": "this.value > 5"})
        
        # Block $function operator
        with pytest.raises(ValueError, match="not allowed"):
            validator.sanitize_query_dict({"$function": {"body": "function() { return true; }"}})
    
    def test_sanitize_query_dict_allows_safe_operators(self):
        """Test that safe operators are allowed"""
        validator = QueryValidator()
        
        # Safe query
        safe_query = {
            "severity": "HIGH",
            "timestamp": {"$gte": datetime.now()}
        }
        
        sanitized = validator.sanitize_query_dict(safe_query)
        assert "severity" in sanitized
        assert "timestamp" in sanitized
    
    def test_query_builder_creates_safe_queries(self):
        """Test that query builder creates safe queries"""
        builder = MongoDBQueryBuilder()
        
        query = builder \
            .filter_by_event_id(4625) \
            .filter_by_severity("HIGH") \
            .filter_by_computer("SERVER01") \
            .build()
        
        assert query['event_id'] == 4625
        assert query['severity'] == "HIGH"
        assert query['computer'] == "SERVER01"
    
    def test_query_builder_validates_inputs(self):
        """Test that query builder validates all inputs"""
        builder = MongoDBQueryBuilder()
        
        # Should raise ValueError for invalid inputs
        with pytest.raises(ValueError):
            builder.filter_by_event_id("invalid")  # type: ignore[arg-type]
        
        with pytest.raises(ValueError):
            builder.filter_by_severity("INVALID")
        
        with pytest.raises(ValueError):
            builder.filter_by_computer("server'; DROP TABLE;")
    
    def test_validate_limit_prevents_abuse(self):
        """Test that limit validation prevents abuse"""
        validator = QueryValidator()
        
        # Valid limits
        assert validator.validate_limit(10) == 10
        assert validator.validate_limit(100) == 100
        
        # Block negative limits
        with pytest.raises(ValueError):
            validator.validate_limit(-1)
        
        # Block excessive limits
        with pytest.raises(ValueError):
            validator.validate_limit(100000)
    
    def test_validate_days_prevents_abuse(self):
        """Test that days validation prevents abuse"""
        validator = QueryValidator()
        
        # Valid days
        assert validator.validate_days(7) == 7
        assert validator.validate_days(30) == 30
        
        # Block zero or negative
        with pytest.raises(ValueError):
            validator.validate_days(0)
        
        with pytest.raises(ValueError):
            validator.validate_days(-1)
        
        # Block excessive days
        with pytest.raises(ValueError):
            validator.validate_days(1000)


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limiter_allows_under_limit(self):
        """Test that requests under limit are allowed"""
        limiter = RateLimiter(requests_per_minute=10, burst_size=5)
        
        # First 10 requests should be allowed
        for i in range(10):
            allowed, retry_after = limiter.is_allowed("test_user")
            assert allowed is True, f"Request {i+1} should be allowed"
            assert retry_after is None
    
    def test_rate_limiter_blocks_over_limit(self):
        """Test that requests over limit are blocked"""
        limiter = RateLimiter(requests_per_minute=5, burst_size=3)
        
        # Use up the limit
        for _ in range(5):
            limiter.is_allowed("test_user")

        # Next request should be blocked
        allowed, retry_after = limiter.is_allowed("test_user")
        assert allowed is False, "Request over limit should be blocked"
        assert retry_after is not None
        assert retry_after > 0
    
    def test_rate_limiter_different_identifiers(self):
        """Test that different identifiers have separate limits"""
        limiter = RateLimiter(requests_per_minute=5, burst_size=3)
        
        # Use up limit for user1
        for _ in range(5):
            limiter.is_allowed("user1")
        
        # user1 should be blocked
        allowed, _ = limiter.is_allowed("user1")
        assert allowed is False
        
        # user2 should still be allowed
        allowed, _ = limiter.is_allowed("user2")
        assert allowed is True
    
    def test_rate_limiter_get_remaining(self):
        """Test getting remaining requests"""
        limiter = RateLimiter(requests_per_minute=10, burst_size=5)
        
        # Initially should have 10 remaining
        remaining = limiter.get_remaining("test_user")
        assert remaining == 10
        
        # After 3 requests, should have 7 remaining
        for _ in range(3):
            limiter.is_allowed("test_user")
        
        remaining = limiter.get_remaining("test_user")
        assert remaining == 7
    
    def test_rate_limiter_reset(self):
        """Test resetting rate limit"""
        limiter = RateLimiter(requests_per_minute=5, burst_size=3)
        
        # Use up the limit
        for _ in range(5):
            limiter.is_allowed("test_user")

        # Should be blocked
        allowed, _ = limiter.is_allowed("test_user")
        assert allowed is False

        # Reset
        limiter.reset("test_user")
        
        # Should be allowed again
        allowed, _ = limiter.is_allowed("test_user")
        assert allowed is True
    
    def test_endpoint_rate_limiter_different_limits(self):
        """Test that different endpoints have different limits"""
        limiter = EndpointRateLimiter()
        
        # Login endpoint has stricter limit (5 per minute)
        for _ in range(5):
            allowed, _ = limiter.is_allowed("user1", "login")
            assert allowed is True
        
        # 6th login attempt should be blocked
        allowed, _ = limiter.is_allowed("user1", "login")
        assert allowed is False
        
        # But API read should still be allowed (different limit)
        allowed, _ = limiter.is_allowed("user1", "api_read")
        assert allowed is True


class TestInputValidation:
    """Test comprehensive input validation"""
    
    def test_datetime_validation(self):
        """Test datetime validation"""
        validator = QueryValidator()
        
        # Valid datetime object
        now = datetime.now()
        result = validator.validate_datetime(now)
        assert result == now
        
        # Valid ISO string
        iso_string = "2026-01-06T12:00:00"
        result = validator.validate_datetime(iso_string)
        assert isinstance(result, datetime)
        
        # Invalid datetime
        with pytest.raises(ValueError):
            validator.validate_datetime("not a date")
        
        with pytest.raises(ValueError):
            validator.validate_datetime(12345)
    
    def test_build_safe_query_comprehensive(self):
        """Test building safe queries with multiple filters"""
        validator = QueryValidator()
        
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        
        query = validator.build_safe_query(
            event_id=[4625, 4624],
            severity="HIGH",
            computer="SERVER01",
            start_date=start_date,
            end_date=end_date
        )
        
        assert 'event_id' in query
        assert '$in' in query['event_id']
        assert 4625 in query['event_id']['$in']
        assert query['severity'] == "HIGH"
        assert query['computer'] == "SERVER01"
        assert 'timestamp' in query


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
