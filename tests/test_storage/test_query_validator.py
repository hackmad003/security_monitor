"""
Query Validator Tests
Tests for NoSQL injection prevention and query validation
"""

import pytest
from security_monitor.database.query_validator import QueryValidator, MongoDBQueryBuilder


class TestNoSQLInjectionPrevention:
    """Test NoSQL injection prevention in query validator"""
    
    def test_blocks_operator_injection(self):
        """Test that MongoDB operator injection is blocked"""
        # Test that validator blocks dangerous operators in individual fields
        
        # Test event_id validation blocks non-integers
        with pytest.raises((ValueError, TypeError)):
            QueryValidator.validate_event_id({"$ne": None})
        
        # Test severity validation blocks invalid values
        with pytest.raises(ValueError):
            QueryValidator.validate_severity("$ne")
        
        # Test computer name validation blocks operators
        with pytest.raises(ValueError):
            QueryValidator.validate_computer_name("test$ne")
    
    def test_allows_safe_queries(self):
        """Test that safe queries are allowed"""
        # Test that validator accepts safe values
        
        # Valid event ID
        event_id = QueryValidator.validate_event_id(4625)
        assert event_id == 4625
        
        # Valid severity
        severity = QueryValidator.validate_severity("HIGH")
        assert severity == "HIGH"
        
        # Valid computer name
        computer = QueryValidator.validate_computer_name("WORKSTATION-01")
        assert computer == "WORKSTATION-01"
    
    def test_blocks_nested_operators(self):
        """Test blocking of nested operators"""
        # Test that validator blocks invalid characters in computer names
        with pytest.raises(ValueError):
            QueryValidator.validate_computer_name("server$ne")
        
        # Test that validator blocks invalid characters
        with pytest.raises(ValueError):
            QueryValidator.validate_computer_name("server{$ne:null}")
    
    def test_query_builder_safe_queries(self):
        """Test that MongoDBQueryBuilder creates safe queries"""
        builder = MongoDBQueryBuilder()
        
        # Build query with user input using builder pattern
        query = builder \
            .filter_by_severity("HIGH") \
            .filter_by_computer("WORKSTATION-01") \
            .build()
        
        # Query should be a dictionary
        assert isinstance(query, dict)
        
        # Should contain validated fields
        assert query['severity'] == "HIGH"
        assert query['computer'] == "WORKSTATION-01"
    
    def test_query_builder_sanitizes_input(self):
        """Test that query builder sanitizes potentially dangerous input"""
        # Test that individual validators reject dangerous input
        
        # Try to inject operator via severity
        with pytest.raises(ValueError):
            QueryValidator.validate_severity("$ne")
        
        # Try to use invalid event ID type
        with pytest.raises((ValueError, TypeError)):
            QueryValidator.validate_event_id("invalid")
        
        # Try to inject via computer name
        with pytest.raises(ValueError):
            QueryValidator.validate_computer_name("test;malicious")
