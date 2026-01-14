"""
MongoDB Query Validator
Prevents NoSQL injection attacks by validating query parameters
"""

import re
from typing import Any, Dict, List, Union, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class QueryValidator:
    """Validates MongoDB query parameters to prevent NoSQL injection"""
    
    # Allowed MongoDB operators
    ALLOWED_OPERATORS = {
        '$eq', '$ne', '$gt', '$gte', '$lt', '$lte',
        '$in', '$nin', '$exists', '$type',
        '$and', '$or', '$not', '$nor',
        '$regex', '$text', '$where'  # Use with extreme caution
    }
    
    # Dangerous operators that should be blocked or sanitized
    DANGEROUS_OPERATORS = {
        '$where',  # Allows arbitrary JavaScript execution
        '$function',  # Allows arbitrary function execution
        '$accumulator',  # Can execute arbitrary code
        '$expr'  # Can be used for injection in some cases
    }
    
    @staticmethod
    def validate_event_id(event_id: Any) -> int:
        """
        Validate event ID parameter
        
        Args:
            event_id: Event ID to validate
            
        Returns:
            Validated integer event ID
            
        Raises:
            ValueError: If event_id is not a valid integer
        """
        try:
            event_id_int = int(event_id)
            if event_id_int < 0 or event_id_int > 99999:
                raise ValueError("Event ID must be between 0 and 99999")
            return event_id_int
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid event ID: must be an integer") from e
    
    @staticmethod
    def validate_severity(severity: str) -> str:
        """
        Validate severity parameter
        
        Args:
            severity: Severity level to validate
            
        Returns:
            Validated severity string
            
        Raises:
            ValueError: If severity is not valid
        """
        valid_severities = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
        
        if not isinstance(severity, str):
            raise ValueError("Severity must be a string")
        
        severity_upper = severity.upper()
        if severity_upper not in valid_severities:
            raise ValueError(f"Invalid severity. Must be one of: {', '.join(valid_severities)}")
        
        return severity_upper
    
    @staticmethod
    def validate_computer_name(computer: str) -> str:
        """
        Validate computer name parameter
        
        Args:
            computer: Computer name to validate
            
        Returns:
            Validated computer name
            
        Raises:
            ValueError: If computer name is invalid
        """
        if not isinstance(computer, str):
            raise ValueError("Computer name must be a string")
        
        if len(computer) == 0 or len(computer) > 255:
            raise ValueError("Computer name must be between 1 and 255 characters")
        
        # Allow alphanumeric, dots, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9._-]+$', computer):
            raise ValueError("Computer name contains invalid characters")
        
        return computer
    
    @staticmethod
    def validate_datetime(dt: Any) -> datetime:
        """
        Validate datetime parameter
        
        Args:
            dt: Datetime to validate
            
        Returns:
            Validated datetime object
            
        Raises:
            ValueError: If datetime is invalid
        """
        if isinstance(dt, datetime):
            return dt
        
        if isinstance(dt, str):
            try:
                return datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except ValueError as e:
                raise ValueError(f"Invalid datetime format: {dt}") from e
        
        raise ValueError("Datetime must be a datetime object or ISO format string")
    
    @staticmethod
    def validate_limit(limit: Any, max_limit: int = 10000) -> int:
        """
        Validate query limit parameter
        
        Args:
            limit: Limit value to validate
            max_limit: Maximum allowed limit
            
        Returns:
            Validated integer limit
            
        Raises:
            ValueError: If limit is invalid
        """
        try:
            limit_int = int(limit)
            if limit_int < 0:
                raise ValueError("Limit must be non-negative")
            if limit_int > max_limit:
                raise ValueError(f"Limit exceeds maximum allowed value of {max_limit}")
            return limit_int
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid limit: must be an integer") from e
    
    @staticmethod
    def validate_days(days: Any, max_days: int = 365) -> int:
        """
        Validate days parameter
        
        Args:
            days: Number of days to validate
            max_days: Maximum allowed days
            
        Returns:
            Validated integer days
            
        Raises:
            ValueError: If days is invalid
        """
        try:
            days_int = int(days)
            if days_int < 1:
                raise ValueError("Days must be at least 1")
            if days_int > max_days:
                raise ValueError(f"Days exceeds maximum allowed value of {max_days}")
            return days_int
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid days: must be an integer") from e
    
    @staticmethod
    def sanitize_query_dict(query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a query dictionary to prevent NoSQL injection
        
        This removes dangerous operators and validates structure
        
        Args:
            query: Query dictionary to sanitize
            
        Returns:
            Sanitized query dictionary
            
        Raises:
            ValueError: If query contains dangerous operators
        """
        if not isinstance(query, dict):
            raise ValueError("Query must be a dictionary")
        
        sanitized = {}
        
        for key, value in query.items():
            # Check for dangerous operators
            if key in QueryValidator.DANGEROUS_OPERATORS:
                logger.error(f"Blocked dangerous operator: {key}")
                raise ValueError(f"Operator '{key}' is not allowed for security reasons")
            
            # Validate operator keys
            if key.startswith('$') and key not in QueryValidator.ALLOWED_OPERATORS:
                logger.warning(f"Unknown operator: {key}")
                raise ValueError(f"Unknown or disallowed operator: {key}")
            
            # Recursively sanitize nested dictionaries
            if isinstance(value, dict):
                sanitized[key] = QueryValidator.sanitize_query_dict(value)
            # Recursively sanitize lists
            elif isinstance(value, list):
                sanitized[key] = [
                    QueryValidator.sanitize_query_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def build_safe_query(
        event_id: Optional[Union[int, List[int]]] = None,
        severity: Optional[str] = None,
        computer: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Build a safe MongoDB query with validated parameters
        
        Args:
            event_id: Event ID or list of event IDs
            severity: Severity level
            computer: Computer name
            start_date: Start datetime
            end_date: End datetime
            
        Returns:
            Safe MongoDB query dictionary
        """
        query = {}
        
        # Validate and add event_id
        if event_id is not None:
            if isinstance(event_id, list):
                validated_ids = [QueryValidator.validate_event_id(eid) for eid in event_id]
                query['event_id'] = {'$in': validated_ids}
            else:
                query['event_id'] = QueryValidator.validate_event_id(event_id)
        
        # Validate and add severity
        if severity is not None:
            query['severity'] = QueryValidator.validate_severity(severity)
        
        # Validate and add computer
        if computer is not None:
            query['computer'] = QueryValidator.validate_computer_name(computer)
        
        # Validate and add date range
        if start_date is not None or end_date is not None:
            date_query = {}
            if start_date is not None:
                date_query['$gte'] = QueryValidator.validate_datetime(start_date)
            if end_date is not None:
                date_query['$lte'] = QueryValidator.validate_datetime(end_date)
            query['timestamp'] = date_query
        
        return query


class MongoDBQueryBuilder:
    """Helper class to build safe MongoDB queries"""
    
    def __init__(self):
        self.validator = QueryValidator()
        self.query = {}
        self.sort = None
        self.limit_value = None
    
    def filter_by_event_id(self, event_id: Union[int, List[int]]) -> 'MongoDBQueryBuilder':
        """Add event ID filter"""
        if isinstance(event_id, list):
            validated_ids = [self.validator.validate_event_id(eid) for eid in event_id]
            self.query['event_id'] = {'$in': validated_ids}
        else:
            self.query['event_id'] = self.validator.validate_event_id(event_id)
        return self
    
    def filter_by_severity(self, severity: str) -> 'MongoDBQueryBuilder':
        """Add severity filter"""
        self.query['severity'] = self.validator.validate_severity(severity)
        return self
    
    def filter_by_computer(self, computer: str) -> 'MongoDBQueryBuilder':
        """Add computer name filter"""
        self.query['computer'] = self.validator.validate_computer_name(computer)
        return self
    
    def filter_by_date_range(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> 'MongoDBQueryBuilder':
        """Add date range filter"""
        date_query = {}
        if start_date is not None:
            date_query['$gte'] = self.validator.validate_datetime(start_date)
        if end_date is not None:
            date_query['$lte'] = self.validator.validate_datetime(end_date)
        if date_query:
            self.query['timestamp'] = date_query
        return self
    
    def sort_by(self, field: str, descending: bool = True) -> 'MongoDBQueryBuilder':
        """Add sort order"""
        # Whitelist allowed sort fields
        allowed_fields = {'timestamp', 'event_id', 'severity', 'computer'}
        if field not in allowed_fields:
            raise ValueError(f"Cannot sort by '{field}'. Allowed fields: {allowed_fields}")
        
        self.sort = [(field, -1 if descending else 1)]
        return self
    
    def limit(self, limit: int) -> 'MongoDBQueryBuilder':
        """Add result limit"""
        self.limit_value = self.validator.validate_limit(limit)
        return self
    
    def build(self) -> Dict[str, Any]:
        """Build and return the query"""
        return self.query
    
    def execute(self, collection):
        """Execute the query on a MongoDB collection"""
        cursor = collection.find(self.query)
        
        if self.sort:
            cursor = cursor.sort(self.sort)
        
        if self.limit_value:
            cursor = cursor.limit(self.limit_value)
        
        return cursor
