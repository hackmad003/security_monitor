"""
MongoDB Storage Handler
Manages MongoDB operations for storing and querying security events
WITH NOSQL INJECTION PREVENTION
"""

import datetime
from typing import List, Dict, Any, Optional
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import logging

from .query_validator import QueryValidator, MongoDBQueryBuilder

logger = logging.getLogger(__name__)


class MongoDBHandler:
    """Handles MongoDB storage and queries"""
    
    def __init__(self, uri: str = 'mongodb://localhost:27017/', db_name: str = 'security_monitor'):
        """
        Initialize MongoDB handler
        
        Args:
            uri: MongoDB connection URI
            db_name: Database name
        """
        self.uri = uri
        self.db_name = db_name
        self.client: Optional[MongoClient] = None
        self.db = None
        
        self._connect()
    
    def _connect(self) -> None:
        """Establish MongoDB connection"""
        try:
            self.client = MongoClient(
                self.uri,
                serverSelectionTimeoutMS=5000
            )
            
            # Test connection
            self.client.admin.command('ping')
            
            # Get database
            self.db = self.client[self.db_name]
            
            # Get/create collections
            self.runs_collection = self.db['analysis_runs']
            self.alerts_collection = self.db['alerts']
            self.events_collection = self.db['events']
            
            # Create indexes
            self._create_indexes()
            
            # Print success message
            print(f"✓ MongoDB connected: {self.db_name}")
            print(f"✓ Collections: analysis_runs, alerts, events")
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"❌ MongoDB connection failed: {e}")
            print(f"   Make sure MongoDB is running: net start MongoDB")
            self.client = None
            self.db = None
        except Exception as e:
            print(f"❌ MongoDB error: {e}")
            self.client = None
            self.db = None
    
    def _create_indexes(self) -> None:
        """Create database indexes for better query performance"""
        if self.db is None:  # ✅ This is correct
            return
        
        try:
            self.runs_collection.create_index([('timestamp', -1)])
            self.alerts_collection.create_index([('severity', 1), ('timestamp', -1)])
            self.alerts_collection.create_index([('computer', 1)])
            self.events_collection.create_index([('event_id', 1), ('timestamp', -1)])
        except Exception as e:
            print(f"Warning: Could not create indexes: {e}")
    
    def is_connected(self) -> bool:
        """Check if MongoDB is connected"""
        return self.client is not None and self.db is not None
    
    def save_analysis_run(
        self,
        events: List[Dict[str, Any]],
        alerts: List[Dict[str, Any]],
        mode: str = 'single',
        duration: float = 0
    ) -> Optional[str]:
        """
        Save analysis run to MongoDB
        
        Args:
            events: List of security events
            alerts: List of alerts
            mode: Analysis mode ('single' or 'realtime')
            duration: Duration of analysis in seconds
            
        Returns:
            Run ID if successful, None otherwise
        """
        if self.client is None or self.db is None:
            print("⚠️ MongoDB not connected, skipping database save")
            return None
        
        if not events and not alerts:
            return None
        
        try:
            current_time = datetime.datetime.now()
            
            # Create analysis run document
            run_doc = {
                'timestamp': current_time,
                'mode': mode,
                'events_analyzed': len(events),
                'alerts_generated': len(alerts),
                'high_severity_count': len([a for a in alerts if a.get('severity') == 'HIGH']),
                'medium_severity_count': len([a for a in alerts if a.get('severity') == 'MEDIUM']),
                'duration_seconds': duration
            }
            
            # Insert run document
            run_result = self.runs_collection.insert_one(run_doc)
            run_id = run_result.inserted_id
            
            # Insert alerts
            if alerts:
                alert_docs = []
                for alert in alerts:
                    alert_doc = {
                        'run_id': run_id,
                        'timestamp': current_time,
                        'severity': alert.get('severity', 'UNKNOWN'),
                        'alert_type': alert.get('type', 'Unknown'),
                        'computer': alert.get('computer', 'Unknown'),
                        'failed_attempts': alert.get('failed_attempts'),
                        'details': alert
                    }
                    alert_docs.append(alert_doc)
                
                self.alerts_collection.insert_many(alert_docs)
            
            # Insert sample of events (first 100)
            if events:
                event_docs = []
                for event in events[:100]:
                    event_doc = {
                        'run_id': run_id,
                        'timestamp': current_time,
                        'event_id': event.get('event_id'),
                        'computer': event.get('computer', 'Unknown'),
                        'source': event.get('source', 'Unknown'),
                        'event_timestamp': event.get('timestamp')
                    }
                    event_docs.append(event_doc)
                
                self.events_collection.insert_many(event_docs)
            
            print(f"✓ Saved to MongoDB (Run ID: {run_id})")
            return str(run_id)
            
        except Exception as e:
            print(f"❌ MongoDB save error: {e}")
            return None
    
    def query_recent_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Query recent analysis runs (SECURE VERSION with input validation)
        
        Args:
            limit: Maximum number of runs to return
            
        Returns:
            List of run documents
        """
        if self.client is None:
            return []
        
        try:
            # SECURITY: Validate limit to prevent abuse
            validated_limit = QueryValidator.validate_limit(limit, max_limit=1000)
            
            runs = list(self.runs_collection.find(
                {},
                {
                    '_id': 1, 'timestamp': 1, 'mode': 1, 'events_analyzed': 1,
                    'alerts_generated': 1, 'high_severity_count': 1, 'medium_severity_count': 1
                }
            ).sort('timestamp', -1).limit(validated_limit))
            
            return runs
        except ValueError as e:
            logger.error(f"Validation error in query_recent_runs: {e}")
            return []
        except Exception as e:
            logger.error(f"Query error: {e}")
            return []
    
    def query_alerts_by_severity(
        self,
        severity: str = 'HIGH',
        days: int = 7
    ) -> List[Dict[str, Any]]:
        """
        Query alerts by severity level (SECURE VERSION with input validation)
        
        Args:
            severity: Alert severity level
            days: Number of days to look back
            
        Returns:
            List of alert documents
        """
        if self.client is None:
            return []
        
        try:
            # SECURITY: Validate inputs to prevent NoSQL injection
            validated_severity = QueryValidator.validate_severity(severity)
            validated_days = QueryValidator.validate_days(days)
            
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=validated_days)
            
            # Use validated query builder
            query = MongoDBQueryBuilder() \
                .filter_by_severity(validated_severity) \
                .filter_by_date_range(start_date=cutoff_date) \
                .sort_by('timestamp', descending=True) \
                .build()
            
            alerts = list(self.alerts_collection.find(
                query,
                {'timestamp': 1, 'alert_type': 1, 'computer': 1, 'failed_attempts': 1, 'severity': 1}
            ).sort('timestamp', -1))
            
            return alerts
        except ValueError as e:
            logger.error(f"Validation error in query_alerts_by_severity: {e}")
            return []
        except Exception as e:
            logger.error(f"Query error: {e}")
            return []
    
    def get_statistics(self, days: int = 30) -> Dict[str, int]:
        """
        Get aggregated statistics (SECURE VERSION with input validation)
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Statistics dictionary
        """
        if self.client is None:
            return {'total_runs': 0, 'total_alerts': 0, 'total_high_severity': 0, 'total_events': 0}
        
        try:
            # SECURITY: Validate days parameter
            validated_days = QueryValidator.validate_days(days, max_days=365)
            
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=validated_days)
            
            # Safe aggregation pipeline (no user-controlled operators)
            pipeline = [
                {'$match': {'timestamp': {'$gte': cutoff_date}}},
                {'$group': {
                    '_id': None,
                    'total_runs': {'$sum': 1},
                    'total_alerts': {'$sum': '$alerts_generated'},
                    'total_high_severity': {'$sum': '$high_severity_count'},
                    'total_events': {'$sum': '$events_analyzed'}
                }}
            ]
            
            result = list(self.runs_collection.aggregate(pipeline))
            
            if result:
                return {
                    'total_runs': result[0]['total_runs'],
                    'total_alerts': result[0]['total_alerts'],
                    'total_high_severity': result[0]['total_high_severity'],
                    'total_events': result[0].get('total_events', 0)
                }
            else:
                return {'total_runs': 0, 'total_alerts': 0, 'total_high_severity': 0, 'total_events': 0}
                
        except ValueError as e:
            logger.error(f"Validation error in get_statistics: {e}")
            return {'total_runs': 0, 'total_alerts': 0, 'total_high_severity': 0, 'total_events': 0}
        except Exception as e:
            logger.error(f"Statistics error: {e}")
            return {'total_runs': 0, 'total_alerts': 0, 'total_high_severity': 0, 'total_events': 0}
    
    def close(self) -> None:
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.client = None
            self.db = None