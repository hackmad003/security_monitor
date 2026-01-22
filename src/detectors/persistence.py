"""
Persistence Detector Module
Detects persistence mechanisms like scheduled tasks
"""

from typing import List, Dict, Any, Optional
from .base_detector import BaseDetector, Alert, AlertSeverity


class PersistenceDetector(BaseDetector):
    """Detects persistence mechanisms via scheduled task creation"""

    # Event ID for scheduled task creation
    TASK_CREATED_EVENT_ID = 4698

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize persistence detector
        
        Args:
            config: Detector configuration
        """
        super().__init__(config)
    
    def detect(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """
        Detect persistence mechanisms
        
        Args:
            events: List of security events
            
        Returns:
            List of persistence alerts
        """
        # Filter scheduled task creation events
        task_events = [e for e in events if e['event_id'] == self.TASK_CREATED_EVENT_ID]
        
        # Generate alerts for each task creation
        new_alerts = []
        for event in task_events:
            alert = self._create_alert(
                severity=AlertSeverity.MEDIUM,
                alert_type='Scheduled Task Created',
                computer=event['computer'],
                timestamp=event['timestamp'],
                note='Possible persistence mechanism'
            )
            new_alerts.append(alert)
        
        return new_alerts
    
    def reset(self) -> None:
        """Reset detector state"""
        self.clear_alerts()