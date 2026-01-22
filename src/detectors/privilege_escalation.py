"""
Privilege Escalation Detector Module
Detects admin privilege assignments
"""

from typing import List, Dict, Any, Optional
from .base_detector import BaseDetector, Alert, AlertSeverity


class PrivilegeEscalationDetector(BaseDetector):
    """Detects privilege escalation via admin privilege assignments"""

    # Event ID for admin privileges assigned
    PRIVILEGE_EVENT_ID = 4672

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize privilege escalation detector
        
        Args:
            config: Detector configuration
        """
        super().__init__(config)
    
    def detect(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """
        Detect privilege escalation events
        
        Args:
            events: List of security events
            
        Returns:
            List of privilege escalation alerts
        """
        # Filter privilege assignment events
        priv_events = [e for e in events if e['event_id'] == self.PRIVILEGE_EVENT_ID]
        
        # Generate alerts for each privilege event
        new_alerts = []
        for event in priv_events:
            alert = self._create_alert(
                severity=AlertSeverity.MEDIUM,
                alert_type='Admin Privileges Assigned',
                computer=event['computer'],
                timestamp=event['timestamp']
            )
            new_alerts.append(alert)
        
        return new_alerts
    
    def reset(self) -> None:
        """Reset detector state"""
        self.clear_alerts()