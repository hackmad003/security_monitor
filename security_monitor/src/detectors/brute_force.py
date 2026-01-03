"""
Brute Force Detector Module
Detects brute force login attempts
"""

from typing import List, Dict, Any
from collections import defaultdict
from .base_detector import BaseDetector, Alert, AlertSeverity


class BruteForceDetector(BaseDetector):
    """Detects brute force attacks via failed login attempts"""
    
    # Event ID for failed login attempts
    FAILED_LOGIN_EVENT_ID = 4625
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize brute force detector
        
        Args:
            config: Configuration with 'threshold' key
        """
        super().__init__(config)
        self.threshold = self.config.get('threshold', 2)
        self.failed_login_tracker = defaultdict(list)
        self.alerted_computers = set()
    
    def detect(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """
        Detect brute force attacks
        
        Args:
            events: List of security events
            
        Returns:
            List of brute force alerts
        """
        # Filter failed login events
        failed_logins = [e for e in events if e['event_id'] == self.FAILED_LOGIN_EVENT_ID]
        
        # Track failed attempts by computer
        for event in failed_logins:
            computer = event['computer']
            timestamp = event['timestamp']
            self.failed_login_tracker[computer].append(timestamp)
        
        # Check threshold and generate alerts
        new_alerts = []
        for computer, attempts in self.failed_login_tracker.items():
            if len(attempts) >= self.threshold:
                # Check if already alerted for this computer
                if computer in self.alerted_computers:
                    continue
                
                # Mark as alerted
                self.alerted_computers.add(computer)
                
                # Create alert
                alert = self._create_alert(
                    severity=AlertSeverity.HIGH,
                    alert_type='Brute Force Detection',
                    computer=computer,
                    timestamp=attempts[-1],
                    failed_attempts=len(attempts),
                    timestamps=attempts[:5]  # Include first 5 timestamps
                )
                new_alerts.append(alert)
        
        return new_alerts
    
    def reset(self) -> None:
        """Reset detector state"""
        self.failed_login_tracker = defaultdict(list)
        self.alerted_computers = set()
        self.clear_alerts()
    
    def reset_alerts(self) -> None:
        """Reset only the alerted computers set (for hourly reset)"""
        self.alerted_computers = set()