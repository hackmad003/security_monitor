"""
Base Detector Module
Abstract base class for all security detectors
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Alert:
    """Security alert data structure"""
    severity: AlertSeverity
    alert_type: str
    computer: str
    timestamp: str
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'severity': self.severity.value,
            'type': self.alert_type,
            'computer': self.computer,
            'timestamp': self.timestamp,
            **self.details
        }


class BaseDetector(ABC):
    """Abstract base class for security event detectors"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize detector
        
        Args:
            config: Detector-specific configuration
        """
        self.config = config or {}
        self.alerts: List[Alert] = []
    
    @abstractmethod
    def detect(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """
        Analyze events and generate alerts
        
        Args:
            events: List of parsed event dictionaries
            
        Returns:
            List of generated alerts
        """
        pass
    
    @abstractmethod
    def reset(self) -> None:
        """Reset detector state"""
        pass
    
    def get_alerts(self) -> List[Alert]:
        """Get all generated alerts"""
        return self.alerts
    
    def clear_alerts(self) -> None:
        """Clear all alerts"""
        self.alerts = []
    
    def _create_alert(
        self,
        severity: AlertSeverity,
        alert_type: str,
        computer: str,
        timestamp: str,
        **details
    ) -> Alert:
        """
        Create and add alert
        
        Args:
            severity: Alert severity
            alert_type: Type of alert
            computer: Computer name
            timestamp: Event timestamp
            **details: Additional alert details
            
        Returns:
            Created alert
        """
        alert = Alert(
            severity=severity,
            alert_type=alert_type,
            computer=computer,
            timestamp=timestamp,
            details=details
        )
        self.alerts.append(alert)
        return alert