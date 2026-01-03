"""
File Logger Module
Logs alerts to file
"""

import datetime
from typing import Dict, Any
from pathlib import Path


class FileLogger:
    """Logs alerts to file"""
    
    def __init__(self, log_file: str = 'alerts.log'):
        """
        Initialize file logger
        
        Args:
            log_file: Path to log file
        """
        self.log_file = Path(log_file)
        
        # Create file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.touch()
    
    def log_alert(self, alert: Dict[str, Any]) -> None:
        """
        Log single alert to file
        
        Args:
            alert: Alert dictionary
        """
        try:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            log_entry = (
                f"[{timestamp}] {alert.get('severity', 'UNKNOWN')} - "
                f"{alert.get('type', 'Unknown Alert')} on {alert.get('computer', 'Unknown')}"
            )
            
            # Add specific details based on alert type
            if alert.get('type') == 'Brute Force Detection':
                log_entry += f" - {alert.get('failed_attempts', 0)} failed attempts"
            
            log_entry += "\n"
            
            # Append to file
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
                
        except Exception as e:
            print(f"⚠️ Failed to write to log file: {e}")
    
    def log_alerts(self, alerts: list) -> None:
        """
        Log multiple alerts to file
        
        Args:
            alerts: List of alert dictionaries
        """
        for alert in alerts:
            self.log_alert(alert)