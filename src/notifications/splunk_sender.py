"""
Splunk Integration Module
Sends events and alerts to Splunk via HTTP Event Collector
"""

import requests
import datetime
import urllib3
from typing import List, Dict, Any, Optional


class SplunkSender:
    """Sends security events and alerts to Splunk"""

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str = 'main',
        sourcetype: str = 'windows_security_monitor',
        verify_ssl: bool = True,  # SECURITY FIX: Changed default to True
        cert_path: Optional[str] = None
    ):
        """
        Initialize Splunk sender
        
        Args:
            hec_url: Splunk HTTP Event Collector URL
            hec_token: HEC authentication token
            index: Splunk index name
            sourcetype: Event sourcetype
            verify_ssl: Whether to verify SSL certificates (default: True for security)
            cert_path: Path to custom CA certificate bundle
        """
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.index = index
        self.sourcetype = sourcetype
        self.verify_ssl = verify_ssl
        self.cert_path = cert_path
        
        # SECURITY WARNING: Only disable SSL for localhost development
        if not verify_ssl:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "⚠️  SECURITY WARNING: SSL verification is DISABLED! "
                "This should only be used for localhost development. "
                "Enable SSL verification in production by setting verify_ssl=True"
            )
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Use custom certificate if provided
        if cert_path and verify_ssl:
            import os
            if not os.path.exists(cert_path):
                raise ValueError(f"Certificate file not found: {cert_path}")
            self.verify_ssl = cert_path
    
    def send_data(
        self,
        events: List[Dict[str, Any]],
        alerts: List[Dict[str, Any]]
    ) -> bool:
        """
        Send events and alerts to Splunk
        
        Args:
            events: List of security events
            alerts: List of security alerts
            
        Returns:
            True if successful, False otherwise
        """
        if not events and not alerts:
            return False
        
        try:
            headers = {
                'Authorization': f"Splunk {self.hec_token}",
                'Content-Type': 'application/json'
            }
            
            sent_count = 0
            
            # Send alerts
            for alert in alerts:
                if self._send_alert(alert, headers):
                    sent_count += 1
            
            # Send sample of events (first 50)
            for event in events[:50]:
                if self._send_event(event, headers):
                    sent_count += 1
            
            if sent_count > 0:
                print(f"✓ Sent {sent_count} events to Splunk")
                return True
            
            return False
            
        except requests.exceptions.ConnectionError:
            print(f"❌ Splunk connection failed - Is Splunk running?")
            return False
        except Exception as e:
            print(f"❌ Splunk error: {e}")
            return False
    
    def _send_alert(self, alert: Dict[str, Any], headers: Dict[str, str]) -> bool:
        """Send individual alert to Splunk"""
        try:
            event_payload = {
                'time': datetime.datetime.now().timestamp(),
                'host': alert.get('computer', 'unknown'),
                'source': 'windows_security_monitor',
                'sourcetype': self.sourcetype,
                'index': self.index,
                'event': {
                    'event_type': 'security_alert',
                    'severity': alert.get('severity', 'UNKNOWN'),
                    'alert_type': alert.get('type', 'Unknown'),
                    'computer': alert.get('computer', 'unknown'),
                    'failed_attempts': alert.get('failed_attempts'),
                    'timestamp': alert.get('timestamp', datetime.datetime.now().isoformat()),
                    'details': alert
                }
            }
            
            response = requests.post(
                self.hec_url,
                headers=headers,
                json=event_payload,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                return True
            else:
                print(f"⚠️ Splunk alert send failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"⚠️ Failed to send alert: {e}")
            return False
    
    def _send_event(self, event: Dict[str, Any], headers: Dict[str, str]) -> bool:
        """Send individual event to Splunk"""
        try:
            event_payload = {
                'time': datetime.datetime.now().timestamp(),
                'host': event.get('computer', 'unknown'),
                'source': 'windows_security_monitor',
                'sourcetype': self.sourcetype,
                'index': self.index,
                'event': {
                    'event_type': 'security_event',
                    'event_id': event.get('event_id'),
                    'computer': event.get('computer', 'unknown'),
                    'source': event.get('source', 'unknown'),
                    'timestamp': event.get('timestamp')
                }
            }
            
            response = requests.post(
                self.hec_url,
                headers=headers,
                json=event_payload,
                verify=self.verify_ssl
            )
            
            return response.status_code == 200
            
        except Exception:
            return False