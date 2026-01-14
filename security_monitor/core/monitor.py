"""
Security Monitor Core Module
Main orchestration class for security event monitoring
"""

import time
import datetime
import winsound
from typing import List, Dict, Any, Optional

from ..utils.config import Config
from ..core.event_reader import EventReader
from ..detectors import (
    BruteForceDetector,
    PrivilegeEscalationDetector,
    PersistenceDetector
)
from ..database import MongoDBHandler, JSONExporter, WeeklyJSONExporter
from ..notifications import EmailSender, SplunkSender, ConsoleLogger, FileLogger  # ← Add FileLogger


class SecurityMonitor:
    """
    Main security monitoring orchestration class
    
    Coordinates event reading, detection, storage, and notifications
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize Security Monitor
        
        Args:
            config: Configuration object (creates default if None)
        """
        # Load configuration
        self.config = config or Config()
        
        # Initialize event reader
        self.event_reader = EventReader(
            server=self.config.event_log_server,
            log_type=self.config.event_log_type
        )
        
        # Initialize detectors (dynamically based on config)
        self.detectors = self._initialize_detectors()
        
        # Initialize storage
        self.mongodb = MongoDBHandler(
            uri=self.config.mongodb_uri,
            db_name=self.config.mongodb_database
        )
        
        # Initialize notifications
        self._init_email()
        self._init_splunk()
        
        # File logger (save to logs/ directory)
        from pathlib import Path
        logs_dir = Path(__file__).parent.parent.parent / "logs"
        logs_dir.mkdir(exist_ok=True)
        self.file_logger = FileLogger(str(logs_dir / 'alerts.log'))

        # Console logger
        self.logger = ConsoleLogger()
        
        # Critical event IDs to monitor
        self.critical_event_ids = set(self.config.critical_events.keys())
        
        # All alerts from all detectors
        self.all_alerts: List[Dict[str, Any]] = []
    
    def _initialize_detectors(self) -> List:
        """
        Initialize enabled detectors based on configuration
        
        Returns:
            List of enabled detector instances
        """
        detectors = []
        
        # Brute Force Detector
        if self.config.detector_brute_force_enabled:
            detectors.append(
                BruteForceDetector({'threshold': self.config.brute_force_threshold})
            )
            print("✓ Brute Force Detector: ENABLED")
        else:
            print("✗ Brute Force Detector: DISABLED")
        
        # Privilege Escalation Detector
        if self.config.detector_privilege_escalation_enabled:
            detectors.append(PrivilegeEscalationDetector())
            print("✓ Privilege Escalation Detector: ENABLED")
        else:
            print("✗ Privilege Escalation Detector: DISABLED")
        
        # Persistence Detector
        if self.config.detector_persistence_enabled:
            detectors.append(PersistenceDetector())
            print("✓ Persistence Detector: ENABLED")
        else:
            print("✗ Persistence Detector: DISABLED")
        
        print()  # Empty line for readability
        return detectors
    
    def _init_email(self) -> None:
        """Initialize email sender"""
        if self.config.email_enabled and self.config.recipient_emails:
            self.email_sender = EmailSender(
                smtp_server=self.config.smtp_server,
                smtp_port=self.config.smtp_port,
                sender_email=self.config.sender_email,
                sender_password=self.config.sender_password,
                recipient_emails=self.config.recipient_emails
            )
        else:
            self.email_sender = None
    
    def _init_splunk(self) -> None:
        """Initialize Splunk sender"""
        if self.config.splunk_enabled and self.config.splunk_hec_token:
            self.splunk_sender = SplunkSender(
                hec_url=self.config.splunk_hec_url,
                hec_token=self.config.splunk_hec_token,
                index=self.config.splunk_index,
                sourcetype=self.config.splunk_sourcetype,
                verify_ssl=self.config.splunk_verify_ssl
            )
        else:
            self.splunk_sender = None
    
    def run_analysis(self, num_events: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Run single security analysis
        
        Args:
            num_events: Number of events to analyze (uses config default if None)
            
        Returns:
            Analysis results dictionary or None
        """
        if num_events is None:
            num_events = self.config.default_event_count
        
        # Print header
        self.logger.print_header("Analysis Started", num_events)
        
        # Read events
        events = self.event_reader.read_events(
            num_events=num_events,
            event_ids=self.critical_event_ids
        )
        
        # Check if events found
        if not events:
            self.logger.print_no_events_guidance()
            return None
        
        print(f"✓ Found {len(events)} relevant security events\n")
        
        # Run detections
        print("Running Security Detections...")
        print("-" * 60)
        
        self.all_alerts = []
        for detector in self.detectors:
            alerts = detector.detect(events)
            for alert in alerts:
                alert_dict = alert.to_dict()
                self.all_alerts.append(alert_dict)
                self.logger.print_alert(alert_dict)
        
        # Check if any alerts generated
        if not self.all_alerts:
            print("✓ No security threats detected\n")
        
        # Generate statistics
        stats = self._generate_statistics(events)
        self.logger.print_statistics(stats)
        
        # Save to MongoDB
        self.mongodb.save_analysis_run(
            events=[self._event_to_dict(e) for e in events],
            alerts=self.all_alerts,
            mode='single',
            duration=0
        )
        
        # Send to Splunk
        if self.splunk_sender:
            self.splunk_sender.send_data(
                events=[self._event_to_dict(e) for e in events],
                alerts=self.all_alerts
            )
        
        # Send email alerts
        if self.email_sender and self.all_alerts:
            self.email_sender.send_alert(
                self.all_alerts,
                computer=self.config.event_log_server
            )

        # Log alerts to file
        if self.all_alerts:
            self.file_logger.log_alerts(self.all_alerts)
            print(f"✓ Logged {len(self.all_alerts)} alerts to alerts.log")
        

        # Auto-export JSON report
        if self.all_alerts:
            WeeklyJSONExporter.export_weekly_report(self.all_alerts)
            print(f"✓ Exported to weekly JSON report")



        # Print footer
        self.logger.print_footer(len(self.all_alerts))
        
        # Return results
        return {
            'events': events,
            'alerts': self.all_alerts,
            'stats': stats
        }
    
    def start_realtime_monitoring(
        self,
        interval_seconds: Optional[int] = None,
        events_per_check: Optional[int] = None
    ) -> None:
        """
        Start real-time security monitoring
        
        Args:
            interval_seconds: Check interval (uses config default if None)
            events_per_check: Events to check per cycle (uses config default if None)
        """
        if interval_seconds is None:
            interval_seconds = self.config.realtime_interval_seconds
        
        if events_per_check is None:
            events_per_check = self.config.events_per_check
        
        # Print header
        self.logger.print_realtime_header(interval_seconds)
        
        # Initialize tracking
        last_check_time = datetime.datetime.now()
        last_alert_reset = datetime.datetime.now()
        
        try:
            while True:
                # Wait for interval
                time.sleep(interval_seconds)
                
                current_time = datetime.datetime.now()
                
                # Check if alert reset needed (hourly)
                time_since_reset = (current_time - last_alert_reset).total_seconds()
                if time_since_reset >= self.config.alert_reset_interval_hours * 3600:
                    print(f"\n{'='*60}")
                    print(f"🔄 Alert Tracking Reset (1 hour elapsed)")
                    print(f"   Will re-alert on any computer if brute force detected")
                    print(f"{'='*60}\n")
                    
                    # Reset brute force detector alerts
                    for detector in self.detectors:
                        if isinstance(detector, BruteForceDetector):
                            detector.reset_alerts()
                    
                    last_alert_reset = current_time
                
                # Print check status
                self.logger.print_realtime_check(current_time, last_check_time)
                
                # Read new events
                new_events = self.event_reader.read_events_since(
                    since_time=last_check_time,
                    max_events=events_per_check,
                    event_ids=self.critical_event_ids
                )
                
                if new_events:
                    print(f"✓ Found {len(new_events)} NEW events since last check")
                    self.logger.print_event_breakdown(new_events)
                    
                    # Run detections
                    print("\nRunning Security Detections...")
                    print("-" * 60)
                    
                    self.all_alerts = []
                    for detector in self.detectors:
                        alerts = detector.detect(new_events)
                        for alert in alerts:
                            alert_dict = alert.to_dict()
                            self.all_alerts.append(alert_dict)
                            self.logger.print_alert(alert_dict)
                    
                    if not self.all_alerts:
                        print("✓ No security threats detected\n")
                    
                    # Alert if HIGH severity
                    if self.all_alerts:
                        high_alerts = [a for a in self.all_alerts if a.get('severity') == 'HIGH']
                        if high_alerts:
                            print(f"🚨 CRITICAL: {len(high_alerts)} HIGH severity alert(s)!")
                            try:
                                winsound.Beep(1000, 500)
                            except:
                                pass  # Beep not available
                        
                        # Send email
                        if self.email_sender:
                            self.email_sender.send_alert(
                                self.all_alerts,
                                computer=self.config.event_log_server
                            )
                        
                        # Save to MongoDB
                        self.mongodb.save_analysis_run(
                            events=[self._event_to_dict(e) for e in new_events],
                            alerts=self.all_alerts,
                            mode='realtime',
                            duration=interval_seconds
                        )
                        
                        # Send to Splunk
                        if self.splunk_sender:
                            self.splunk_sender.send_data(
                                events=[self._event_to_dict(e) for e in new_events],
                                alerts=self.all_alerts
                            )

                        # Log to file  ← ADD THIS BLOCK
                        if self.all_alerts:
                            self.file_logger.log_alerts(self.all_alerts)
                            WeeklyJSONExporter.export_weekly_report(self.all_alerts)


                        
                        # ADD THESE 4 LINES FOR JSON IN REAL-TIME:
                        if self.all_alerts:
                            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                            filename = f'security_report_{timestamp}.json'
                            JSONExporter.export_report(self.all_alerts, filename)

                    
                    # Clear detector alerts for next cycle
                    for detector in self.detectors:
                        detector.clear_alerts()
                else:
                    print(f"✓ No new events in the last {interval_seconds} seconds")
                
                # Update last check time
                last_check_time = current_time
        
        except KeyboardInterrupt:
            print(f"\n\n{'='*60}")
            print("Real-Time Monitoring Stopped")
            print(f"{'='*60}\n")
    
    def export_report(self, filename: Optional[str] = None) -> bool:
        """
        Export security report to JSON
        
        Args:
            filename: Output filename (uses config default if None)
            
        Returns:
            True if successful
        """
        if filename is None:
            filename = self.config.default_export_filename
        
        return JSONExporter.export_report(self.all_alerts, filename)
    
    def display_statistics(self, days: Optional[int] = None) -> None:
        """
        Display MongoDB statistics
        
        Args:
            days: Number of days to analyze (uses config default if None)
        """
        if days is None:
            days = self.config.statistics_days
        
        stats = self.mongodb.get_statistics(days)
        recent_runs = self.mongodb.query_recent_runs(5)
        high_alerts = self.mongodb.query_alerts_by_severity('HIGH', days)
        
        self.logger.print_mongodb_statistics(stats, recent_runs, high_alerts, days)
    
    def _generate_statistics(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate event statistics"""
        stats = {
            'total_events': len(events),
            'event_breakdown': {},
            'timeline': []
        }
        
        # Get critical event names
        critical_events = self.config.critical_events
        
        # Count event types
        for event in events:
            event_id = event.get('event_id')
            if event_id is not None:
                event_type = critical_events.get(event_id, f"Event {event_id}")
            else:
                event_type = "Unknown Event"
            stats['event_breakdown'][event_type] = stats['event_breakdown'].get(event_type, 0) + 1
        
        return stats
    
    def _event_to_dict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert event to dictionary with event type name"""
        critical_events = self.config.critical_events
        event_copy = event.copy()
        event_id = event.get('event_id')
        if event_id is not None:
            event_copy['event_type'] = critical_events.get(event_id, f"Event {event_id}")
        else:
            event_copy['event_type'] = "Unknown Event"
        return event_copy
    
    def close(self) -> None:
        """Clean up resources"""
        if self.event_reader:
            self.event_reader.close()
        if self.mongodb:
            self.mongodb.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        """Context manager exit"""
        self.close()