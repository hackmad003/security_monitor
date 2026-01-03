"""
Console Logger Module
Handles formatted console output for security monitoring
"""

import datetime
from typing import List, Dict, Any
from collections import defaultdict


class ConsoleLogger:
    """Handles formatted console output"""
    
    @staticmethod
    def print_header(title: str, num_events: int = None) -> None:
        """Print analysis header"""
        print(f"\n{'='*60}")
        print(f"Windows Security Event Monitor - {title}")
        if num_events:
            print(f"Analyzing last {num_events} security events...")
        print(f"{'='*60}\n")
    
    @staticmethod
    def print_footer(alert_count: int) -> None:
        """Print analysis footer"""
        print(f"\n{'='*60}")
        print(f"Analysis Complete - {alert_count} alerts generated")
        print(f"{'='*60}\n")
    
    @staticmethod
    def print_no_events_guidance() -> None:
        """Print guidance when no events are found"""
        print("❌ No relevant security events found in recent logs.\n")
        print("This could mean:")
        print("  • Your system has been quiet (good!)")
        print("  • Not enough activity of monitored event types")
        print("  • Windows Event logging may not be fully enabled\n")
        print("To generate test events, try:")
        print("  1. Lock and unlock your computer (generates login events)")
        print("  2. Try logging in with wrong password (generates failed login)")
        print("  3. Run program again with more events: run_analysis(500)\n")
    
    @staticmethod
    def print_alert(alert: Dict[str, Any]) -> None:
        """Print formatted alert"""
        print(f"⚠ ALERT: {alert.get('type', 'Unknown')}")
        print(f"   Severity: {alert.get('severity', 'UNKNOWN')}")
        print(f"   Computer: {alert.get('computer', 'N/A')}")
        
        if alert.get('type') == 'Brute Force Detection':
            print(f"   Failed Attempts: {alert.get('failed_attempts', 'N/A')}")
        elif 'timestamp' in alert:
            print(f"   Time: {alert.get('timestamp')}")
        
        if 'note' in alert:
            print(f"   Note: {alert.get('note')}")
        
        print()
    
    @staticmethod
    def print_statistics(stats: Dict[str, Any]) -> None:
        """Print event statistics"""
        print("\nEvent Statistics:")
        print("-" * 60)
        
        event_breakdown = stats.get('event_breakdown', {})
        for event_type, count in sorted(event_breakdown.items(), key=lambda x: x[1], reverse=True):
            print(f"  {event_type}: {count}")
    
    @staticmethod
    def print_realtime_header(interval: int) -> None:
        """Print real-time monitoring header"""
        print(f"\n{'='*60}")
        print(f"Real-Time Security Monitoring Started")
        print(f"Checking every {interval} seconds for NEW events only...")
        print(f"Alert tracking resets every 1 hour")
        print(f"Press Ctrl+C to stop")
        print(f"{'='*60}\n")
    
    @staticmethod
    def print_realtime_check(current_time: datetime.datetime, last_check: datetime.datetime) -> None:
        """Print real-time check status"""
        print(f"[{current_time.strftime('%H:%M:%S')}] " 
              f"Checking for events since {last_check.strftime('%H:%M:%S')}...")
    
    @staticmethod
    def print_event_breakdown(events: List[Dict[str, Any]]) -> None:
        """Print event type breakdown"""
        if not events:
            return
        
        event_counts = defaultdict(int)
        for e in events:
            # Try event_type first, fallback to event_id with description
            event_type = e.get('event_type')
            
            if not event_type:
                # Map event_id to readable name
                event_id = e.get('event_id', 'Unknown')
                event_type_map = {
                    4625: "Failed Login Attempt",
                    4624: "Successful Login",
                    4720: "User Account Created",
                    4672: "Admin Privileges Assigned",
                    4698: "Scheduled Task Created",
                    4688: "Process Created",
                    4663: "File Access Attempt",
                    4648: "Login with Explicit Credentials"
                }
                event_type = event_type_map.get(event_id, f"Event {event_id}")
            
            event_counts[event_type] += 1
        
        print(f"   Event breakdown:")
        for event_type, count in event_counts.items():
            print(f"   - {event_type}: {count}")
    
    @staticmethod
    def print_mongodb_statistics(
        stats: Dict[str, int],
        recent_runs: List[Dict[str, Any]],
        high_alerts: List[Dict[str, Any]],
        days: int = 7
    ) -> None:
        """Print MongoDB statistics"""
        print(f"\n{'='*60}")
        print(f"MongoDB Statistics (Last {days} days)")
        print(f"{'='*60}\n")
        
        print(f"Total Analysis Runs: {stats.get('total_runs', 0)}")
        print(f"Total Alerts: {stats.get('total_alerts', 0)}")
        print(f"High Severity Alerts: {stats.get('total_high_severity', 0)}")
        
        print(f"\nRecent Analysis Runs:")
        print("-" * 60)
        
        if recent_runs:
            for run in recent_runs:
                timestamp = run.get('timestamp')
                mode = run.get('mode', 'unknown')
                events = run.get('events_analyzed', 0)
                alerts = run.get('alerts_generated', 0)
                high = run.get('high_severity_count', 0)
                medium = run.get('medium_severity_count', 0)
                
                if timestamp:
                    ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    print(f"  {ts_str} [{mode:8s}] "
                          f"Events: {events:4d} | Alerts: {alerts} (H:{high}, M:{medium})")
        else:
            print("  No runs found")
        
        print(f"\nRecent HIGH Severity Alerts:")
        print("-" * 60)
        
        if high_alerts:
            for alert in high_alerts[:5]:
                timestamp = alert.get('timestamp')
                alert_type = alert.get('alert_type', 'Unknown')
                computer = alert.get('computer', 'Unknown')
                
                if timestamp:
                    ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    print(f"  {ts_str} - {alert_type} on {computer}")
        else:
            print("  No HIGH severity alerts")
        
        print(f"\n{'='*60}\n")