"""
Multi-Target Security Monitor
Monitors multiple machines from central location
"""

import concurrent.futures
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any, Set
from .monitor import SecurityMonitor
from ..utils.config import Config


class MultiTargetMonitor:
    """Monitors multiple target machines"""

    def __init__(self, config: Config = None):
        """Initialize multi-target monitor"""
        self.config = config or Config()
        self.targets = self._load_targets()
        self._alerted_cache: Set[str] = set()
        self._load_alert_cache()

    def _get_cache_path(self) -> Path:
        """Get path to alert cache file"""
        cache_dir = Path(__file__).parent.parent.parent / "data"
        cache_dir.mkdir(exist_ok=True)
        return cache_dir / "alerted_events.json"

    def _load_alert_cache(self) -> None:
        """Load previously alerted event hashes from cache"""
        cache_path = self._get_cache_path()
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    data = json.load(f)
                    self._alerted_cache = set(data.get('hashes', []))
            except Exception:
                self._alerted_cache = set()

    def _save_alert_cache(self) -> None:
        """Save alerted event hashes to cache"""
        cache_path = self._get_cache_path()
        try:
            with open(cache_path, 'w') as f:
                json.dump({'hashes': list(self._alerted_cache)}, f)
        except Exception:
            pass

    def _get_alert_hash(self, alert: Dict) -> str:
        """Generate unique hash for an alert to detect duplicates"""
        # Use type + computer + timestamp as unique identifier
        key = f"{alert.get('type', '')}-{alert.get('computer', '')}-{alert.get('timestamp', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    def _filter_new_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Filter out alerts that have already been processed"""
        new_alerts = []
        for alert in alerts:
            alert_hash = self._get_alert_hash(alert)
            if alert_hash not in self._alerted_cache:
                new_alerts.append(alert)
                self._alerted_cache.add(alert_hash)
        return new_alerts

    def _print_alert_summary(self, alerts: List[Dict], target_name: str) -> None:
        """Print summarized alert statistics instead of individual alerts"""
        from collections import Counter

        # Count alerts by type and severity
        type_counts = Counter(a.get('type', 'Unknown') for a in alerts)
        severity_counts = Counter(a.get('severity', 'UNKNOWN') for a in alerts)

        print(f"\n  📊 Alert Summary for {target_name}:")
        print(f"     Total: {len(alerts)} alerts")

        # Show by severity
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                icon = "🔴" if severity == "HIGH" else "🟠" if severity == "MEDIUM" else "🟡"
                print(f"     {icon} {severity}: {count}")

        # Show by type
        print(f"     By Type:")
        for alert_type, count in type_counts.most_common():
            print(f"       - {alert_type}: {count}")
    
    def _load_targets(self) -> List[Dict[str, str]]:
        """
        Load target machines from configuration

        Returns:
            List of target configs: [{'host': '192.168.1.100', 'name': 'PC-1'}, ...]
        """
        import yaml
        from pathlib import Path

        # Load from targets.yaml (go up 3 levels: core -> src -> security_monitor)
        targets_path = Path(__file__).parent.parent.parent / "config" / "app" / "targets.yaml"

        if targets_path.exists():
            try:
                with open(targets_path, 'r') as f:
                    data = yaml.safe_load(f)

                targets = []
                for target in data.get('targets', []):
                    if target.get('enabled', True):
                        targets.append({
                            'host': target['host'],
                            'name': target['name']
                        })

                if targets:
                    return targets
            except Exception as e:
                print(f"Warning: Could not load targets.yaml: {e}")

        # Fallback to localhost only
        return [{'host': 'localhost', 'name': 'LocalMachine'}]
    
    def monitor_target(self, target: Dict[str, str]) -> Dict[str, Any]:
        """
        Monitor single target machine with full detection & notification pipeline
        """
        try:
            print(f"🔍 Monitoring {target['name']} ({target['host']})...")
            
            # ==========================================
            # 1. READ EVENTS
            # ==========================================
            if target['host'] == 'localhost':
                from ..core.event_reader import EventReader
                reader = EventReader(server=target['host'], log_type='Security')
                events = reader.read_events(num_events=100, event_ids=self.config.critical_events.keys())
                reader.close()
            else:
                from ..core.remote_event_reader import RemoteEventReader
                username = self.config.get('credentials.username', 'Administrator')
                password = self.config.get('credentials.password', 'SecurePass123!')
                reader = RemoteEventReader(server=target['host'], username=username, password=password)
                events = reader.read_events(num_events=100, event_ids=self.config.critical_events.keys())
                reader.close()
            
            # ==========================================
            # 2. RUN DETECTORS
            # ==========================================
            from ..detectors import BruteForceDetector, PrivilegeEscalationDetector, PersistenceDetector
            
            detectors = [
                BruteForceDetector(self.config),
                PrivilegeEscalationDetector(self.config),
                PersistenceDetector(self.config)
            ]
            
            all_alerts = []
            for detector in detectors:
                alerts = detector.detect(events)
                all_alerts.extend(alerts)
            
            # ==========================================
            # 3. CONVERT ALERTS TO DICTIONARIES
            # ==========================================
            import datetime
            alert_dicts = []
            for alert in all_alerts:
                if hasattr(alert, 'to_dict'):
                    # Alert object with to_dict method
                    alert_dict = alert.to_dict()
                    alert_dict['target'] = target['name']
                    alert_dicts.append(alert_dict)
                elif hasattr(alert, '__dict__'):
                    # Alert object - convert manually
                    severity = getattr(alert, 'severity', 'UNKNOWN')
                    # Handle AlertSeverity enum
                    if hasattr(severity, 'value'):
                        severity = severity.value
                    alert_dicts.append({
                        'type': getattr(alert, 'alert_type', getattr(alert, 'type', 'Unknown')),
                        'severity': severity,
                        'timestamp': getattr(alert, 'timestamp', datetime.datetime.now().isoformat()),
                        'target': target['name'],
                        'computer': getattr(alert, 'computer', target['name']),
                        'details': getattr(alert, 'details', {})
                    })
                else:
                    # Already a dict - ensure severity is string
                    if isinstance(alert.get('severity'), object) and hasattr(alert.get('severity'), 'value'):
                        alert['severity'] = alert['severity'].value
                    alert['target'] = target['name']
                    alert_dicts.append(alert)
            
            # ==========================================
            # 4. FILTER DUPLICATES & STORAGE
            # ==========================================
            # Filter out already-alerted events
            if alert_dicts:
                new_alerts = self._filter_new_alerts(alert_dicts)
                skipped = len(alert_dicts) - len(new_alerts)

                if skipped > 0:
                    print(f"  ⏭️  Skipped {skipped} already-alerted events")
            else:
                new_alerts = []
                skipped = 0

            if new_alerts:
                print(f"  🚨 Found {len(new_alerts)} NEW alerts for {target['name']}")
                alert_dicts = new_alerts  # Only process new alerts

                # 4a. MongoDB
                try:
                    from ..storage import MongoDBHandler
                    mongo = MongoDBHandler(
                        uri=self.config.mongodb_uri,
                        db_name=self.config.mongodb_database
                    )
                    mongo.save_analysis_run(events=events, alerts=alert_dicts, mode='multi-target')
                    mongo.close()
                    print(f"  💾 Saved to MongoDB")
                except Exception as e:
                    print(f"  ⚠️ MongoDB failed: {e}")

                # 4b. Weekly JSON file (all targets consolidated)
                try:
                    from ..storage import WeeklyJSONExporter
                    WeeklyJSONExporter.export_weekly_report(alerts=alert_dicts)
                except Exception as e:
                    print(f"  ⚠️ JSON export failed: {e}")

                # 4c. alerts.log file
                try:
                    from ..notifications import FileLogger
                    from pathlib import Path
                    logs_dir = Path(__file__).parent.parent.parent / "logs"
                    logs_dir.mkdir(exist_ok=True)
                    file_logger = FileLogger(str(logs_dir / 'alerts.log'))
                    file_logger.log_alerts(alert_dicts)
                    print(f"  📝 Logged to logs/alerts.log")
                except Exception as e:
                    print(f"  ⚠️ File logging failed: {e}")

                # ==========================================
                # 5. NOTIFICATIONS
                # ==========================================

                # 5a. Console (show summary instead of individual alerts)
                self._print_alert_summary(alert_dicts, target['name'])

                # 5b. Email (if enabled in .env)
                if self.config.email_enabled:
                    try:
                        from ..notifications import EmailSender
                        email = EmailSender(
                            smtp_server=self.config.smtp_server,
                            smtp_port=self.config.smtp_port,
                            sender_email=self.config.sender_email,
                            sender_password=self.config.sender_password,
                            recipient_emails=self.config.recipient_emails
                        )
                        email.send_alert(alert_dicts, computer=target['name'])
                        print(f"  📧 Email alerts sent")
                    except Exception as e:
                        print(f"  ⚠️ Email failed: {e}")

                # 5c. Splunk (if enabled in .env)
                if self.config.splunk_enabled:
                    try:
                        from ..notifications import SplunkSender
                        splunk = SplunkSender(
                            hec_url=self.config.splunk_hec_url,
                            hec_token=self.config.splunk_hec_token,
                            index=self.config.splunk_index,
                            sourcetype=self.config.splunk_sourcetype,
                            verify_ssl=self.config.splunk_verify_ssl
                        )
                        splunk.send_data(events=events, alerts=alert_dicts)
                        print(f"  📊 Sent to Splunk")
                    except Exception as e:
                        print(f"  ⚠️ Splunk failed: {e}")
            else:
                print(f"  ✅ No new alerts detected")

            # Save the alert cache
            self._save_alert_cache()

            # ==========================================
            # 6. RETURN RESULTS
            # ==========================================
            return {
                'target': target['name'],
                'host': target['host'],
                'success': True,
                'events_found': len(events),
                'alerts_found': len(new_alerts),
                'events': events,
                'alerts': new_alerts
            }
            
        except Exception as e:
            print(f"❌ Failed to monitor {target['name']}: {e}")
            import traceback
            traceback.print_exc()
            return {
                'target': target['name'],
                'host': target['host'],
                'success': False,
                'error': str(e)
            }
    
    def monitor_all_targets(self, parallel: bool = True) -> List[Dict[str, Any]]:
        """
        Monitor all targets with full detection pipeline
        """
        print(f"\n{'='*60}")
        print(f"Multi-Target Security Monitoring")
        print(f"Monitoring {len(self.targets)} machines...")
        print(f"{'='*60}\n")
        
        results = []
        
        if parallel:
            # Monitor all machines in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_target = {
                    executor.submit(self.monitor_target, target): target 
                    for target in self.targets
                }
                
                for future in concurrent.futures.as_completed(future_to_target):
                    result = future.result()
                    results.append(result)
        else:
            # Monitor one at a time
            for target in self.targets:
                result = self.monitor_target(target)
                results.append(result)
        
        # Summary
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        total_alerts = sum(r.get('alerts_found', 0) for r in successful)
        
        print(f"\n{'='*60}")
        print(f"Monitoring Complete")
        print(f"  Successful: {len(successful)}/{len(self.targets)}")
        print(f"  Failed: {len(failed)}")
        print(f"  Total Alerts: {total_alerts}")  # ← NEW
        print(f"{'='*60}\n")
        
        return results

    def start_realtime_monitoring(
        self,
        interval_seconds: int = 10,
        events_per_check: int = 100
    ) -> None:
        """
        Start real-time monitoring of all targets with full detection pipeline
        
        Args:
            interval_seconds: Check interval in seconds
            events_per_check: Events to check per cycle per machine
        """
        import time
        import datetime
        
        print(f"\n{'='*60}")
        print(f"🌐 Real-Time Multi-Target Monitoring Started")
        print(f"Monitoring {len(self.targets)} machines...")
        print(f"Checking every {interval_seconds} seconds")
        print(f"Press Ctrl+C to stop")
        print(f"{'='*60}\n")
        
        cycle_count = 0
        
        try:
            while True:
                cycle_count += 1
                current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                print(f"\n{'='*60}")
                print(f"[{current_time}] 🔄 Cycle #{cycle_count} - Checking all targets...")
                print(f"{'='*60}")
                
                # Monitor all targets (runs through full detection pipeline)
                results = self.monitor_all_targets(parallel=True)
                
                # Display detailed summary
                print(f"\n[{current_time}] 📊 Cycle #{cycle_count} Summary:")
                print("-" * 60)
                
                for result in results:
                    if result['success']:
                        events_found = result['events_found']
                        alerts_found = result.get('alerts_found', 0)
                        
                        if alerts_found > 0:
                            icon = "🚨"  # Alert icon
                            print(f"  {icon} {result['target']}: {events_found} events, {alerts_found} ALERTS")
                            
                            # Show alert details
                            if 'alerts' in result:
                                for alert in result['alerts'][:3]:  # Show first 3 alerts
                                    severity = alert.get('severity', 'UNKNOWN')
                                    alert_type = alert.get('type', 'Unknown')
                                    print(f"      └─ [{severity}] {alert_type}")
                                
                                if len(result['alerts']) > 3:
                                    print(f"      └─ ... and {len(result['alerts']) - 3} more alerts")
                        
                        elif events_found > 0:
                            icon = "🟢"
                            print(f"  {icon} {result['target']}: {events_found} events, 0 alerts")
                        else:
                            icon = "⚪"
                            print(f"  {icon} {result['target']}: No new events")
                    else:
                        print(f"  🔴 {result['target']}: ERROR - {result.get('error', 'Unknown')}")
                
                # Overall cycle statistics
                print("-" * 60)
                successful_count = sum(1 for r in results if r['success'])
                failed_count = sum(1 for r in results if not r['success'])
                total_events = sum(r.get('events_found', 0) for r in results if r['success'])
                total_alerts = sum(r.get('alerts_found', 0) for r in results if r['success'])
                
                print(f"  Targets: {successful_count}/{len(self.targets)} successful")
                print(f"  Events: {total_events} total")
                print(f"  Alerts: {total_alerts} total")
                
                if total_alerts > 0:
                    print(f"\n  🚨 SECURITY ALERTS: {total_alerts} threats detected!")
                
                # Wait for next cycle
                print(f"\n  💤 Next check in {interval_seconds} seconds...")
                print(f"  ⏹️  Press Ctrl+C to stop monitoring")
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print(f"\n\n{'='*60}")
            print("🛑 Real-Time Monitoring Stopped by User")
            print(f"{'='*60}")
            print(f"📊 Final Statistics:")
            print(f"  Total Cycles: {cycle_count}")
            print(f"  Monitored Targets: {len(self.targets)}")
            print(f"  Duration: ~{cycle_count * interval_seconds} seconds")
            print(f"{'='*60}\n")
        except Exception as e:
            print(f"\n\n{'='*60}")
            print(f"❌ Real-Time Monitoring Stopped Due to Error")
            print(f"{'='*60}")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            print()