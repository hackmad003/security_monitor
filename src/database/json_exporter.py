"""
JSON Exporter Module
Exports security reports to JSON files
"""

import json
import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class WeeklyJSONExporter:
    """Exports security alerts to weekly consolidated JSON files"""

    @staticmethod
    def get_week_filename() -> str:
        """Get filename based on current week: security_report_2025_W01.json"""
        now = datetime.datetime.now()
        year, week_num, _ = now.isocalendar()
        return f"security_report_{year}_W{week_num:02d}.json"

    @staticmethod
    def export_weekly_report(
        alerts: List[Dict[str, Any]],
        output_dir: Optional[str] = None
    ) -> bool:
        """
        Export alerts to weekly consolidated JSON file.
        Appends to existing file if it exists.

        Args:
            alerts: List of alert dictionaries
            output_dir: Output directory (defaults to data/reports/)

        Returns:
            True if successful
        """
        if not alerts:
            return True

        try:
            # Default to data/reports/ in project root
            if output_dir is None:
                output_path = Path(__file__).parent.parent.parent / "data" / "reports"
            else:
                output_path = Path(output_dir)

            output_path.mkdir(parents=True, exist_ok=True)

            filename = WeeklyJSONExporter.get_week_filename()
            filepath = output_path / filename

            # Load existing data or create new
            if filepath.exists():
                with open(filepath, 'r') as f:
                    report = json.load(f)
            else:
                now = datetime.datetime.now()
                year, week_num, _ = now.isocalendar()
                report = {
                    'week': f"{year}-W{week_num:02d}",
                    'created': datetime.datetime.now().isoformat(),
                    'last_updated': None,
                    'alerts': [],
                    'summary': {
                        'total_alerts': 0,
                        'high_severity': 0,
                        'medium_severity': 0,
                        'low_severity': 0,
                        'targets_affected': []
                    }
                }

            # Append new alerts
            report['alerts'].extend(alerts)
            report['last_updated'] = datetime.datetime.now().isoformat()

            # Update summary
            all_alerts = report['alerts']
            targets = set(a.get('target', a.get('computer', 'Unknown')) for a in all_alerts)
            report['summary'] = {
                'total_alerts': len(all_alerts),
                'high_severity': len([a for a in all_alerts if a.get('severity') == 'HIGH']),
                'medium_severity': len([a for a in all_alerts if a.get('severity') == 'MEDIUM']),
                'low_severity': len([a for a in all_alerts if a.get('severity') == 'LOW']),
                'targets_affected': list(targets)
            }

            # Write back
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)

            print(f"  📄 Saved to {filename} ({len(alerts)} new alerts)")
            return True

        except Exception as e:
            print(f"  ⚠️ Weekly JSON export failed: {e}")
            return False


class JSONExporter:
    """Exports security analysis results to JSON format"""
    
    @staticmethod
    def export_report(
        alerts: List[Dict[str, Any]],
        filename: str = 'security_report.json',
        output_dir: str = '.'
    ) -> bool:
        """
        Export security report to JSON file
        
        Args:
            alerts: List of alert dictionaries
            filename: Output filename
            output_dir: Output directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create output directory if it doesn't exist
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Full file path
            filepath = output_path / filename

            #print(f"🔍 DEBUG: Full filepath = {filepath}")  # ← ADD THIS
            #print(f"🔍 DEBUG: Absolute path = {filepath.absolute()}")  # ← ADD THIS
            
            # Create report structure
            report = {
                'timestamp': datetime.datetime.now().isoformat(),
                'alerts': alerts,
                'summary': {
                    'total_alerts': len(alerts),
                    'high_severity': len([a for a in alerts if a.get('severity') == 'HIGH']),
                    'medium_severity': len([a for a in alerts if a.get('severity') == 'MEDIUM']),
                    'low_severity': len([a for a in alerts if a.get('severity') == 'LOW'])
                }
            }
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"✓ Report exported to {filepath}")
            return True
            
        except Exception as e:
            print(f"❌ Export error: {e}")
            return False
    
    @staticmethod
    def export_events(
        events: List[Dict[str, Any]],
        filename: str = 'security_events.json',
        output_dir: str = '.'
    ) -> bool:
        """
        Export security events to JSON file
        
        Args:
            events: List of event dictionaries
            filename: Output filename
            output_dir: Output directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            filepath = output_path / filename
            
            export_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'event_count': len(events),
                'events': events
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"✓ Events exported to {filepath}")
            return True
            
        except Exception as e:
            print(f"❌ Export error: {e}")
            return False