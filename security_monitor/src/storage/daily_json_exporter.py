"""
Daily JSON Exporter Module
Maintains one JSON report per day with all alerts appended
"""

import json
import datetime
from typing import List, Dict, Any
from pathlib import Path


class DailyJSONExporter:
    """Exports security alerts to daily JSON reports"""
    
    @staticmethod
    def export_daily_report(
        alerts: List[Dict[str, Any]],
        output_dir: str = '.'
    ) -> bool:
        """
        Export alerts to daily JSON report (appends to existing)
        
        Args:
            alerts: List of alert dictionaries
            output_dir: Output directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create output directory if it doesn't exist
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Daily filename (no timestamp)
            today = datetime.datetime.now().strftime('%Y%m%d')
            filename = f'security_report_{today}.json'
            filepath = output_path / filename
            
            # Load existing report if it exists
            if filepath.exists():
                with open(filepath, 'r') as f:
                    report = json.load(f)
                
                # Append new alerts
                report['alerts'].extend(alerts)
                
                # Update summary
                all_alerts = report['alerts']
                report['summary'] = {
                    'total_alerts': len(all_alerts),
                    'high_severity': len([a for a in all_alerts if a.get('severity') == 'HIGH']),
                    'medium_severity': len([a for a in all_alerts if a.get('severity') == 'MEDIUM']),
                    'low_severity': len([a for a in all_alerts if a.get('severity') == 'LOW'])
                }
                report['last_updated'] = datetime.datetime.now().isoformat()
            else:
                # Create new report
                report = {
                    'date': today,
                    'created': datetime.datetime.now().isoformat(),
                    'last_updated': datetime.datetime.now().isoformat(),
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
            
            print(f"✓ Daily report updated: {filepath}")
            return True
            
        except Exception as e:
            print(f"❌ Export error: {e}")
            return False