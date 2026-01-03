"""
Configuration Management Module
Handles loading and managing configuration from multiple sources
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv


class Config:
    """Centralized configuration management"""
    
    def __init__(self, config_path: Optional[str] = None, env_path: Optional[str] = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to YAML configuration file
            env_path: Path to .env file
        """
        self._config: Dict[str, Any] = {}
        
        # Load .env file
        if env_path:
            load_dotenv(env_path)
        else:
            load_dotenv()
        
        # Load YAML configuration
        if config_path:
            self._load_yaml_config(config_path)
        else:
            # Try default locations (config is now in src/config/)
            default_paths = [
                Path(__file__).parent.parent / "config" / "settings.yaml",  # src/config/
                Path("src/config/settings.yaml"),
                Path("config/settings.yaml"),
                Path("settings.yaml")
            ]
            for path in default_paths:
                if path.exists():
                    self._load_yaml_config(str(path))
                    break
    
    def _load_yaml_config(self, path: str) -> None:
        """Load configuration from YAML file"""
        try:
            with open(path, 'r') as f:
                self._config = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Could not load config from {path}: {e}")
            self._config = {}
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get nested config value using dot notation
        
        Args:
            key: Dot-separated key (e.g., 'credentials.username')
            default: Default value if key not found
            
        Returns:
            Config value or default
        """
        import yaml
        from pathlib import Path
        
        # Load targets.yaml for credentials (in config/app/)
        targets_path = Path(__file__).parent.parent.parent / "config" / "app" / "targets.yaml"
        
        if not targets_path.exists():
            return default
        
        try:
            with open(targets_path, 'r') as f:
                targets_data = yaml.safe_load(f)
            
            # Navigate nested keys
            keys = key.split('.')
            value = targets_data
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
            
        except Exception:
            return default
    
    def get_env(self, key: str, default: Any = None) -> Any:
        """
        Get environment variable with type conversion
        
        Args:
            key: Environment variable name
            default: Default value if not found
            
        Returns:
            Environment variable value with appropriate type
        """
        value = os.getenv(key, default)
        
        # Type conversion for common cases
        if isinstance(value, str):
            if value.lower() in ('true', 'yes', '1'):
                return True
            elif value.lower() in ('false', 'no', '0'):
                return False
            elif value.isdigit():
                return int(value)
        
        return value
    
    # ==========================================
    # MONGODB CONFIGURATION
    # ==========================================
    @property
    def mongodb_uri(self) -> str:
        """Get MongoDB connection URI"""
        return self.get_env('MONGODB_URI', 'mongodb://localhost:27017/')
    
    @property
    def mongodb_database(self) -> str:
        """Get MongoDB database name"""
        return self.get_env('MONGODB_DATABASE', 'security_monitor')
    
    # ==========================================
    # EMAIL CONFIGURATION
    # ==========================================
    @property
    def email_enabled(self) -> bool:
        """Check if email alerts are enabled"""
        return self.get_env('EMAIL_ENABLED', False)
    
    @property
    def smtp_server(self) -> str:
        """Get SMTP server address"""
        return self.get_env('SMTP_SERVER', 'smtp.gmail.com')
    
    @property
    def smtp_port(self) -> int:
        """Get SMTP server port"""
        return int(self.get_env('SMTP_PORT', 587))
    
    @property
    def sender_email(self) -> str:
        """Get sender email address"""
        return self.get_env('SENDER_EMAIL', '')
    
    @property
    def sender_password(self) -> str:
        """Get sender email password"""
        return self.get_env('SENDER_PASSWORD', '')
    
    @property
    def recipient_emails(self) -> list:
        """Get list of recipient email addresses"""
        emails = self.get_env('RECIPIENT_EMAILS', '')
        return [e.strip() for e in emails.split(',') if e.strip()]
    
    # ==========================================
    # SPLUNK CONFIGURATION
    # ==========================================
    @property
    def splunk_enabled(self) -> bool:
        """Check if Splunk integration is enabled"""
        return self.get_env('SPLUNK_ENABLED', False)
    
    @property
    def splunk_hec_url(self) -> str:
        """Get Splunk HTTP Event Collector URL"""
        return self.get_env('SPLUNK_HEC_URL', 'https://localhost:8088/services/collector/event')
    
    @property
    def splunk_hec_token(self) -> str:
        """Get Splunk HEC authentication token"""
        return self.get_env('SPLUNK_HEC_TOKEN', '')
    
    @property
    def splunk_index(self) -> str:
        """Get Splunk index name"""
        return self.get_env('SPLUNK_INDEX', 'main')
    
    @property
    def splunk_sourcetype(self) -> str:
        """Get Splunk sourcetype"""
        return self.get_env('SPLUNK_SOURCETYPE', 'windows_security_monitor')
    
    @property
    def splunk_verify_ssl(self) -> bool:
        """Check if SSL verification is enabled for Splunk"""
        return self.get_env('SPLUNK_VERIFY_SSL', False)
    
    # ==========================================
    # EVENT LOG CONFIGURATION
    # ==========================================
    @property
    def event_log_server(self) -> str:
        """Get event log server name"""
        return self.get('event_log.server', 'localhost')
    
    @property
    def event_log_type(self) -> str:
        """Get event log type"""
        return self.get('event_log.log_type', 'Security')
    
    @property
    def critical_events(self) -> Dict[int, str]:
        """Get critical event IDs to monitor"""
        return self.get('critical_events', {
            4625: "Failed Login Attempt",
            4624: "Successful Login",
            4720: "User Account Created",
            4672: "Admin Privileges Assigned",
            4698: "Scheduled Task Created",
            4688: "Process Created",
            4663: "File Access Attempt",
            4648: "Login with Explicit Credentials"
        })
    
    # ==========================================
    # DETECTION CONFIGURATION
    # ==========================================
    @property
    def brute_force_threshold(self) -> int:
        """Get brute force detection threshold"""
        return int(self.get_env('BRUTE_FORCE_THRESHOLD', 
                                 self.get('detection.brute_force_threshold', 2)))
    
    @property
    def alert_reset_interval_hours(self) -> int:
        """Get alert reset interval in hours"""
        return int(self.get_env('ALERT_RESET_INTERVAL_HOURS',
                                 self.get('detection.alert_reset_interval_hours', 1)))
    
    # ==========================================
    # MONITORING CONFIGURATION
    # ==========================================
    @property
    def default_event_count(self) -> int:
        """Get default number of events to analyze"""
        return self.get('monitoring.default_event_count', 5000)
    
    @property
    def realtime_interval_seconds(self) -> int:
        """Get real-time monitoring check interval"""
        return int(self.get_env('REALTIME_INTERVAL_SECONDS',
                                 self.get('monitoring.realtime_interval_seconds', 10)))
    
    @property
    def events_per_check(self) -> int:
        """Get number of events to check per cycle"""
        return int(self.get_env('EVENTS_PER_CHECK',
                                 self.get('monitoring.events_per_check', 5000)))
    
    # ==========================================
    # REPORTING CONFIGURATION
    # ==========================================
    @property
    def default_export_filename(self) -> str:
        """Get default export filename"""
        return self.get('reporting.default_export_filename', 'security_report.json')
    
    @property
    def statistics_days(self) -> int:
        """Get number of days for statistics"""
        return self.get('reporting.statistics_days', 7)