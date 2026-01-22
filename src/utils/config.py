"""
Configuration Management Module
Handles loading and managing configuration from multiple sources
WITH SECURE CREDENTIAL STORAGE
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv
import logging

from .secure_credentials import SecureCredentialStore

logger = logging.getLogger(__name__)


class Config:
    """Centralized configuration management with secure credential storage"""
    
    def __init__(self, config_path: Optional[str] = None, env_path: Optional[str] = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to YAML configuration file
            env_path: Path to .env file
        """
        self._config: Dict[str, Any] = {}
        
        # Initialize secure credential store
        self.credential_store = SecureCredentialStore()
        
        # Load .env file
        if env_path:
            load_dotenv(env_path)
        else:
            load_dotenv()
        
        # Load YAML configuration
        if config_path:
            self._load_yaml_config(config_path)
        else:
            # Try default locations
            default_paths = [
                Path(__file__).parent.parent.parent / "config" / "app" / "settings.yaml",  # security_monitor/config/app/
                Path("config/app/settings.yaml"),
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
                loaded = yaml.safe_load(f)
                self._config = loaded if isinstance(loaded, dict) else {}
        except Exception as e:
            print(f"Warning: Could not load config from {path}: {e}")
            self._config = {}
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get nested config value using dot notation from settings.yaml
        
        Args:
            key: Dot-separated key (e.g., 'detectors.brute_force.enabled')
            default: Default value if key not found
            
        Returns:
            Config value or default
        """
        # Navigate nested keys in self._config (loaded from settings.yaml)
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_target_config(self, key: str, default: Any = None) -> Any:
        """
        Get nested config value from targets.yaml (for credentials)
        
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
                                 self.get('detectors.brute_force.threshold', 
                                         self.get('detection.brute_force_threshold', 2))))
    
    @property
    def alert_reset_interval_hours(self) -> int:
        """Get alert reset interval in hours"""
        return int(self.get_env('ALERT_RESET_INTERVAL_HOURS',
                                 self.get('detection.alert_reset_interval_hours', 1)))
    
    # ==========================================
    # DETECTOR ENABLE/DISABLE CONFIGURATION
    # ==========================================
    @property
    def detector_brute_force_enabled(self) -> bool:
        """Check if brute force detector is enabled"""
        return bool(self.get('detectors.brute_force.enabled', True))
    
    @property
    def detector_privilege_escalation_enabled(self) -> bool:
        """Check if privilege escalation detector is enabled"""
        return bool(self.get('detectors.privilege_escalation.enabled', True))
    
    @property
    def detector_persistence_enabled(self) -> bool:
        """Check if persistence detector is enabled"""
        return bool(self.get('detectors.persistence.enabled', True))
    
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
    
    # ==========================================
    # SECURE CREDENTIAL MANAGEMENT
    # ==========================================
    def get_target_credentials(self, target_name: str) -> Dict[str, str]:
        """
        Get credentials for a target from secure storage or environment
        
        Priority order:
        1. Secure encrypted storage
        2. Environment variables
        3. Legacy targets.yaml (with warning)
        
        Args:
            target_name: Name of the target system
            
        Returns:
            Dictionary with 'username' and 'password' keys
            
        Raises:
            ValueError: If no credentials found for target
        """
        # Try secure credential store first (RECOMMENDED)
        creds = self.credential_store.get_credentials(target_name)
        if creds:
            logger.debug(f"Loaded credentials for {target_name} from secure storage")
            return creds
        
        # Try environment variables (target_name_USERNAME, target_name_PASSWORD)
        env_prefix = target_name.upper().replace('-', '_').replace('.', '_')
        username = os.getenv(f"{env_prefix}_USERNAME")
        password = os.getenv(f"{env_prefix}_PASSWORD")
        
        if username and password:
            logger.debug(f"Loaded credentials for {target_name} from environment variables")
            return {'username': username, 'password': password}
        
        # Fallback to legacy targets.yaml (DEPRECATED - shows warning)
        legacy_creds = self._get_legacy_credentials(target_name)
        if legacy_creds:
            logger.warning(
                f"⚠️  SECURITY WARNING: Loading credentials for {target_name} from plaintext YAML file. "
                "Please migrate to secure storage using the migration script."
            )
            return legacy_creds
        
        raise ValueError(
            f"No credentials found for target '{target_name}'. "
            "Please configure credentials using environment variables or secure storage."
        )
    
    def _get_legacy_credentials(self, target_name: str) -> Optional[Dict[str, str]]:
        """
        Get credentials from legacy targets.yaml file (DEPRECATED)
        
        This method is provided for backward compatibility only.
        Users should migrate to secure credential storage.
        
        Args:
            target_name: Name of the target system
            
        Returns:
            Dictionary with 'username' and 'password', or None if not found
        """
        targets_path = Path(__file__).parent.parent.parent / "config" / "app" / "targets.yaml"
        
        if not targets_path.exists():
            return None
        
        try:
            with open(targets_path, 'r') as f:
                targets_data = yaml.safe_load(f)

            if not isinstance(targets_data, dict) or 'targets' not in targets_data:
                return None

            # Find target in list
            targets_list = targets_data.get('targets', [])
            if not isinstance(targets_list, list):
                return None

            for target in targets_list:
                if isinstance(target, dict) and target.get('name') == target_name:
                    creds = target.get('credentials', {})
                    if isinstance(creds, dict) and 'username' in creds and 'password' in creds:
                        return {
                            'username': creds['username'],
                            'password': creds['password']
                        }

            return None
            
        except Exception as e:
            logger.error(f"Error reading legacy credentials: {e}")
            return None
    
    def store_target_credentials(self, target_name: str, username: str, password: str):
        """
        Store credentials securely for a target
        
        Args:
            target_name: Name of the target system
            username: Username for authentication
            password: Password for authentication
        """
        self.credential_store.store_credentials(target_name, username, password)
        logger.info(f"Stored credentials for target: {target_name}")
    
    def delete_target_credentials(self, target_name: str) -> bool:
        """
        Delete stored credentials for a target
        
        Args:
            target_name: Name of the target system
            
        Returns:
            True if credentials were deleted, False if not found
        """
        result = self.credential_store.delete_credentials(target_name)
        if result:
            logger.info(f"Deleted credentials for target: {target_name}")
        return result
    
    def list_stored_targets(self) -> list:
        """
        Get list of targets with stored credentials
        
        Returns:
            List of target names
        """
        return self.credential_store.list_targets()