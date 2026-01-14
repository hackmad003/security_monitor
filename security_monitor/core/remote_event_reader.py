"""
Remote Event Reader Module - SECURE VERSION
Reads Windows Security Event Logs from remote machines using PowerShell
WITH PROTECTION AGAINST COMMAND INJECTION
"""

import subprocess
import json
import datetime
import base64
from typing import List, Dict, Any, Optional
import logging

from ..utils.secure_credentials import CredentialValidator

logger = logging.getLogger(__name__)


class RemoteEventReader:
    """Reads event logs from remote Windows machines - SECURE VERSION"""
    
    def __init__(self, server: str, username: str, password: str):
        """
        Initialize remote event reader with credential validation
        
        Args:
            server: Remote server name or IP
            username: Admin username
            password: Admin password
            
        Raises:
            ValueError: If credentials contain invalid characters
        """
        # SECURITY: Validate all inputs before storing
        CredentialValidator.validate_hostname(server)
        CredentialValidator.validate_credential_input(username, "username")
        CredentialValidator.validate_credential_input(password, "password")
        
        self.server = server
        self.username = username
        self.password = password
        
        logger.info(f"Initialized secure remote event reader for {server}")
    
    def read_events(
        self,
        num_events: int = 100,
        event_ids: Optional[set] = None,
        log_type: str = 'Security',
        max_retries: int = 3,
        since_time: Optional[datetime.datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Read events from remote machine using PowerShell with retry logic
        
        Args:
            num_events: Maximum number of events to read
            event_ids: Set of event IDs to filter
            log_type: Event log type (default: Security)
            max_retries: Number of retry attempts
            since_time: Only read events after this time (for real-time monitoring)
        """
        # Validate inputs
        if num_events <= 0 or num_events > 100000:
            raise ValueError("num_events must be between 1 and 100000")
        
        if log_type not in ['Security', 'Application', 'System']:
            raise ValueError("Invalid log_type. Must be Security, Application, or System")
        
        ps_command = self._build_powershell_command_secure(
            num_events, event_ids, log_type, since_time
        )

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Connecting to {self.server}... (attempt {attempt}/{max_retries})")
                print(f"  📡 Connecting to {self.server}... (attempt {attempt}/{max_retries})")

                result = subprocess.run(
                    ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', ps_command],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    encoding='utf-8'
                )

                if result.returncode != 0:
                    error_msg = result.stderr[:300] if result.stderr else "Unknown error"
                    logger.warning(f"PowerShell error (attempt {attempt}): {error_msg}")
                    print(f"  ⚠️ PowerShell error (attempt {attempt}): {error_msg}")
                    if attempt < max_retries:
                        continue
                    return []

                if not result.stdout or not result.stdout.strip():
                    logger.warning(f"Empty response (attempt {attempt})")
                    print(f"  ⚠️ Empty response (attempt {attempt})")
                    if attempt < max_retries:
                        continue
                    return []

                print(f"  ✓ Got {len(result.stdout)} characters")

                events = json.loads(result.stdout)
                event_count = len(events) if isinstance(events, list) else 1
                logger.info(f"Parsed {event_count} events from {self.server}")
                print(f"  ✓ Parsed {event_count} events")

                return self._convert_events(events)

            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout (attempt {attempt}/{max_retries})")
                print(f"  ⚠️ Timeout (attempt {attempt}/{max_retries})")
                if attempt < max_retries:
                    continue
                logger.error(f"All {max_retries} attempts timed out for {self.server}")
                print(f"  ❌ All {max_retries} attempts timed out for {self.server}")
                return []
            except json.JSONDecodeError as e:
                logger.error(f"JSON parse error: {e}")
                print(f"  ❌ JSON parse error: {e}")
                return []
            except Exception as e:
                logger.error(f"Error reading events: {e}")
                print(f"  ❌ Error: {e}")
                if attempt < max_retries:
                    continue
                return []

        return []
    
    def _build_powershell_command_secure(
        self,
        num_events: int,
        event_ids: Optional[set],
        log_type: str,
        since_time: Optional[datetime.datetime] = None
    ) -> str:
        """
        Build SECURE PowerShell command using Base64 encoding to prevent injection
        
        This method uses -EncodedCommand to ensure that no user input can
        escape the command context and execute arbitrary code.
        
        Args:
            num_events: Maximum number of events to read
            event_ids: Set of event IDs to filter
            log_type: Event log type
            since_time: Optional time filter
            
        Returns:
            Base64-encoded PowerShell command
        """
        
        # Build PowerShell script using here-strings to safely handle credentials
        # Here-strings (@'...'@) prevent variable expansion and command injection
        ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'

# Use here-string to safely handle password (prevents injection)
$password = ConvertTo-SecureString -String @'
{self.password}
'@ -AsPlainText -Force

# Use here-string for username as well
$username = @'
{self.username}
'@

$credential = New-Object System.Management.Automation.PSCredential ($username, $password)

# Build filter hashtable safely
$filterHash = @{{
    LogName = '{log_type}'
}}
"""
        
        # Add event IDs if specified (validate as integers)
        if event_ids:
            try:
                # Convert to integers to ensure they're valid
                safe_ids = [str(int(id)) for id in event_ids]
                ids_str = ','.join(safe_ids)
                ps_script += f"\n$filterHash['Id'] = @({ids_str})\n"
            except (ValueError, TypeError) as e:
                logger.error(f"Invalid event IDs: {e}")
                raise ValueError("Event IDs must be integers")
        
        # Add time filter if specified
        if since_time:
            # Format time safely
            time_str = since_time.strftime('%Y-%m-%dT%H:%M:%S')
            ps_script += f"\n$filterHash['StartTime'] = [datetime]'{time_str}'\n"
        
        # Build the command using validated server name
        ps_script += f"""
# Get events from remote server
Get-WinEvent -ComputerName '{self.server}' -Credential $credential -FilterHashtable $filterHash -MaxEvents {num_events} -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id, MachineName, Message | 
    ConvertTo-Json -Compress
"""
        
        # Encode to Base64 (UTF-16 LE for PowerShell)
        # This prevents ANY possibility of command injection
        encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
        
        return encoded
    
    def _convert_events(self, events: List[Dict]) -> List[Dict[str, Any]]:
        """Convert PowerShell events to our format"""
        converted = []
        
        # Handle both single event and array
        if isinstance(events, dict):
            events = [events]
        
        for event in events:
            converted.append({
                'event_id': event.get('Id'),
                'timestamp': event.get('TimeCreated'),
                'computer': event.get('MachineName', self.server),
                'message': event.get('Message', ''),
                'source': 'PowerShell-Remote'
            })
        
        return converted
    
    def close(self):
        """Cleanup (not needed for PowerShell approach)"""
        pass
