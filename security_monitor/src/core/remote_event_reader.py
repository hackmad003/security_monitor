"""
Remote Event Reader Module
Reads Windows Security Event Logs from remote machines using PowerShell
"""

import subprocess
import json
import datetime
from typing import List, Dict, Any, Optional


class RemoteEventReader:
    """Reads event logs from remote Windows machines"""
    
    def __init__(self, server: str, username: str, password: str):
        """
        Initialize remote event reader
        
        Args:
            server: Remote server name or IP
            username: Admin username
            password: Admin password
        """
        self.server = server
        self.username = username
        self.password = password
    
    def read_events(
        self,
        num_events: int = 100,
        event_ids: set = None,
        log_type: str = 'Security',
        max_retries: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Read events from remote machine using PowerShell with retry logic
        """
        ps_command = self._build_powershell_command(num_events, event_ids, log_type)

        for attempt in range(1, max_retries + 1):
            try:
                print(f"  📡 Connecting to {self.server}... (attempt {attempt}/{max_retries})")

                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command', ps_command],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    encoding='utf-8'
                )

                if result.returncode != 0:
                    error_msg = result.stderr[:300] if result.stderr else "Unknown error"
                    print(f"  ⚠️ PowerShell error (attempt {attempt}): {error_msg}")
                    if attempt < max_retries:
                        continue
                    return []

                if not result.stdout or not result.stdout.strip():
                    print(f"  ⚠️ Empty response (attempt {attempt})")
                    if attempt < max_retries:
                        continue
                    return []

                print(f"  ✓ Got {len(result.stdout)} characters")

                events = json.loads(result.stdout)
                event_count = len(events) if isinstance(events, list) else 1
                print(f"  ✓ Parsed {event_count} events")

                return self._convert_events(events)

            except subprocess.TimeoutExpired:
                print(f"  ⚠️ Timeout (attempt {attempt}/{max_retries})")
                if attempt < max_retries:
                    continue
                print(f"  ❌ All {max_retries} attempts timed out for {self.server}")
                return []
            except json.JSONDecodeError as e:
                print(f"  ❌ JSON parse error: {e}")
                return []
            except Exception as e:
                print(f"  ❌ Error: {e}")
                if attempt < max_retries:
                    continue
                return []

        return []
    
    def _build_powershell_command(
        self,
        num_events: int,
        event_ids: Optional[set],
        log_type: str
    ) -> str:
        """Build PowerShell command to read events"""

        # Build credentials
        cred_setup = (
            f"$password = ConvertTo-SecureString '{self.password}' -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential ('{self.username}', $password); "
        )

        # Use FilterHashtable for much better performance (filters at source)
        if event_ids:
            event_id_list = ','.join(str(id) for id in event_ids)
            # FilterHashtable is 10x faster than Where-Object
            filter_hash = f"@{{LogName='{log_type}'; Id={event_id_list}}}"
            get_events = f"Get-WinEvent -ComputerName {self.server} -Credential $cred -FilterHashtable {filter_hash} -MaxEvents {num_events} -ErrorAction SilentlyContinue"
        else:
            get_events = f"Get-WinEvent -ComputerName {self.server} -Credential $cred -LogName {log_type} -MaxEvents {num_events} -ErrorAction SilentlyContinue"

        ps_command = (
            f"{cred_setup}"
            f"{get_events} | "
            f"Select-Object TimeCreated, Id, MachineName, Message | "
            f"ConvertTo-Json -Compress"
        )

        return ps_command
    
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