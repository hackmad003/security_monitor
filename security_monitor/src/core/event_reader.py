"""
Event Reader Module
Handles reading and parsing Windows Event Logs
"""

import win32evtlog
import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict


class EventReader:
    """Reads and parses Windows Security Event Logs"""
    
    def __init__(self, server: str = 'localhost', log_type: str = 'Security'):
        """
        Initialize Event Reader
        
        Args:
            server: Server name (default: localhost)
            log_type: Event log type (default: Security)
        """
        self.server = server
        self.log_type = log_type
        self.handle = None
        self.flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        self._open_log()
    
    def _open_log(self) -> None:
        """Open event log handle"""
        try:
            self.handle = win32evtlog.OpenEventLog(self.server, self.log_type)
        except Exception as e:
            raise RuntimeError(f"Failed to open event log: {e}")
    
    def close(self) -> None:
        """Close event log handle"""
        if self.handle:
            win32evtlog.CloseEventLog(self.handle)
            self.handle = None
    
    def read_events(
        self, 
        num_events: int = 5000, 
        event_ids: Optional[set] = None
    ) -> List[Dict[str, Any]]:
        """
        Read events from Windows Event Log
        
        Args:
            num_events: Maximum number of events to read
            event_ids: Set of event IDs to filter (None = all events)
            
        Returns:
            List of parsed event dictionaries
        """
        events = []
        all_events = []
        
        try:
            total = 0
            
            while total < num_events:
                events_batch = win32evtlog.ReadEventLog(self.handle, self.flags, 0)
                
                if not events_batch:
                    break
                
                for event in events_batch:
                    if total >= num_events:
                        break
                    
                    # Track all events for diagnostics (use masked ID)
                    all_events.append({
                        'event_id': event.EventID & 0xFFFF,
                        'timestamp': event.TimeGenerated.Format(),
                        'source': event.SourceName
                    })
                    
                    # Filter by event IDs if specified
                    # Mask to lower 16 bits - Windows adds qualifier bits to upper 16
                    masked_id = event.EventID & 0xFFFF
                    if event_ids is None or masked_id in event_ids:
                        events.append(self._parse_event(event))
                    
                    total += 1
                
                if len(events_batch) == 0:
                    break
            
            # Print diagnostics
            if event_ids and all_events:
                self._print_diagnostics(all_events, len(events))
        
        except Exception as e:
            print(f"Error reading events: {e}")
        
        return events
    
    def read_events_since(
        self, 
        since_time: datetime.datetime, 
        max_events: int = 1000,
        event_ids: Optional[set] = None
    ) -> List[Dict[str, Any]]:
        """
        Read events after a specific time
        
        Args:
            since_time: Read events after this time
            max_events: Maximum number of events to read
            event_ids: Set of event IDs to filter
            
        Returns:
            List of parsed event dictionaries
        """
        events = []
        
        try:
            # Reopen handle to reset cursor
            self._open_log()
            
            total = 0
            
            while total < max_events:
                events_batch = win32evtlog.ReadEventLog(self.handle, self.flags, 0)
                
                if not events_batch:
                    break
                
                for event in events_batch:
                    if total >= max_events:
                        break
                    
                    # Get event time
                    event_time = event.TimeGenerated
                    event_datetime = datetime.datetime(
                        event_time.year, event_time.month, event_time.day,
                        event_time.hour, event_time.minute, event_time.second
                    )
                    
                    total += 1
                    
                    # Only include events after cutoff
                    if event_datetime > since_time:
                        masked_id = event.EventID & 0xFFFF
                        if event_ids is None or masked_id in event_ids:
                            events.append(self._parse_event(event))
                    else:
                        # Hit old events, stop reading
                        return events
                
                if len(events_batch) == 0:
                    break
        
        except Exception as e:
            print(f"Error reading events: {e}")
            # Try to reopen handle
            try:
                self._open_log()
            except:
                pass
        
        return events
    
    def _parse_event(self, event) -> Dict[str, Any]:
        """
        Parse raw Windows event into dictionary

        Args:
            event: Raw Windows Event Object

        Returns:
            Parsed event dictionary
        """
        return {
            'timestamp': event.TimeGenerated.Format(),
            'event_id': event.EventID & 0xFFFF,  # Mask to get actual event ID
            'computer': event.ComputerName,
            'source': event.SourceName,
            'category': event.EventCategory
        }
    
    def _print_diagnostics(self, all_events: List[Dict], filtered_count: int) -> None:
        """Print diagnostic information about scanned events"""
        print(f"📊 Scanned {len(all_events)} total events in Security log")
        
        # Count event IDs
        event_id_counts = defaultdict(int)
        for evt in all_events:
            event_id_counts[evt['event_id']] += 1
        
        # Show top 5
        top_events = sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"   Top Event IDs found: {top_events}")
        print(f"   Filtered to {filtered_count} relevant events\n")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()