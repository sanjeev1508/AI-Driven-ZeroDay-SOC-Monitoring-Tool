"""
Agent 1 - Unified Log Collector + Normalizer

Collects Windows Event Logs directly from the local machine, filters to
security-relevant events, normalizes them, and writes both raw and normalized
entries to CSV files (no Kafka required).
"""

import json
import time
import logging
import csv
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List

import win32evtlog
import win32evtlogutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent


class LogCollectorAgent:
    """Collects and normalizes Windows Event Logs, writing to CSV outputs."""
    
    def __init__(
        self,
        raw_csv_path: str = None,
        normalized_csv_path: str = None,
        timeframe_hours: int = 5,
    ):
        self.log_types = ['System', 'Application', 'Security']
        self.server = 'localhost'
        self.flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        self.last_record_numbers: Dict[str, int] = {}
        
        # Sensitive/security-relevant event ids (used to drop unwanted noise)
        self.security_event_ids = {
            4624: 'Successful logon',
            4625: 'Failed logon',
            4672: 'Special privileges assigned',
            4688: 'Process creation',
            4697: 'Service installation',
            4698: 'Scheduled task creation',
            4700: 'Scheduled task enabled',
            4702: 'Scheduled task updated',
            4719: 'System audit policy changed',
            4732: 'Member added to security-enabled local group',
            4738: 'User account changed',
            4740: 'User account locked out',
            4768: 'Kerberos authentication ticket requested',
            4769: 'Kerberos service ticket requested',
            4776: 'Domain controller attempted to validate credentials',
            5140: 'Network share object accessed',
            5142: 'Network share object added',
            5143: 'Network share object modified',
            5144: 'Network share object deleted',
            # System driver load
            6: 'Driver load',
        }
        
        # Suspicious process list reused for behavior features
        self.suspicious_processes = [
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'
        ]
        
        # CSV paths
        self.raw_csv_path = Path(raw_csv_path) if raw_csv_path else BASE_DIR / "raw_logs.csv"
        self.normalized_csv_path = Path(normalized_csv_path) if normalized_csv_path else BASE_DIR / "filtered_logs.csv"
        self.raw_csv_initialized = False
        self.normalized_csv_initialized = False
        self.raw_csv_writer = None
        self.normalized_csv_writer = None
        self.raw_csv_handle = None
        self.normalized_csv_handle = None
        
        # Timeframe filter
        self.timeframe_hours = timeframe_hours
        self.start_time = datetime.now() - timedelta(hours=self.timeframe_hours)
        
        # Prepare CSVs
        self._init_raw_csv()
        self._init_normalized_csv()
        
    def extract_xml_event_data(self, event: Any) -> Dict[str, Any]:
        """
        Extract full XML EventData from Windows Event Log.
        This is critical - StringInserts only give ~30% of the information.
        Uses win32evtlog.EvtRender to get full XML representation.
        """
        event_data = {}
        
        try:
            # Method 1: Try to get EventData directly from event object
            # For modern Windows Event Log (Vista+), EventData is available
            if hasattr(event, 'EventData') and event.EventData:
                # EventData can be a list of dictionaries or tuples
                for item in event.EventData:
                    if isinstance(item, dict):
                        event_data.update(item)
                    elif isinstance(item, tuple) and len(item) == 2:
                        event_data[item[0]] = item[1]
                    elif isinstance(item, str):
                        # Sometimes EventData contains string representations
                        try:
                            parsed = json.loads(item)
                            if isinstance(parsed, dict):
                                event_data.update(parsed)
                        except:
                            pass
            
            # Method 2: Use win32evtlogutil to get formatted message
            # This gives us the human-readable message which contains structured data
            try:
                formatted_msg = win32evtlogutil.SafeFormatMessage(event, log_type=event.LogName)
                if formatted_msg:
                    # Store formatted message for reference
                    event_data['_formatted_message'] = formatted_msg
                    
                    # Try to extract key-value pairs from formatted message
                    # Windows Event Log messages often contain structured information
                    lines = formatted_msg.split('\n')
                    for line in lines:
                        if ':' in line:
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                key = parts[0].strip()
                                value = parts[1].strip()
                                if key and value:
                                    event_data[key] = value
            except Exception as e:
                logger.debug(f"Could not format message: {e}")
            
            # Method 3: Try to get XML representation using EvtRender
            # This requires additional Windows API calls
            try:
                import win32evtlog
                # For XML rendering, we'd need to use EvtRender, but it's complex
                # For now, we rely on EventData and formatted message
                pass
            except Exception as e:
                logger.debug(f"Could not render XML: {e}")
            
        except Exception as e:
            logger.warning(f"Error extracting XML EventData: {e}")
            event_data['_extraction_error'] = str(e)
        
        # Fallback to StringInserts if EventData extraction failed
        if not event_data and hasattr(event, 'StringInserts') and event.StringInserts:
            for idx, insert in enumerate(event.StringInserts):
                event_data[f"StringInsert_{idx}"] = str(insert)
        
        # Always include StringInserts as backup even if we have EventData
        if hasattr(event, 'StringInserts') and event.StringInserts:
            for idx, insert in enumerate(event.StringInserts):
                if f"StringInsert_{idx}" not in event_data:
                    event_data[f"StringInsert_{idx}"] = str(insert)
        
        return event_data
    
    def _init_raw_csv(self):
        """Initialize raw CSV file with headers."""
        try:
            self.raw_csv_path.parent.mkdir(parents=True, exist_ok=True)
            file_exists = self.raw_csv_path.exists()
            self.raw_csv_handle = open(self.raw_csv_path, 'a', newline='', encoding='utf-8')
            self.raw_csv_writer = csv.DictWriter(
                self.raw_csv_handle,
                fieldnames=[
                    'timestamp', 'log_type', 'source_name', 'event_id', 'event_type',
                    'event_category', 'record_number', 'computer_name',
                    'raw_message', 'event_data_json'
                ],
            )
            if not file_exists:
                self.raw_csv_writer.writeheader()
                self.raw_csv_handle.flush()
            self.raw_csv_initialized = True
            logger.info(f"Raw CSV logging initialized: {self.raw_csv_path}")
        except Exception as e:
            logger.error(f"Failed to initialize raw CSV file: {e}")
            self.raw_csv_initialized = False
    
    def _init_normalized_csv(self):
        """Initialize normalized CSV file with headers."""
        try:
            self.normalized_csv_path.parent.mkdir(parents=True, exist_ok=True)
            file_exists = self.normalized_csv_path.exists()
            self.normalized_csv_handle = open(self.normalized_csv_path, 'a', newline='', encoding='utf-8')
            self.normalized_csv_writer = csv.DictWriter(
                self.normalized_csv_handle,
                fieldnames=[
                    'timestamp', 'provider', 'event_id', 'event_type', 'log_type',
                    'computer_name', 'record_number', 'event_description', 'keywords',
                    'behavior_features_json', 'raw_message'
                ],
            )
            if not file_exists:
                self.normalized_csv_writer.writeheader()
                self.normalized_csv_handle.flush()
            self.normalized_csv_initialized = True
            logger.info(f"Normalized CSV logging initialized: {self.normalized_csv_path}")
        except Exception as e:
            logger.error(f"Failed to initialize normalized CSV file: {e}")
            self.normalized_csv_initialized = False
    
    def _should_include_log(self, log_entry: Dict[str, Any]) -> bool:
        """
        Filter to keep only recent, security-relevant events.
        Drops unwanted/noisy logs outside the timeframe or not in the sensitive list.
        """
        try:
            log_timestamp_str = log_entry.get('timestamp', '')
            if not log_timestamp_str:
                return False
            
            # Parse timestamp
            if isinstance(log_timestamp_str, str):
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%m/%d/%Y %H:%M:%S']:
                    try:
                        log_timestamp = datetime.strptime(log_timestamp_str, fmt)
                        break
                    except Exception:
                        continue
                else:
                    try:
                        log_timestamp = datetime.fromisoformat(log_timestamp_str.replace('Z', '+00:00'))
                    except Exception:
                        log_timestamp = datetime.now()
            else:
                log_timestamp = log_timestamp_str
            
            current_time = datetime.now()
            time_diff = current_time - log_timestamp
            if not (timedelta(seconds=0) <= time_diff <= timedelta(hours=self.timeframe_hours)):
                return False
            
            # Security relevance filter
            event_id = log_entry.get('event_id', 0)
            log_type = log_entry.get('log_type', '')
            is_sensitive_id = event_id in self.security_event_ids
            is_security_log = log_type.lower() == 'security'
            
            # Also keep process creations that involve suspicious processes
            event_data = log_entry.get('event_data', {}) or {}
            process_name = str(event_data.get('ProcessName', '')).lower()
            suspicious_process = any(sp in process_name for sp in self.suspicious_processes)
            
            return is_sensitive_id or is_security_log or suspicious_process
        except Exception as e:
            logger.debug(f"Error filtering log: {e}")
            return True  # Fail-open to avoid losing potentially important data
    
    def _write_raw_csv(self, log_entry: Dict[str, Any]):
        """Write the raw log entry to CSV."""
        if not self.raw_csv_initialized or not self.raw_csv_writer:
            return
        
        try:
            event_data_json = json.dumps(log_entry.get('event_data', {}), ensure_ascii=False)
            csv_row = {
                'timestamp': log_entry.get('timestamp', ''),
                'log_type': log_entry.get('log_type', ''),
                'source_name': log_entry.get('source_name', ''),
                'event_id': log_entry.get('event_id', 0),
                'event_type': log_entry.get('event_type', 0),
                'event_category': log_entry.get('event_category', 0),
                'record_number': log_entry.get('record_number', 0),
                'computer_name': log_entry.get('computer_name', ''),
                'raw_message': log_entry.get('raw_message', '')[:500],
                'event_data_json': event_data_json[:2000],
            }
            self.raw_csv_writer.writerow(csv_row)
            self.raw_csv_handle.flush()
        except Exception as e:
            logger.error(f"Error writing raw log to CSV: {e}")
    
    def _write_normalized_csv(self, normalized_log: Dict[str, Any]):
        """Write the normalized log entry to CSV."""
        if not self.normalized_csv_initialized or not self.normalized_csv_writer:
            return
        
        try:
            behavior_features_json = json.dumps(normalized_log.get('behavior_features', {}), ensure_ascii=False)
            keywords_str = ', '.join(normalized_log.get('keywords', []))
            csv_row = {
                'timestamp': normalized_log.get('timestamp', ''),
                'provider': normalized_log.get('provider', ''),
                'event_id': normalized_log.get('event_id', 0),
                'event_type': normalized_log.get('event_type', 0),
                'log_type': normalized_log.get('log_type', ''),
                'computer_name': normalized_log.get('computer_name', ''),
                'record_number': normalized_log.get('record_number', 0),
                'event_description': normalized_log.get('event_description', ''),
                'keywords': keywords_str[:500],
                'behavior_features_json': behavior_features_json[:2000],
                'raw_message': normalized_log.get('raw_message', '')[:500],
            }
            self.normalized_csv_writer.writerow(csv_row)
            self.normalized_csv_handle.flush()
        except Exception as e:
            logger.error(f"Error writing normalized log to CSV: {e}")
    
    def parse_event_to_dict(self, event: Any, log_type: str) -> Dict[str, Any]:
        """Convert Windows Event Log event to structured dictionary."""
        try:
            # Extract full XML EventData
            event_data = self.extract_xml_event_data(event)
            
            # Build structured log entry
            log_entry = {
                'timestamp': event.TimeGenerated.isoformat() if hasattr(event.TimeGenerated, 'isoformat') else str(event.TimeGenerated),
                'log_type': log_type,
                'source_name': event.SourceName if hasattr(event, 'SourceName') else 'Unknown',
                'event_id': event.EventID if hasattr(event, 'EventID') else 0,
                'event_type': event.EventType if hasattr(event, 'EventType') else 0,
                'event_category': event.EventCategory if hasattr(event, 'EventCategory') else 0,
                'record_number': event.RecordNumber if hasattr(event, 'RecordNumber') else 0,
                'computer_name': event.ComputerName if hasattr(event, 'ComputerName') else 'Unknown',
                'event_data': event_data,  # Full structured EventData
                'raw_message': str(event.StringInserts) if hasattr(event, 'StringInserts') and event.StringInserts else '',
            }
            
            return log_entry
        except Exception as e:
            logger.error(f"Error parsing event: {e}")
            return None
    
    def extract_keywords(self, log_entry: Dict[str, Any]) -> List[str]:
        """Extract keywords from log entry for pattern matching."""
        keywords: List[str] = []
        
        if 'source_name' in log_entry:
            keywords.append(str(log_entry['source_name']).lower())
        
        if 'event_id' in log_entry:
            keywords.append(f"event_{log_entry['event_id']}")
        
        event_data = log_entry.get('event_data', {})
        if isinstance(event_data, dict):
            for key, value in event_data.items():
                if isinstance(value, str) and value:
                    if 'process' in key.lower() or 'image' in key.lower():
                        keywords.append(value.lower())
                    if 'user' in key.lower() or 'account' in key.lower():
                        keywords.append(value.lower())
                    
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    keywords.extend(re.findall(ip_pattern, value))
        
        if 'raw_message' in log_entry and log_entry['raw_message']:
            keywords.extend(re.findall(r'\b[A-Z][a-z]+\.exe\b', log_entry['raw_message']))
        
        return list(set(keywords))
    
    def extract_behavior_features(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract behavioral features that might indicate suspicious activity."""
        features = {
            'process_creation': False,
            'privilege_escalation': False,
            'driver_load': False,
            'service_installation': False,
            'scheduled_task_creation': False,
            'network_connection': False,
            'file_access': False,
            'registry_modification': False,
            'suspicious_process': False,
            'privilege_change': False,
        }
        
        event_id = log_entry.get('event_id', 0)
        event_data = log_entry.get('event_data', {}) or {}
        
        if event_id == 4688:
            features['process_creation'] = True
            process_name = str(event_data.get('ProcessName', '')).lower()
            if any(sp in process_name for sp in self.suspicious_processes):
                features['suspicious_process'] = True
        
        if event_id == 4672:
            features['privilege_escalation'] = True
            features['privilege_change'] = True
        
        if event_id == 4697:
            features['service_installation'] = True
        
        if event_id in [4698, 4700, 4702]:
            features['scheduled_task_creation'] = True
        
        if event_id == 6 and log_entry.get('log_type') == 'System':
            features['driver_load'] = True
        
        if 'network' in str(event_data).lower() or 'connection' in str(event_data).lower():
            features['network_connection'] = True
        
        if 'file' in str(event_data).lower() or 'path' in str(event_data).lower():
            features['file_access'] = True
        
        if 'registry' in str(event_data).lower() or 'reg' in str(event_data).lower():
            features['registry_modification'] = True
        
        return features
    
    def normalize_log(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize raw log entry into structured format with features."""
        try:
            event_data = raw_log.get('event_data', {})
            if isinstance(event_data, str):
                try:
                    event_data = json.loads(event_data)
                except Exception:
                    event_data = {}
            
            normalized = {
                'timestamp': raw_log.get('timestamp', datetime.now().isoformat()),
                'provider': raw_log.get('source_name', 'Unknown'),
                'event_id': raw_log.get('event_id', 0),
                'event_type': raw_log.get('event_type', 0),
                'log_type': raw_log.get('log_type', 'Unknown'),
                'computer_name': raw_log.get('computer_name', 'Unknown'),
                'record_number': raw_log.get('record_number', 0),
                'event_data': event_data if isinstance(event_data, dict) else {},
                'keywords': self.extract_keywords(raw_log),
                'behavior_features': self.extract_behavior_features(raw_log),
                'event_description': self.security_event_ids.get(
                    raw_log.get('event_id', 0),
                    'Unknown event'
                ),
                'raw_message': raw_log.get('raw_message', ''),
            }
            
            return normalized
        except Exception as e:
            logger.error(f"Error normalizing log: {e}")
            return None
    
    def collect_logs(self, log_type: str) -> None:
        """Collect logs from a specific log type and write to CSV."""
        try:
            hand = win32evtlog.OpenEventLog(self.server, log_type)
            
            events = []
            
            try:
                # Find the newest record currently in the log
                oldest = win32evtlog.GetOldestEventLogRecord(hand)
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                newest_in_log = oldest + total - 1
            except Exception as e:
                logger.error(f"Cannot get record info for {log_type}: {e}")
                win32evtlog.CloseEventLog(hand)
                return

            events = []
            
            # If we have a last record number, check if there are new events
            if log_type in self.last_record_numbers:
                last_seen = self.last_record_numbers[log_type]
                
                if last_seen >= newest_in_log:
                    # No new events
                    win32evtlog.CloseEventLog(hand)
                    return
                elif last_seen + 1 < oldest:
                    # Last seen record was deleted/overwritten
                    logger.warning(f"Event log {log_type} rolled over. Re-initializing.")
                    del self.last_record_numbers[log_type]
                else:
                    # Read forward from the next record
                    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
                    try:
                        events = win32evtlog.ReadEventLog(hand, flags, last_seen + 1)
                    except Exception as e:
                        logger.warning(f"Seek failed for {log_type} at offset {last_seen + 1}: {e}")
                        del self.last_record_numbers[log_type]
                        # Fallthrough to first run logic
            
            if not events and log_type not in self.last_record_numbers:
                # First run or seek failed: read the newest records to begin tracking
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                all_events = []
                batch = win32evtlog.ReadEventLog(hand, flags, 0)
                count = 0
                max_events = 50  # Read last 50 events on first run
                
                while batch and count < max_events:
                    all_events.extend(batch)
                    count += len(batch)
                    if count >= max_events:
                        break
                    batch = win32evtlog.ReadEventLog(hand, flags, 0)
                
                # Reverse to get chronological order (oldest first)
                events = list(reversed(all_events[:max_events]))
                logger.info(f"First run: Reading last {len(events)} events from {log_type} log")
            
            if events:
                kept = 0
                filtered = 0
                for event in events:
                    log_entry = self.parse_event_to_dict(event, log_type)
                    if not log_entry:
                        continue
                    
                    # Always track the highest record number we have successfully parsed
                    if 'record_number' in log_entry:
                        current_rec = log_entry['record_number']
                        if log_type not in self.last_record_numbers or current_rec > self.last_record_numbers[log_type]:
                            self.last_record_numbers[log_type] = current_rec
                    
                    # Apply timeframe + sensitivity filter
                    if not self._should_include_log(log_entry):
                        filtered += 1
                        continue
                    
                    # Persist raw entry
                    self._write_raw_csv(log_entry)
                    
                    # Normalize and persist normalized entry
                    normalized_log = self.normalize_log(log_entry)
                    if normalized_log:
                        self._write_normalized_csv(normalized_log)
                        kept += 1
                
                if kept > 0:
                    logger.info(
                        f"{log_type}: kept {kept} sensitive events "
                        f"(filtered {filtered} unwanted/out-of-window)"
                    )
                elif filtered > 0:
                    logger.debug(f"{log_type}: filtered {filtered} events (outside window or non-sensitive)")
            else:
                if log_type == 'System':
                    logger.debug(f"No new events in {log_type} log")
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            logger.error(f"Cannot access {log_type} log: {e}", exc_info=True)
    
    def run(self, interval: int = 5):
        """Main collection loop writing directly to CSV outputs."""
        logger.info(
            f"Starting Unified Log Collector - writing raw -> {self.raw_csv_path}, "
            f"normalized -> {self.normalized_csv_path}"
        )
        
        try:
            while True:
                try:
                    for log_type in self.log_types:
                        self.collect_logs(log_type)
                    time.sleep(interval)
                except KeyboardInterrupt:
                    raise
                except Exception as ex:
                    logger.error(f"Error in collection loop: {ex}")
                    time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Stopping Unified Log Collector Agent...")
        finally:
            if self.raw_csv_handle:
                self.raw_csv_handle.close()
            if self.normalized_csv_handle:
                self.normalized_csv_handle.close()


if __name__ == "__main__":
    collector = LogCollectorAgent()
    collector.run(interval=5)

