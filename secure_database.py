"""
Secure database operations - prevents SQL injection
"""
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Dict, Any

logger = logging.getLogger(__name__)


class KismetDB:
    """Secure wrapper for Kismet database operations"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.__connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self) -> None:
        """Establish secure database connection"""
        try:
            self.__connection = sqlite3.connect(self.db_path, timeout=30.0)
            self.__connection.row_factory = sqlite3.Row  # Enable column access by name
            logger.info(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database {self.db_path}: {e}")
            raise

    def close(self) -> None:
        """Close database connection"""
        if self.__connection:
            self.__connection.close()
            self.__connection = None

    def execute_safe_query(self, query: str, params: Tuple = ()) -> List[sqlite3.Row]:
        """Execute parameterized query safely"""
        if not self.__connection:
            raise RuntimeError("Database not connected")

        try:
            cursor = self.__connection.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Database query failed: {query}, params: {params}, error: {e}")
            raise

    def get_devices_by_time_range(self, start_time: float, end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Get devices within time range with proper parameterization
        
        Args:
            start_time: Unix timestamp for start time
            end_time: Optional unix timestamp for end time
            
        Returns:
            List of device dictionaries
        """
        if end_time is not None:
            query = "SELECT devmac, type, device, last_time FROM devices WHERE last_time >= ? AND last_time <= ?"
            params = (start_time, end_time)
        else:
            query = "SELECT devmac, type, device, last_time FROM devices WHERE last_time >= ?"
            params = (start_time,)

        rows = self.execute_safe_query(query, params)

        devices = []
        for row in rows:
            try:
                # Parse device JSON safely
                device_data = None
                if row['device']:
                    try:
                        device_data = json.loads(row['device'])
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.warning(f"Failed to parse device JSON for {row['devmac']}: {e}")

                devices.append({
                    'mac': row['devmac'],
                    'type': row['type'],
                    'device_data': device_data,
                    'last_time': row['last_time']
                })
            except Exception as e:
                logger.warning(f"Error processing device row: {e}")
                continue

        return devices

    def get_mac_addresses_by_time_range(self, start_time: float, end_time: Optional[float] = None) -> List[str]:
        """Get just MAC addresses for a time range"""
        devices = self.get_devices_by_time_range(start_time, end_time)
        return [device['mac'] for device in devices if device['mac']]

    def get_probe_requests_by_time_range(self, start_time: float, end_time: Optional[float] = None) -> List[Dict[str, str]]:
        """
        Get probe requests with SSIDs for time range
        
        Returns:
            List of dicts with 'mac', 'ssid', 'timestamp'
        """
        devices = self.get_devices_by_time_range(start_time, end_time)

        probes = []
        for device in devices:
            mac = device['mac']
            device_data = device['device_data']

            if not device_data:
                continue

            # Extract probe request SSID safely
            try:
                dot11_device = device_data.get('dot11.device', {})
                if not isinstance(dot11_device, dict):
                    continue

                probe_record = dot11_device.get('dot11.device.last_probed_ssid_record', {})
                if not isinstance(probe_record, dict):
                    continue

                ssid = probe_record.get('dot11.probedssid.ssid', '')
                if ssid and isinstance(ssid, str):
                    probes.append({
                        'mac': mac,
                        'ssid': ssid,
                        'timestamp': device['last_time']
                    })
            except (KeyError, TypeError, AttributeError) as e:
                logger.debug(f"No probe data for device {mac}: {e}")
                continue

        return probes

    def validate_connection(self) -> bool:
        """Validate database connection and basic structure"""
        try:
            # Test basic query
            result = self.execute_safe_query("SELECT COUNT(*) as count FROM devices LIMIT 1")
            count = result[0]['count'] if result else 0
            logger.info(f"Database contains {count} devices")
            return True
        except sqlite3.Error as e:
            logger.error(f"Database validation failed: {e}")
            return False


class SecureTimeWindows:
    """Secure time window management for device tracking"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.time_windows = config.get('timing', {}).get('time_windows', {
            'recent': 5,
            'medium': 10,
            'old': 15,
            'oldest': 20
        })

    def get_time_boundaries(self) -> Dict[str, float]:
        """Calculate secure time boundaries"""
        now = datetime.now()

        boundaries = {}
        for window_name, minutes in self.time_windows.items():
            boundary_time = now - timedelta(minutes=minutes)
            boundaries[f'{window_name}_time'] = time.mktime(boundary_time.timetuple())

        # Add current time boundary (2 minutes ago for active scanning)
        current_boundary = now - timedelta(minutes=2)
        boundaries['current_time'] = time.mktime(current_boundary.timetuple())

        return boundaries


def create_secure_db_connection(db_path: str) -> KismetDB:
    """Factory function to create secure database connection"""
    return KismetDB(db_path)
