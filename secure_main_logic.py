"""
Secure main logic for Chasing Your Tail - replaces vulnerable SQL operations
"""
import logging
from datetime import datetime
from typing import IO
from typing import List, Dict, Set, Any

from chasing_your_tail import event_log_file
from events import write_event_log, SSIDProbeEvent
from secure_database import KismetDB, SecureTimeWindows

logger = logging.getLogger(__name__)


class SecureCYTMonitor:
    past_five_mins_macs: Set[str] = set()
    five_ten_min_ago_macs: Set[str] = set()
    ten_fifteen_min_ago_macs: Set[str] = set()
    fifteen_twenty_min_ago_macs: Set[str] = set()

    past_five_mins_ssids: Set[str] = set()
    five_ten_min_ago_ssids: Set[str] = set()
    ten_fifteen_min_ago_ssids: Set[str] = set()
    fifteen_twenty_min_ago_ssids: Set[str] = set()

    def __init__(self, config: Dict[str, Any], ignore_list: List[str], ssid_ignore_list: List[str], log_file: IO, probes_file: IO):
        self.config = config
        self.ignore_list = set(mac.upper() for mac in ignore_list)
        self.ssid_ignore_list = set(ssid_ignore_list)
        self.log_file = log_file
        self.probes_file = probes_file
        self.time_manager = SecureTimeWindows(config)

    def initialize_tracking_lists(self, db: KismetDB) -> None:
        """Initialize all tracking lists securely"""
        try:
            boundaries = self.time_manager.get_time_boundaries()

            # Initialize MAC tracking lists
            self.__initialize_mac_lists(db, boundaries)

            # Initialize SSID tracking lists  
            self.__initialize_ssid_lists(db, boundaries)

            self.__log_initialization_stats()

        except Exception as e:
            logger.error(f"Failed to initialize tracking lists", exc_info=e)
            raise

    def __initialize_mac_lists(self, db: KismetDB, boundaries: Dict[str, float]) -> None:
        """Initialize MAC address tracking lists"""
        # Past 5 minutes
        macs = db.get_mac_addresses_by_time_range(boundaries['recent_time'])
        self.past_five_mins_macs = self.__filter_macs(macs)

        # 5-10 minutes ago
        macs = db.get_mac_addresses_by_time_range(boundaries['medium_time'], boundaries['recent_time'])
        self.five_ten_min_ago_macs = self.__filter_macs(macs)

        # 10-15 minutes ago
        macs = db.get_mac_addresses_by_time_range(boundaries['old_time'], boundaries['medium_time'])
        self.ten_fifteen_min_ago_macs = self.__filter_macs(macs)

        # 15-20 minutes ago
        macs = db.get_mac_addresses_by_time_range(boundaries['oldest_time'], boundaries['old_time'])
        self.fifteen_twenty_min_ago_macs = self.__filter_macs(macs)

    def __initialize_ssid_lists(self, db: KismetDB, boundaries: Dict[str, float]) -> None:
        """Initialize SSID tracking lists"""
        # Past 5 minutes
        probes = db.get_probe_requests_by_time_range(boundaries['recent_time'])
        self.past_five_mins_ssids = self.__filter_ssids([p['ssid'] for p in probes])

        # 5-10 minutes ago
        probes = db.get_probe_requests_by_time_range(boundaries['medium_time'], boundaries['recent_time'])
        self.five_ten_min_ago_ssids = self.__filter_ssids([p['ssid'] for p in probes])

        # 10-15 minutes ago
        probes = db.get_probe_requests_by_time_range(boundaries['old_time'], boundaries['medium_time'])
        self.ten_fifteen_min_ago_ssids = self.__filter_ssids([p['ssid'] for p in probes])

        # 15-20 minutes ago
        probes = db.get_probe_requests_by_time_range(boundaries['oldest_time'], boundaries['old_time'])
        self.fifteen_twenty_min_ago_ssids = self.__filter_ssids([p['ssid'] for p in probes])

    def __filter_macs(self, mac_list: List[str]) -> Set[str]:
        """Filter MAC addresses against ignore list"""
        return {mac.upper() for mac in mac_list if mac.upper() not in self.ignore_list}

    def __filter_ssids(self, ssid_list: List[str]) -> Set[str]:
        """Filter SSIDs against ignore list"""
        return {ssid for ssid in ssid_list if ssid and ssid not in self.ssid_ignore_list}

    def __log_initialization_stats(self) -> None:
        """Log initialization statistics"""
        mac_stats = [
            ("Past 5 minutes", len(self.past_five_mins_macs)),
            ("5-10 minutes ago", len(self.five_ten_min_ago_macs)),
            ("10-15 minutes ago", len(self.ten_fifteen_min_ago_macs)),
            ("15-20 minutes ago", len(self.fifteen_twenty_min_ago_macs))
        ]

        ssid_stats = [
            ("Past 5 minutes", len(self.past_five_mins_ssids)),
            ("5-10 minutes ago", len(self.five_ten_min_ago_ssids)),
            ("10-15 minutes ago", len(self.ten_fifteen_min_ago_ssids)),
            ("15-20 minutes ago", len(self.fifteen_twenty_min_ago_ssids))
        ]

        for period, count in mac_stats:
            logger.info("%s MACs added to the %s list", count, period)

        for period, count in ssid_stats:
            logger.info("%s Probed SSIDs added to the %s list", count, period)

    def process_current_activity(self, db: KismetDB) -> None:
        """Process current activity and detect matches"""
        try:
            boundaries = self.time_manager.get_time_boundaries()

            # Get current devices and probes
            current_devices = db.get_devices_by_time_range(boundaries['current_time'])

            for device in current_devices:
                mac = device['mac']
                device_data = device.get('device_data', {})

                if not mac:
                    continue

                # Check for probe requests
                self.__process_probe_requests(device_data, mac)

                # Check MAC address tracking
                self.__process_mac_tracking(mac)

        except Exception as e:
            logger.error(f"Error processing current activity", exc_info=e)

    def __process_probe_requests(self, device_data: Dict, mac: str) -> None:
        """Process probe requests from device data"""
        if not device_data:
            return

        try:
            dot11_device = device_data.get('dot11.device', {})
            if not isinstance(dot11_device, dict):
                return

            probe_record = dot11_device.get('dot11.device.last_probed_ssid_record', {})
            if not isinstance(probe_record, dict):
                return

            ssid = probe_record.get('dot11.probedssid.ssid', '')
            if not ssid or ssid in self.ssid_ignore_list:
                return

            write_event_log(event_log_file, SSIDProbeEvent(datetime.now(), ssid, mac))

            logger.info("Probe detected from %s: %s", mac, ssid)

            # Check against historical lists
            self.__check_ssid_history(ssid)

        except (KeyError, TypeError, AttributeError) as e:
            logger.debug("No probe data for device %s", mac, exc_info=e)

    def __check_ssid_history(self, ssid: str) -> None:
        """Check SSID against historical tracking lists"""
        if ssid in self.five_ten_min_ago_ssids:
            logger.warning("Repeated probe detected: %s (5-10 min window)", ssid)

        if ssid in self.ten_fifteen_min_ago_ssids:
            logger.warning("Repeated probe detected: %s (10-15 min window)", ssid)

        if ssid in self.fifteen_twenty_min_ago_ssids:
            logger.warning("Repeated probe detected: %s (15-20 min window)", ssid)

    def __process_mac_tracking(self, mac: str) -> None:
        """Process MAC address tracking"""
        if mac.upper() in self.ignore_list:
            return

        # Check against historical lists
        if mac in self.five_ten_min_ago_macs:
            logger.warning("Device reappeared: %s (5-10 min window)", mac)

        if mac in self.ten_fifteen_min_ago_macs:
            logger.warning("Device reappeared: %s (10-15 min window)", mac)

        if mac in self.fifteen_twenty_min_ago_macs:
            logger.warning("Device reappeared: %s (15-20 min window)", mac)

    def rotate_tracking_lists(self, db: KismetDB) -> None:
        """Rotate tracking lists and update with fresh data"""
        try:
            # Rotate MAC lists
            self.fifteen_twenty_min_ago_macs = self.ten_fifteen_min_ago_macs
            self.ten_fifteen_min_ago_macs = self.five_ten_min_ago_macs
            self.five_ten_min_ago_macs = self.past_five_mins_macs

            # Rotate SSID lists
            self.fifteen_twenty_min_ago_ssids = self.ten_fifteen_min_ago_ssids
            self.ten_fifteen_min_ago_ssids = self.five_ten_min_ago_ssids
            self.five_ten_min_ago_ssids = self.past_five_mins_ssids

            # Get fresh data for past 5 minutes
            boundaries = self.time_manager.get_time_boundaries()

            # Update past 5 minutes MAC list
            macs = db.get_mac_addresses_by_time_range(boundaries['recent_time'])
            self.past_five_mins_macs = self.__filter_macs(macs)

            # Update past 5 minutes SSID list
            probes = db.get_probe_requests_by_time_range(boundaries['recent_time'])
            self.past_five_mins_ssids = self.__filter_ssids([p['ssid'] for p in probes])

            self.__log_rotation_stats()

        except Exception as e:
            logger.error("Error rotating tracking lists", exc_info=e)

    def __log_rotation_stats(self) -> None:
        """Log rotation statistics"""
        # Log to file
        logger.info("%s MACs moved to the 15-20 Min list", len(self.fifteen_twenty_min_ago_macs))
        logger.info("%s MACs moved to the 10-15 Min list", len(self.ten_fifteen_min_ago_macs))
        logger.info("%s MACs moved to the 5 to 10 mins ago list", len(self.five_ten_min_ago_macs))

        logger.info("Probed SSIDs moved to the 15 to 20 mins ago list", len(self.fifteen_twenty_min_ago_ssids))
        logger.info("%s Probed SSIDs moved to the 10 to 15 mins ago list", len(self.ten_fifteen_min_ago_ssids))
        logger.info("%s Probed SSIDs moved to the 5 to 10 mins ago list", len(self.five_ten_min_ago_ssids))
