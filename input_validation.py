"""
Input validation and sanitization for CYT
Prevents injection attacks and ensures data integrity
"""
import logging
import re

logger = logging.getLogger(__name__)


class InputValidator:
    """Comprehensive input validation for CYT"""

    MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

    # Dangerous characters to filter
    DANGEROUS_CHARS = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')', '{', '}', '[', ']']

    @classmethod
    def validate_mac_address(cls, mac: str) -> bool:
        """Validate MAC address format"""
        if not isinstance(mac, str):
            return False
        if len(mac) > 17:  # Max length for MAC address
            return False
        return bool(cls.MAC_PATTERN.match(mac))

    @classmethod
    def validate_ssid(cls, ssid: str) -> bool:
        """Validate SSID format and content"""
        if not isinstance(ssid, str):
            return False
        if len(ssid) == 0 or len(ssid) > 32:
            return False
        # Check for null bytes and control characters
        if '\x00' in ssid or any(ord(c) < 32 and c not in '\t\n\r' for c in ssid):
            return False
        # Check for dangerous characters
        if any(char in ssid for char in cls.DANGEROUS_CHARS):
            logger.warning(f"SSID contains dangerous characters: {ssid}")
            return False
        return True
