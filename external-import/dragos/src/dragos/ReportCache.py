from .constants import (
    INDICATOR_TYPE_MAPPING,
)

class ReportCache:
    """A cache system for storing and retrieving report-related indicators and metadata.
    
    Cache structure:
    {
        "DOM-2021-34": {
            "indicators": {
                "rockwall.city": {"type": "domain"},
                "another.indicator": {"type": "IP address"},
                ...
            },
            "attack_techniques": {"Defense Evasion:Masquerading", ...},
            "threat_groups": {"GroupA", ...}
        }
    }
    """
    def __init__(self):
        # Initialize the main cache structure
        self.report_indicators_cache = {}

    def ensure_cache_for_serial(self, serial: str) -> None:
        """Initialize the serial key if it doesn't exist in the cache.
        
        Args:
            serial: Report serial number to initialize in cache.
        """
        if serial not in self.report_indicators_cache:
            self.report_indicators_cache[serial] = {
                "indicators": {},
                "attack_techniques": set(),
                "threat_groups": set()
            }
            
    def update_cache_report_with_indicator(self, indicator: dict) -> None:
        """
        Update cache with indicator information for each report it appears in.    
        """
        for product in indicator["products"]:
            serial = product["serial"]
            
            self.ensure_cache_for_serial(serial)

            value = indicator["value"]
            indicator_type = indicator["indicator_type"]

            mapping = INDICATOR_TYPE_MAPPING.get(indicator_type, None)

            if mapping:
            
                self.report_indicators_cache[serial]["indicators"][value] = {"indicator_type": indicator_type}

                self.report_indicators_cache[serial]["attack_techniques"].update(
                    set(indicator.get("attack_techniques", []))
                )
                self.report_indicators_cache[serial]["threat_groups"].update(
                    set(indicator.get("threat_groups", []))
                )
    
    def get_report_indicators(self, serial: str) -> dict:
        """Get all indicators for a specific report serial.
        
        Args:
            serial: Report serial number to retrieve indicators for.
            
        Returns:
            Set of indicator values associated with the report.
        """
        # Get the indicator dictionary for the report serial
        return self.report_indicators_cache.get(serial, {}).get("indicators", {})
    
    
    def get_report_techniques(self, serial: str) -> set:
        """Get all attack techniques for a specific report serial.
        
        Args:
            serial: Report serial number to retrieve techniques for.
            
        Returns:
            Set of attack techniques associated with the report.
        """
        return self.report_indicators_cache.get(serial, {}).get("attack_techniques", set())
    
    def get_report_threat_groups(self, serial: str) -> set:
        """Get all threat groups for a specific report serial.
        
        Args:
            serial: Report serial number to retrieve threat groups for.
            
        Returns:
            Set of threat groups associated with the report.
        """
        return self.report_indicators_cache.get(serial, {}).get("threat_groups", set())
    
    def clear_cache(self):
        """Clear the entire cache."""
        self.report_indicators_cache.clear()

