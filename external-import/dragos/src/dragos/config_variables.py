import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "CONNECTOR_DRAGOS_API_BASE_URL",
            ["connector_dragos", "api_base_url"],
            self.load,
        )

        self.api_access_token = get_config_variable(
            "CONNECTOR_DRAGOS_API_ACCESS_TOKEN",
            ["connector_dragos", "api_access_token"],
            self.load,
        )
        
        self.api_access_key = get_config_variable(
            "CONNECTOR_DRAGOS_API_ACCESS_KEY",
            ["connector_dragos", "api_access_key"],
            self.load,
        )

        self.start_date = get_config_variable(
            "CONNECTOR_DRAGOS_START_DATE",
            ["connector_dragos", "start_date"],
            self.load,
        )

        self.requests_per_minute_limit = get_config_variable(
            "CONNECTOR_DRAGOS_REQUESTS_PER_MINUTE_LIMIT",
            ["connector_dragos", "requests_per_minute_limit"],
            self.load,
            isNumber=True,
            default=30,
        )

        self.requests_per_week_limit = get_config_variable(
            "CONNECTOR_DRAGOS_REQUESTS_PER_WEEK_LIMIT",
            ["connector_dragos", "requests_per_week_limit"],
            self.load,
            isNumber=True,
            default=250,
        )
        
        self.indicators_page_size = get_config_variable(
            "CONNECTOR_DRAGOS_INDICATORS_PAGE_SIZE",
            ["connector_dragos", "indicators_page_size"],
            self.load,
            isNumber=True,
            default=1000,
        )
        
        self.reports_page_size = get_config_variable(
            "CONNECTOR_DRAGOS_REPORTS_PAGE_SIZE",
            ["connector_dragos", "reports_page_size"],
            self.load,
            isNumber=True,
            default=500,
        )
