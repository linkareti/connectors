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
            "CONNECTOR_ARCTICHUB_API_BASE_URL",
            ["connector_arctichub", "api_base_url"],
            self.load,
        )

        self.api_events_path = get_config_variable(
            "CONNECTOR_ARCTICHUB_API_EVENTS_PATH",
            ["connector_arctichub", "api_events_path"],
            self.load,
        )

        self.api_customers_path = get_config_variable(
            "CONNECTOR_ARCTICHUB_API_CUSTOMERS_PATH",
            ["connector_arctichub", "api_customers_path"],
            self.load,
        )

        self.api_events_key = get_config_variable(
            "CONNECTOR_ARCTICHUB_API_EVENTS_KEY",
            ["connector_arctichub", "api_events_key"],
            self.load,
        )

        self.api_customers_key = get_config_variable(
            "CONNECTOR_ARCTICHUB_API_CUSTOMERS_KEY",
            ["connector_arctichub", "api_customers_key"],
            self.load,
        )