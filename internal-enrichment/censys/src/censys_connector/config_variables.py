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

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "CONNECTOR_CENSYS_API_BASE_URL",
            ["connector_censys", "api_base_url"],
            self.load,
        )

        self.api_id = get_config_variable(
            "CONNECTOR_CENSYS_API_ID",
            ["connector_censys", "api_id"],
            self.load,
        )

        self.api_secret = get_config_variable(
            "CONNECTOR_CENSYS_API_SECRET",
            ["connector_censys", "api_secret"],
            self.load,
        )

        self.max_tlp = get_config_variable(
            "CONNECTOR_CENSYS_MAX_TLP",
            ["connector_censys", "max_tlp"],
            self.load,
        )