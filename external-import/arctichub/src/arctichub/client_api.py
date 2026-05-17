import requests
from urllib.parse import urljoin

from arctichub.settings import ArctichubConfig


class ConnectorClient:
    def __init__(self, helper, config: ArctichubConfig):
        """
        Initialize the client with necessary configurations.

        Args:
            helper: Connector helper used for logging.
            config (ArctichubConfig): Arctic Hub connector configuration.
        """
        self.helper = helper
        self.config = config

        base_url = str(config.api_base_url)
        self.customer_session = self._create_session(config.api_customers_key.get_secret_value())
        self.customers_endpoint = urljoin(base_url.rstrip("/") + "/", config.api_customers_path)

        self.event_session = None
        self.events_endpoint = None
        if config.api_events_key is not None:
            self.event_session = self._create_session(config.api_events_key.get_secret_value())
            self.events_endpoint = urljoin(base_url.rstrip("/") + "/", config.api_events_path)

    @staticmethod
    def _create_session(api_key: str) -> requests.Session:
        """
        Create a requests session with the API key header.

        Args:
            api_key: Authentication token.

        Returns:
            A configured requests.Session.
        """
        session = requests.Session()
        session.headers.update({
            "Authorization": f"token {api_key}",
            "Accept": "application/json",
        })
        return session

    def _request_data(self, session: requests.Session, api_url: str, params=None):
        """
        Perform a GET request to the API endpoint.

        Args:
            session: Requests session.
            api_url: API endpoint URL.
            params: Optional query parameters.

        Returns:
            Response object, or None if the request fails.
        """
        try:
            response = session.get(api_url, params=params)
            self.helper.connector_logger.info(
                "[API] HTTP GET request to endpoint", {"url_path": api_url}
            )
            response.raise_for_status()
            return response

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching data",
                {"url_path": api_url, "error": str(err)},
            )
            return None

    def get_events(self, params=None) -> list:
        """
        Fetch events from the API.

        Args:
            params: Optional query parameters (e.g. for time-based filtering).

        Returns:
            List of event records, or empty list on failure or if events are not configured.
        """
        if self.event_session is None or self.events_endpoint is None:
            self.helper.connector_logger.warning(
                "[API] Events session not configured — set api_events_key to enable events fetching"
            )
            return []
        try:
            response = self._request_data(self.event_session, self.events_endpoint, params=params)
            return response.json() if response else []
        except Exception as err:
            self.helper.connector_logger.error("[API] Failed to parse events response", {"error": str(err)})
            return []

    def get_customers(self, params=None) -> list:
        """
        Fetch customers from the API.

        Args:
            params: Optional query parameters.

        Returns:
            List of customer records, or empty list on failure.
        """
        try:
            response = self._request_data(self.customer_session, self.customers_endpoint, params=params)
            return response.json() if response else []
        except Exception as err:
            self.helper.connector_logger.error("[API] Failed to parse customers response", {"error": str(err)})
            return []
