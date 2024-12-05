import requests

from urllib.parse import urljoin

class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations

        Args:
            helper: Logging and helper utilities
            config: Configuration settings
        """
        self.helper = helper
        self.config = config

        self.customer_session = self._create_session(config.api_customers_key)
        self.event_session = self._create_session(config.api_events_key)

        self.customers_endpoint = urljoin(self.config.api_base_url + '/', self.config.api_customers_path)
        self.events_endpoint = urljoin(self.config.api_base_url + '/', self.config.api_events_path)

    def _create_session(self, api_key):
        """
        Create a requests session with standard headers

        Args:
            api_key: Authentication token

        Returns:
            requests.Session: Configured session
        """
        session = requests.Session()
        session.headers.update({
            'Authorization': f"token {api_key}",
            "Accept": "application/json"
        })
        return session

    def _request_data(self, session: requests.Session, api_url: str, params=None):
        """
        Internal method to handle API requests

        Args:
            session: Requests session
            api_url: API endpoint URL
            params: Optional query parameters

        Returns:
            Response or None if request fails
        """
        try:
            response = session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None
        

    def get_events(self, params=None) -> dict:
        """
        Fetch events from the API

        Args:
            params: Optional query parameters

        Returns:
            dict: JSON response or None
        """
        try:
        
            response = self._request_data(self.event_session, self.events_endpoint, params=params)
            return response.json()
        
        except Exception as err:
            self.helper.connector_logger.error(err)


    def get_customers(self, params=None) -> dict:
        """
        Fetch customers from the API

        Args:
            params: Optional query parameters

        Returns:
            dict: JSON response or None
        """
        try:
        
            response = self._request_data(self.customer_session, self.customers_endpoint, params=params)
            return response.json()
        
        except Exception as err:
            self.helper.connector_logger.error(err)




