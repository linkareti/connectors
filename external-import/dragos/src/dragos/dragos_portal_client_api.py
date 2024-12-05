import time
from datetime import datetime, timedelta
from typing import Dict, List

import requests


class DragosClient:
    
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = { 'Api-Token': self.config.api_access_token, 'Api-Secret': self.config.api_access_key }
        self.session = requests.Session()
        self.session.headers.update(headers)

        self.indicators_endpoint = self.config.api_base_url + 'indicators'
        self.reports_endpoint = self.config.api_base_url + 'products'
        
        self.requests_per_minute_limit = self.config.requests_per_minute_limit
        self.requests_per_week_limit = self.config.requests_per_week_limit
        self.minute_requests = []  # Keep timestamps of requests in the last minute
        self.weekly_requests_count = 0
        self.week_start_time = datetime.now()

        #api request size configuration
        self.indicators_page_size = self.config.indicators_page_size
        self.reports_page_size = self.config.reports_page_size

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            
            self._enforce_rate_limits()
            
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url, "params": params}
            )

            response.raise_for_status()
            
            self._record_request()
                        
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_indicators(self, params=None) -> List[Dict]:
        """
        :return: A list of indicators from the Dragos Portal
        """
        try:
        
            dragos_indicators = self._get_indicators(params)

            return dragos_indicators
            
        except Exception as err:
            self.helper.connector_logger.error(err)
            return None

    def get_reports(self, params=None) -> List[Dict]:
        """
        :return: A list of indicators from the Dragos Portal
        """
        try:
        
            dragos_reports = self._get_reports(params)

            return dragos_reports
            
        except Exception as err:
            self.helper.connector_logger.error(err)
            return None

    def get_report_indicators(self, report_serials: list, params=None, serial_chunk_size=10) -> Dict[str, List]:
        """
        :return: A map of indicators by report
        """
        try:
        
            report_indicators = []
            
            if params is None:
                params = {}   
        
            for i in range(0, len(report_serials), serial_chunk_size):
                serial_chunk = report_serials[i:i + serial_chunk_size]
                params['serial[]']=serial_chunk
                report_indicators += self._get_indicators(params)

            return report_indicators
            
        except Exception as err:
            self.helper.connector_logger.error(err)
            return None

    def _get_indicators(self, params=None) -> List[Dict]:
        if params is None:
            params = {}
        params.setdefault('page_size', self.indicators_page_size)
        return self._get_paginated_endpoint(self.indicators_endpoint, 'indicators', params)

    def _get_reports(self, params=None) -> List[Dict]:
        if params is None:
            params = {}
        params.setdefault('page_size', self.reports_page_size)
        return self._get_paginated_endpoint(self.reports_endpoint, 'products', params)

    def _get_paginated_endpoint(self, endpoint, data_object_name, params=None) -> List[Dict]:
        
        results = []
        page = 1
        total_pages = 1
        
        if params is None:
            params = {}
     
        params.setdefault('page', page)
        
        while page <= total_pages:
            params['page'] = page
            
            request_data = self._request_data(endpoint, params)
            data = request_data.json()
            
            results += data[data_object_name]
            total_pages = data['total_pages']
            
            page += 1

        return results
    
    def _enforce_rate_limits(self):
        """
        Checks the per-minute and per-week rate limits.
        If per-minute limit is exceeded, it sleeps for the remainder of the minute.
        If per-week limit is exceeded, it raises an exception to stop further requests.
        """
        now = datetime.now()

        # Check per-week limit
        if self.weekly_requests_count >= self.requests_per_week_limit:
            raise Exception("[API] Weekly request limit exceeded.")

        # Check per-minute limit
        self._clean_old_requests(now)
        if len(self.minute_requests) >= self.requests_per_minute_limit:
            # Pause until we are allowed to make more requests
            sleep_time = 60 - (now - self.minute_requests[0]).total_seconds()
            self.helper.connector_logger.warning(
                f"[API] Per-minute request limit exceeded. Sleeping for {sleep_time:.2f} seconds."
            )
            time.sleep(sleep_time)
            
    def _clean_old_requests(self, now):
        """
        Removes requests that are older than one minute from the record.
        """
        one_minute_ago = now - timedelta(seconds=60)
        self.minute_requests = [req_time for req_time in self.minute_requests if req_time > one_minute_ago]

    def _record_request(self):
        """
        Records a successful request to the list for rate-limiting purposes.
        """
        now = datetime.now()

        # Add to the per-minute request tracking
        self.minute_requests.append(now)

        # Reset weekly counter if it's a new week
        if (now - self.week_start_time).days >= 7:
            self.week_start_time = now
            self.weekly_requests_count = 0

        # Increment the per-week request count
        self.weekly_requests_count += 1
