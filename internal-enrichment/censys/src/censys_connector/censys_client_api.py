
from censys.search import CensysHosts, CensysCerts

class CensysClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.censys_hosts = CensysHosts(api_id=self.config.api_id, api_secret=self.config.api_secret)
        self.censys_certs = CensysCerts(api_id=self.config.api_id, api_secret=self.config.api_secret)
        

    def query_censys_ip(self, ip_address):
        """
        Fetch IP address: Retrieve metadata, open ports, services, and geolocation data.
        """
        try:
            host_data = self.censys_hosts.view(ip_address)
            return host_data
        except Exception as err:
            self.helper.connector_logger.error(f"[CONNECTOR] Error fetching data for ip: {ip_address}")
            return None
    
    def query_censys_domain(self, domain):
        """
        Fetch Domain: Retrieve DNS data, certificate links, and IP mappings..
        """
        try:
            domain_data = self.censys_hosts.search(f"dns.names: {domain}")
            return domain_data()
        except Exception as err:
            self.helper.connector_logger.error(f"[CONNECTOR] Error fetching data for domain: {domain}")
            return None

    def query_censys_certificate(self, certificate_hash):
        """
        Fetch Certificate.
        """
        try:
            cert_data = self.censys_certs.view(certificate_hash)
            return cert_data
        except Exception as err:
            self.helper.connector_logger.error(f"[CONNECTOR] Error fetching data for certificate: {certificate_hash}")
            return None

    def query_censys_host_certificates(self, host):
        """
        Fetch Certificate for given host.
        """
        try:
            cert_data = self.censys_certs.search(f"names: {host}")
            return cert_data()
        except Exception as err:
            self.helper.connector_logger.error(f"[CONNECTOR] Error fetching certificate data for host: {host}")
            return None
