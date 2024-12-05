from pycti import OpenCTIConnectorHelper

from .censys_client_api import CensysClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix


class ConnectorCensys:
    """
    Specifications of the internal enrichment connector

    This class encapsulates the main actions, expected to be run by any internal enrichment connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to enrich a data (Observables) created or modified in the OpenCTI core platform.
    It will create a STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    Ingesting a bundle allow the connector to be compatible with the playbook automation feature.


    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        # playbook_compatible=True only if a bundle is sent !
        self.helper = OpenCTIConnectorHelper(
            config=self.config.load, playbook_compatible=True
        )
        self.client = CensysClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

        # Define variables
        self.author = None
        self.tlp = None
        self.stix_objects_list = []

    def _collect_intelligence(self, observable) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # === Create the author
        self.author = self.converter_to_stix.create_author()

        obs_type = observable["type"]

        if obs_type.lower() in ("ipv4-addr", "ipv6-addr"):
            ip = observable["value"]
            host_data = self.client.query_censys_ip(ip)
    
            if host_data:
                enrichment_data = self.converter_to_stix.process_ip(host_data)
                self.stix_objects_list.extend(enrichment_data)
                return self.stix_objects_list

        elif obs_type.lower() in ("domain-name", "hostname"):
            domain = observable["value"]
            domain_data = self.client.query_censys_domain(domain)
    
            if domain_data:
                enrichment_data = self.converter_to_stix.process_domain(observable, domain_data)
                self.stix_objects_list.extend(enrichment_data)
            
                domain_cert_data = self.client.query_censys_host_certificates(domain)
                if domain_cert_data:
                    enrichment_data = self.converter_to_stix.process_domain_hosts(observable, domain_cert_data)
                    self.stix_objects_list.extend(enrichment_data)

                return self.stix_objects_list

        elif obs_type.lower() in ("x509-certificate"):
            sha_256_value = observable["hashes"].get('SHA-256', 'Not Found')
            cert_data = self.client.query_censys_certificate(sha_256_value)
    
            if cert_data:
                enrichment_data = self.converter_to_stix.process_certificate(cert_data)
                self.stix_objects_list.extend(enrichment_data)
                return self.stix_objects_list

        else:
            raise ValueError(
                f'{obs_type} is not a supported entity type.'
            )        
        
    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["type"]

        if entity_type in scopes:
            return True
        else:
            return False

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: Boolean
        """
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    self.tlp = marking_definition["definition"]

        valid_max_tlp = self.helper.check_max_tlp(self.tlp, self.config.max_tlp)

        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and check which type to send for process
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            opencti_entity = data["enrichment_entity"]
            self.extract_and_check_markings(opencti_entity)

            # To enrich the data, you can add more STIX object in stix_objects
            self.stix_objects_list = data["stix_objects"]
            observable = data["stix_entity"]

            info_msg = (
                "[CONNECTOR] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {observable["type"]}})

            if self.entity_in_scope(observable):
                
                stix_objects = self._collect_intelligence(observable)

                if stix_objects is not None and len(stix_objects) is not None:
                    stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                    bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

                    info_msg = (
                        "[API] Observable value found and knowledge added for type: "
                        + observable["type"]
                        + ", sending "
                        + str(len(bundles_sent))
                        + " stix bundle(s) for worker import"
                    )
                    return info_msg
                else:
                    info_msg = "[CONNECTOR] No information found"
                    return info_msg

            else:
                return self.helper.connector_logger.info(
                    "[CONNECTOR] Skip the following entity as it does not concern "
                    "the initial scope found in the config connector: ",
                    {"entity_id": opencti_entity["entity_id"]},
                )
        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)