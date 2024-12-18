import sys
from datetime import datetime, timezone

import re

from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix


class ConnectorArctichub:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

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
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence with paged processing
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            # Logging last run details
            is_first_run = current_state is None or "last_run" not in current_state
            if is_first_run:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )
            else:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "Connector arctichub feed"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Fetch all customers
            all_customers = self.client.get_customers()

            # Process customers in "pages"
            total_processed = 0
            total_customers = len(all_customers)
            total_ignored = 0
            
            self.helper.connector_logger.info(
                "[CONNECTOR] Total customers to be processed",
                {
                    "total_customers": total_customers
                }
            )

            create_organization = is_first_run
            
            for customer_data in all_customers:

                if not self.is_customer_valid(customer_data):
                    total_ignored += 1
                    continue
                
                # Collect and transform this page
                stix_objects = []

                if create_organization:
                    organization = self.converter_to_stix.create_author()
                    stix_objects.append(organization)
                    self.helper.connector_logger.info(
                       "[CONNECTOR] Creating organization in the first run...",
                        {"otganization": organization},
                    )
                    create_organization = False

                paged_stix_objects = self.converter_to_stix.process_customer(customer_data)
                stix_objects.extend(paged_stix_objects)
                
                # Send this page to the platform
                if stix_objects:
                    stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                    bundles_sent = self.helper.send_stix2_bundle(
                        stix_objects_bundle,
                        update=self.config.update_existing_data,
                        work_id=work_id
                    )

                    total_processed += 1
                    self.helper.connector_logger.info(
                        "Sending STIX objects to OpenCTI...",
                        {
                            "total_processed": total_processed,
                            "total_customers": total_customers,
                            "total_ignored": total_ignored,
                            "bundles_sent": str(len(bundles_sent))
                        },
                    )

            # Store the current timestamp as a last run of the connector
            current_state = self.helper.get_state() or {}
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.fromtimestamp(current_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            
            current_state["last_run"] = current_state_datetime
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, "
                f"processed {total_processed} customers out of {total_customers}, "
                f"ignored {total_ignored} customers, "
                f"storing last_run as {last_run_datetime}"
            )

            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
    
    def is_customer_valid(self, customer_data: dict) -> bool:
        """
        Validate if a customer should be processed based on various criteria
        
        :param customer_data: Complete customer data dictionary
        :return: Boolean indicating if customer should be processed
        """
        # Check if customer data is valid
        if 'data' not in customer_data or 'labels' not in customer_data['data']:
            self.helper.connector_logger.info(
                "[CONNECTOR] Ignoring customer with invalid data structure", 
                {"customer_data": customer_data}
            )
            return False

        data = customer_data['data']
        customer_name = data.get('name', 'Unknown')
        labels = data['labels']

        # Check if customer name matches any regex pattern in ignored names list
        if self.config.customers_ignored_names:
            for ignored_pattern in self.config.customers_ignored_names:
                if re.match(ignored_pattern, customer_name, re.IGNORECASE):
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Ignoring customer by name pattern", 
                        {
                            "customer": customer_name, 
                            "ignored_pattern": ignored_pattern
                        }
                    )
                    return False

        # Check for organization type
        organization_type = labels.get('organization type', None)
        if not organization_type:
            self.helper.connector_logger.info(
                "[CONNECTOR] Ignoring customer without organization type", 
                {"customer": customer_name}
            )
            return False

        return True
    
    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )