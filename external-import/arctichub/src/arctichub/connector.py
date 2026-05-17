import re
import sys
from datetime import datetime, timezone
from typing import List

from arctichub.client_api import ConnectorClient
from arctichub.converter_to_stix import ConverterToStix
from arctichub.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class ConnectorArctichub:
    """
    Specifications of the external import connector.

    This class encapsulates the main actions, expected to be run by any external import connector.
    This type of connector fetches external data to create STIX bundles and sends them to OpenCTI.
    Customers are processed individually, each producing its own bundle, to limit memory usage.

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration.
        helper (OpenCTIConnectorHelper):
            Handle the connection and requests between the connector and OpenCTI.
        client (ConnectorClient):
            Provide methods to request the Arctic Hub API.
        converter_to_stix (ConverterToStix):
            Provide methods for converting Arctic Hub data into SDK entities.

    ---

    Best practices:
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to schedule connector's runs frequency
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to OpenCTI
        - `self.helper.set_state()` is used to store persistent data in connector's state
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `ConnectorArctichub` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector.
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI.
        """
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config.arctichub)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence with per-customer bundle processing.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            now = datetime.now(timezone.utc)
            current_timestamp = int(now.timestamp())
            current_state = self.helper.get_state()

            is_first_run = current_state is None or "last_run" not in current_state
            if is_first_run:
                self.helper.connector_logger.info("[CONNECTOR] Connector has never run...")
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": current_state["last_run"]},
                )

            friendly_name = "Connector Arctic Hub feed"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            all_customers = self.client.get_customers()
            # Sort by number of IP ranges descending to process larger customers first
            all_customers = sorted(
                all_customers,
                key=lambda x: len(x["data"].get("ip range", [])),
                reverse=True,
            )

            total_processed = 0
            total_customers = len(all_customers)
            total_ignored = 0

            self.helper.connector_logger.info(
                "[CONNECTOR] Total customers to be processed",
                {"total_customers": total_customers},
            )

            # Include the author organization only on the first run
            include_author = is_first_run

            for customer_data in all_customers:
                if not self.is_customer_valid(customer_data):
                    total_ignored += 1
                    continue

                octi_objects = []

                if include_author:
                    octi_objects.append(self.converter_to_stix.author)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Including author organization in the first run..."
                    )
                    include_author = False

                octi_objects.extend(self.converter_to_stix.process_customer(customer_data))

                if octi_objects:
                    self._send_bundle(octi_objects, work_id)
                    total_processed += 1
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Customer bundle sent",
                        {
                            "total_processed": total_processed,
                            "total_customers": total_customers,
                            "total_ignored": total_ignored,
                        },
                    )

            # Process events if enabled
            events_processed = 0
            if self.config.arctichub.enable_events:
                events_processed = self._process_events(work_id, current_state or {})

            current_state = self.helper.get_state() or {}
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%SZ")
            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%SZ")

            current_state["last_run"] = current_state_datetime
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, "
                f"processed {total_processed} customers out of {total_customers}, "
                f"ignored {total_ignored} customers, "
                f"processed {events_processed} events, "
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

    def _send_bundle(self, octi_objects: list, work_id: str) -> None:
        """Convert SDK objects to STIX and send a bundle to OpenCTI."""
        if not octi_objects:
            return
        stix_objects = [obj.to_stix2_object() for obj in octi_objects]
        stix_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            stix_bundle,
            update=self.config.connector.update_existing_data,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        self.helper.connector_logger.info(
            "[CONNECTOR] Bundle sent to OpenCTI",
            {"bundles_sent": str(len(bundles_sent)), "stix_objects": len(stix_objects)},
        )

    def _process_events(self, work_id: str, current_state: dict) -> int:
        """
        Fetch and process events from Arctic Hub, sending STIX bundles in batches.

        Events are filtered client-side to only process those observed after the last
        events run. State is updated with the latest observation time after processing.

        Args:
            work_id: The current OpenCTI work ID.
            current_state: The current connector state dict (used to read/write last_events_run).

        Returns:
            Number of events processed.
        """
        self.helper.connector_logger.info("[CONNECTOR] Starting events processing...")

        last_events_run_str = current_state.get("last_events_run")
        last_events_run: datetime | None = None
        if last_events_run_str:
            try:
                last_events_run = datetime.fromisoformat(last_events_run_str)
            except ValueError:
                pass

        if last_events_run:
            self.helper.connector_logger.info(
                "[CONNECTOR] Processing events since last run",
                {"last_events_run": last_events_run.isoformat()},
            )
        else:
            self.helper.connector_logger.info(
                "[CONNECTOR] First events run — processing all available events"
            )

        all_events = self.client.get_events()
        if not all_events:
            self.helper.connector_logger.info("[CONNECTOR] No events returned from API")
            return 0

        self.helper.connector_logger.info(
            "[CONNECTOR] Total events fetched from API", {"total": len(all_events)}
        )

        batch: List = []
        total_processed = 0
        total_skipped = 0
        latest_observation_time: datetime | None = None
        batch_size = self.config.arctichub.events_batch_size

        for event_data in all_events:
            event = event_data.get("event", {})

            # Filter: skip events already processed in a previous run
            obs_time_str = event.get("observation time")
            obs_time = self.converter_to_stix._parse_event_datetime(obs_time_str)
            if last_events_run and obs_time and obs_time <= last_events_run:
                total_skipped += 1
                continue

            octi_objects = self.converter_to_stix.process_event(event_data)
            if not octi_objects:
                total_skipped += 1
                continue

            batch.extend(octi_objects)
            total_processed += 1

            # Track the latest observation time seen
            if obs_time and (latest_observation_time is None or obs_time > latest_observation_time):
                latest_observation_time = obs_time

            # Send when batch is full
            if len(batch) >= batch_size:
                self._send_bundle(batch, work_id)
                self.helper.connector_logger.info(
                    "[CONNECTOR] Events batch sent",
                    {"events_processed_so_far": total_processed},
                )
                batch = []

        # Send remaining events
        if batch:
            self._send_bundle(batch, work_id)

        self.helper.connector_logger.info(
            "[CONNECTOR] Events processing complete",
            {
                "total_processed": total_processed,
                "total_skipped": total_skipped,
            },
        )

        # Persist the latest observation time so the next run can filter from here
        if latest_observation_time:
            current_state["last_events_run"] = latest_observation_time.isoformat()
            self.helper.set_state(current_state)

        return total_processed

    def is_customer_valid(self, customer_data: dict) -> bool:
        """
        Validate if a customer should be processed.

        Args:
            customer_data: Complete customer data dictionary from the API.

        Returns:
            True if the customer should be processed, False otherwise.
        """
        if "data" not in customer_data or "labels" not in customer_data["data"]:
            self.helper.connector_logger.info(
                "[CONNECTOR] Ignoring customer with invalid data structure",
                {"customer_data": customer_data},
            )
            return False

        data = customer_data["data"]
        customer_name = data.get("name", "Unknown")
        labels = data["labels"]

        for ignored_pattern in self.config.arctichub.customers_ignored_names:
            if re.match(ignored_pattern, customer_name, re.IGNORECASE):
                self.helper.connector_logger.info(
                    "[CONNECTOR] Ignoring customer by name pattern",
                    {"customer": customer_name, "ignored_pattern": ignored_pattern},
                )
                return False

        if not labels.get("organization type"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Ignoring customer without organization type",
                {"customer": customer_name},
            )
            return False

        return True

    def run(self) -> None:
        """
        Start the connector, schedule its runs and trigger the first run.

        It allows you to schedule the process to run at a certain interval.
        This specific scheduler from the `OpenCTIConnectorHelper` will also check the queue size.
        If `CONNECTOR_QUEUE_THRESHOLD` is set and the queue exceeds the threshold,
        the connector will not run until the queue is sufficiently reduced.

        Example:
            - If `CONNECTOR_DURATION_PERIOD=P1D`, then the connector runs every day.
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
