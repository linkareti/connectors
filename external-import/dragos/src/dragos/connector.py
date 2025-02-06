import sys
from datetime import datetime, timedelta
from typing import Generator, List, Callable

from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .dragos_portal_client_api import DragosClient
from .indicator_type_not_supported_error import IndicatorTypeNotSupportedError
from .ReportCache import ReportCache

from .constants import (
    GEOGRAPHIC_LOCATION_TYPE_MAP
)

from pycti import (
    AttackPattern,
    Indicator,
    OpenCTIConnectorHelper,
    ThreatActor,
)

class ConnectorDragos:
    def __init__(self):
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = DragosClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)
        self.batch_size = int(self.config.batch_size)
        self.report_indicators_cache = ReportCache()

    def process_indicator(self, data: dict) -> List[dict]:
        stix_objects = []

        observable = self.converter_to_stix.create_obs(data["value"])
        if observable is not None:
            stix_objects.append(observable)

        labels = self.converter_to_stix.get_default_labels()
        
        indicator = self.converter_to_stix.create_indicator(
            indicator_type = data["indicator_type"],
            value = data["value"],
            name = data['value'],
            description = data.get("comment"),
            valid_from = data.get("first_seen"),
            created = data.get("first_seen"),
            modified = data.get("updated_at"),
            labels=labels,
            confidence=data.get("confidence")
        )
        stix_objects.append(indicator)

        based_on_relationship = self.converter_to_stix.create_relationship(
            source_id = indicator.id, 
            relationship_type = 'based-on', 
            target_id = observable.id,
        )
        
        stix_objects.append(based_on_relationship)

        # sighting = self.converter_to_stix.create_sighting(
        #     indicator = indicator,
        #     first_seen = data.get("first_seen"),
        #     last_seen = data.get("last_seen")
        # )
        # stix_objects.append(sighting)

        attack_patterns = self.handle_attack_techniques(indicator, data)
        if attack_patterns:
            stix_objects.extend(attack_patterns)

        threat_actors = self.handle_threat_groups(indicator, data)
        if threat_actors:
            stix_objects.extend(threat_actors)

        # Additional handlers can be added here as needed for other fields
        # e.g., handle_kill_chains(indicator, data)
        
        return stix_objects

    def handle_attack_techniques(self, indicator, data: dict) -> List[dict]:
        
        stix_objects = []
        
        labels = self.converter_to_stix.get_default_labels()
        
        # A helper function to process both attack and ICS techniques
        def add_technique(techniques, technique_type="attack"):
            for technique in techniques:
                # Handle the technique names differently for ics_attack_techniques if needed
                attack_pattern = self.converter_to_stix.create_attack_pattern(
                    name=technique, 
                    #kill_chain_phases= #FIXME: extract kill chain phases
                    created=indicator.get("first_seen"),
                    modified=indicator.get("updated_at"),
                    labels=labels,
                    confidence=indicator.get("updated_at")
                )
                
                stix_objects.append(attack_pattern)

                # Create the relationship between indicator and attack pattern
                relationship = self.converter_to_stix.create_relationship(
                    source_id=indicator.id, 
                    relationship_type='indicates', 
                    target_id=attack_pattern.id,
                    created=indicator.get("first_seen"),
                    modified=indicator.get("updated_at")
                )
                
                stix_objects.append(relationship)
        
        # Process regular attack techniques
        if data.get("attack_techniques"):
            add_technique(data["attack_techniques"], technique_type="attack")
        
        # Process ICS attack techniques
        if data.get("ics_attack_techniques"):
            add_technique(data["ics_attack_techniques"], technique_type="ics")

    def handle_threat_groups(self, indicator, data: dict) -> List[dict]:
        stix_objects = []
        if data.get("threat_groups"):
            for group in data["threat_groups"]:

                threat_actor = self.converter_to_stix.create_threat_actor(group)
                stix_objects.append(threat_actor)
                
                relationship = self.converter_to_stix.create_relationship(
                    source_id = indicator.id, 
                    relationship_type = 'indicates', 
                    target_id = threat_actor.id,
                    created=indicator.get("first_seen"),
                    modified=indicator.get("updated_at")
                )
                
                stix_objects.append(relationship)
        
        return stix_objects
    
    def _process_indicators(self, indicators: List[dict]) -> Generator[List, None, None]:
        """Process indicators in batches and yield STIX objects"""
        current_batch = []
        
        # First add the organization as author
        organization = self.converter_to_stix.author
        current_batch.append(organization)
        
        for indicator in indicators:
            try:
                #cache the indicator to lower the need for reports to request adittional data from server
                #cache before processing because even if they are not supported requesting from reports would not improve that situation....
                self.report_indicators_cache.update_cache_report_with_indicator(indicator)
                
                indicator_stix_objects = self.process_indicator(indicator)
                current_batch.extend(indicator_stix_objects)
                
                # Yield batch if it reaches the configured size
                if len(current_batch) >= self.batch_size:
                    yield current_batch
                    current_batch = []
                    
            except IndicatorTypeNotSupportedError as e:
                self.helper.connector_logger.warning(e)
        
        # Yield any remaining objects in the final batch
        if current_batch:
            yield current_batch

    def report_object_refs_from_cache(self, report_data: dict) -> set:
        """
        Verify if cached indicators match the report's ioc_count and update report structure.
        
        Args:
            report_data: Dictionary containing report information
            
        Returns:
            - updated_report_data: Report data with object_refs if complete
        """
        serial = report_data["serial"]
        expected_count = report_data["ioc_count"]
        
        # Get cached indicators for this report
        cached_indicators = self.report_indicators_cache.get_report_indicators(serial)
        current_count = len(cached_indicators.keys())
        
        # Check if counts match
        if current_count != expected_count:
            
            indicators = self.client.get_report_ioc_csv(serial)
            for indicator in indicators:
                self.report_indicators_cache.update_cache_report_with_indicator(indicator)

        combined_set = set()

        cached_indicators = self.report_indicators_cache.get_report_indicators(serial)
        cached_techniques = self.report_indicators_cache.get_report_techniques(serial)
        cached_threat_groups = self.report_indicators_cache.get_report_threat_groups(serial)

        for value, metadata in cached_indicators.items():
            indicator_type = metadata["indicator_type"]
            pattern = self.converter_to_stix._generate_stix2_pattern(indicator_type, value)
            indicator_id = Indicator.generate_id(pattern)
            combined_set.add(indicator_id)

        for technique in cached_techniques:
            technique_id = AttackPattern.generate_id(technique, technique)
            combined_set.add(technique_id)
                
        for threat_group in cached_threat_groups:
            threat_group_id = ThreatActor.generate_id(threat_group, "Threat-Actor-Group")
            combined_set.add(threat_group_id)
    
        return combined_set

    def process_report(self, report: dict) -> List[dict]:
        stix_objects = []

        labels = self.converter_to_stix.get_default_labels()

        object_refs = list(self.report_object_refs_from_cache(report))

        stix_object_from_tags = self.handle_tags(report)
        stix_objects.extend(stix_object_from_tags)
        object_refs.extend([object_from_tag.id for object_from_tag in stix_object_from_tags])

        if not object_refs:
            self.helper.connector_logger.info(
                "[CONNECTOR] Report import ignored since it doesn't have any referenced object...",
                {"report_serial": report.get("serial")},
            )
            return []

        stix_report = self.converter_to_stix.create_report(
            name=report.get("title"),
            published=report.get("release_date"),
            object_refs=object_refs,
            created=report.get("release_date"),
            modified=report.get("updated_at"),
            description=report.get("executive_summary"),
            report_types=[report["type"]],
            labels=labels,
            confidence=None,
            tlp_level=report.get("tlp_level"),
            # report_status = None,
            threat_level=report.get("threat_level"),
            report_link=report.get("report_link"),
            slides_link=report.get("slides_link"),
        )

        stix_objects.append(stix_report)

        return stix_objects
    
    def handle_tags(self, report: dict) -> list:
        stix_objects = []

        locations = self.handle_report_geographic_locations(report)
        stix_objects.extend(locations)
        
        sectors = self.handle_report_industries(report)
        stix_objects.extend(sectors)

        attack_patterns = self.handle_report_attack_patterns(report)
        stix_objects.extend(attack_patterns)

        vendors = self.handle_report_vendors(report)
        stix_objects.extend(vendors)

        system_types = self.handle_report_system_types(report)
        stix_objects.extend(system_types)

        malwares = self.handle_report_malware(report)
        stix_objects.extend(malwares)

        softwares = self.handle_report_softwares(report)
        stix_objects.extend(softwares)

        return stix_objects

    def handle_report_geographic_locations(self, report: dict):
        stix_objects = []

        geographic_location_tags = [tag['text'] for tag in report['tags'] if tag['tag_type'] == 'GeographicLocation']

        for geographic_location in geographic_location_tags:

            location_type = GEOGRAPHIC_LOCATION_TYPE_MAP.get(geographic_location)

            if location_type == "Region":
                region = self.converter_to_stix.create_region(geographic_location)
                stix_objects.append(region)

            elif location_type == "Country":
                country = self.converter_to_stix.create_country(geographic_location)
                stix_objects.append(country)
            
        return stix_objects

    def handle_report_industries(self, report: dict):
        stix_objects = []

        industries_tags = [tag['text'] for tag in report['tags'] if tag['tag_type'] == 'Industry']

        for industry in industries_tags:
            sector = self.converter_to_stix.create_sector(industry)
            stix_objects.append(sector)
            
        return stix_objects

    def handle_report_attack_patterns(self, report: dict):
        stix_objects = []

        attack_patterns_tags = [tag['text'] for tag in report['tags'] if tag['tag_type'] == 'ATT&CK Technique']

        for attack_pattern_tag in attack_patterns_tags:
            attack_pattern = self.converter_to_stix.create_attack_pattern(attack_pattern_tag)
            stix_objects.append(attack_pattern)
            
        return stix_objects

    def handle_report_vendors(self, report: dict):
        stix_objects = []

        vendor_tags = [tag['text'] for tag in report['tags'] if tag['tag_type'] == 'Vendor']

        for vendor_tag in vendor_tags:
            vendor = self.converter_to_stix.create_identity(name = vendor_tag, identity_class="organization")
            stix_objects.append(vendor)
    
        return stix_objects
        
    def handle_report_system_types(self, report: dict):
        stix_objects = []
    
        system_type_tags = [tag['text'] for tag in report['tags'] if tag['tag_type'] == 'System Type']

        for system_type_tag in system_type_tags:
            system_type = self.converter_to_stix.create_infrastructure(name=system_type_tag)
            stix_objects.append(system_type)

        return stix_objects

    def handle_report_malware(self, report: dict):
        stix_objects = []
    
        malware_tags = [tag['text'] for tag in report['tags'] if tag['tag_type'] == 'Malware']

        for malware_tag in malware_tags:
            malware = self.converter_to_stix.create_malware(name=malware_tag)
            stix_objects.append(malware)

        return stix_objects

    def handle_report_softwares(self, report: dict):
        stix_objects = []

        software_tags = [tag['text'] for tag in report['tags'] if tag['tag_type'] == 'Software']

        for software_tag in software_tags:
            software = self.converter_to_stix.create_software(name=software_tag)
            stix_objects.append(software)
    
        return stix_objects

    def _process_reports(self, reports: List[dict]) -> Generator[List, None, None]:
        """Process reports in batches and yield STIX objects"""
        current_batch = []
        
        for report in reports:
            report_stix_objects = self.process_report(report)
            current_batch.extend(report_stix_objects)
            
            # Yield batch if it reaches the configured size
            if len(current_batch) >= self.batch_size:
                yield current_batch
                current_batch = []
        
        # Yield any remaining objects in the final batch
        if current_batch:
            yield current_batch

    def _date_interval(self, start_date_str: str, interval_in_days: int = 60) -> str | None:
        """
        Safely parses the start date (handling both with and without time) and
        calculates a future date by adding a specified number of days.

        Args:
            start_date_str (str): The start date string (either with or without time).
            days_to_add (int): The number of days to add to the start date (default 60 days).

        Returns:
            str: The future date as a string in the format "%Y-%m-%d %H:%M:%S".
        """
        try:
            # Attempt to parse with the full datetime format
            start_date = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            # Fallback to just the date format if full datetime format fails
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")

        # Calculate the future date by adding the specified number of days
        future_date = start_date + timedelta(days=interval_in_days)

        # Check if the future date is greater than the current date
        if future_date > datetime.now():
            return None
    
        # Return the future date as a string in the format "%Y-%m-%d %H:%M:%S"
        return future_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
    def process_message(self) -> None:
        """
        Connector main process to collect and stream intelligence
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now()
            current_state = self.helper.get_state() or {}

            if "last_run" in current_state:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": current_state["last_run"]},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            indicators_update_after = current_state.get("last_run", self.config.import_start_date)

            reports_update_after = current_state.get("report_import_date", self.config.import_start_date)
            reports_update_before = self._date_interval(reports_update_after, self.config.reports_import_interval)

            self._stream_indicators(indicators_update_after)
            self._stream_reports(reports_update_after, reports_update_before)

            # Update state
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            new_state = current_state or {}
            new_state["last_run"] = current_state_datetime
            new_state["report_import_date"] = reports_update_before if reports_update_before is not None else current_state_datetime
            self.helper.set_state(new_state)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def _stream_data(
            self, 
            update_after: str, 
            data_type: str, 
            process_function: Callable, 
            collect_function: Callable,
            update_before: str = None, 
            ) -> None:
        """
        Stream data from the source in batches of STIX objects.
        """
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"{data_type.capitalize()} from {update_after}" + (f" to {update_before}" if update_before else "")
        )

        self.helper.connector_logger.info(
            f"[CONNECTOR] {data_type.capitalize()} import started...",
            {"connector_name": self.helper.connect_name},
        )

        total_bundles_sent = 0
        
        data = collect_function(params={"updated_after": update_after})
        
        if update_before:
            filter_date_datetime = datetime.strptime(update_before, "%Y-%m-%dT%H:%M:%S.%fZ")
            filtered_data = [
                item for item in data
                if datetime.strptime(item["updated_at"], "%Y-%m-%dT%H:%M:%S.%fZ") < filter_date_datetime
            ]
        else:
            filtered_data = data
        
        for stix_batch in process_function(filtered_data):
            if stix_batch:
                stix_bundle = self.helper.stix2_create_bundle(stix_batch)
                bundles_sent = self.helper.send_stix2_bundle(stix_bundle, work_id=work_id)
                stix_bundle = None
                total_bundles_sent += len(bundles_sent)

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": len(bundles_sent)},
                )

        message = (f"{self.helper.connect_name} connector successfully processed {total_bundles_sent} {data_type}s ")

        self.helper.api.work.to_processed(work_id, message)
        self.helper.connector_logger.info(message)

    # Refactored methods using the _stream_data helper function

    def _stream_indicators(self, update_after: str) -> None:
        self._stream_data(
            update_after=update_after,
            data_type="indicators",
            process_function=self._process_indicators,
            collect_function=self.client.get_indicators
        )

    def _stream_reports(self, update_after: str, update_before: str) -> None:
        self._stream_data(
            update_after=update_after,
            update_before=update_before,
            data_type="reports",
            process_function=self._process_reports,
            collect_function=self.client.get_reports
        )

    def run(self) -> None:
        """Run the connector with scheduling"""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
