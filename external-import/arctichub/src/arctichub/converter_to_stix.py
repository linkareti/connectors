import ipaddress
from datetime import datetime, timezone
from typing import List

import validators

from connectors_sdk.models import (
    AutonomousSystem,
    DomainName,
    ExternalReference,
    File,
    IPV4Address,
    IPV6Address,
    Indicator,
    Infrastructure,
    Organization,
    OrganizationAuthor,
    Relationship,
    Sector,
    TLPMarking,
    URL,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType, TLPLevel
from pycti import OpenCTIConnectorHelper

from arctichub.settings import ConnectorSettings

_AnyOctiObject = (
    OrganizationAuthor
    | Organization
    | Sector
    | Infrastructure
    | IPV4Address
    | IPV6Address
    | DomainName
    | AutonomousSystem
    | Relationship
    | TLPMarking
    | Indicator
    | File
    | URL
)

# Maps Arctic Hub event types to STIX indicator types
_EVENT_TYPE_TO_INDICATOR_TYPE: dict[str, str] = {
    "scanner": "anomalous-activity",
    "brute-force": "malicious-activity",
    "c&c": "malicious-activity",
    "malware infection": "malicious-activity",
    "malware url": "malicious-activity",
    "phishing": "malicious-activity",
    "defacement": "malicious-activity",
    "artifact": "malicious-activity",
    "attribution": "malicious-activity",
    "dropzone": "malicious-activity",
    "exploitation": "malicious-activity",
    "spam infrastructure": "malicious-activity",
    "vulnerable service": "anomalous-activity",
    "weak encryption": "anomalous-activity",
}

# Maps artifact hash type names from Arctic Hub to STIX HashAlgorithm
_HASH_TYPE_MAP: dict[str, HashAlgorithm] = {
    "sha1": HashAlgorithm.SHA1,
    "sha256": HashAlgorithm.SHA256,
    "sha512": HashAlgorithm.SHA512,
    "md5": HashAlgorithm.MD5,
    "sha-1": HashAlgorithm.SHA1,
    "sha-256": HashAlgorithm.SHA256,
}


class ConverterToStix:
    """
    Provides methods for converting Arctic Hub data into SDK entities (STIX 2.1 compliant).

    Each method returns SDK model instances. Callers are responsible for calling
    `.to_stix2_object()` before bundling.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config
        self.author = self._create_author()

    @staticmethod
    def _create_author() -> OrganizationAuthor:
        """Create the connector's author organization."""
        return OrganizationAuthor(
            name="Arctic Hub",
            description=(
                "Arctic Security helps national cybersecurity authorities deploy early warning "
                "systems for cybersecurity. Arctic Hub is a powerful cybersecurity automation "
                "platform that collects, harmonizes, and packages threat information, and ensures "
                "quick and effective notifications for your stakeholders."
            ),
        )

    def _create_organization(
        self,
        name: str,
        description: str | None = None,
        contact_information: str | None = None,
    ) -> Organization:
        """Create an organization entity for a customer."""
        return Organization(
            name=name,
            description=description,
            contact_information=contact_information,
            author=self.author,
        )

    def _create_sector(self, name: str) -> Sector:
        """Create a sector entity."""
        return Sector(
            name=name,
            author=self.author,
        )

    def _create_infrastructure(self, name: str) -> Infrastructure:
        """Create an infrastructure entity."""
        return Infrastructure(
            name=name,
            author=self.author,
        )

    def _create_relationship(
        self,
        source: _AnyOctiObject,
        relationship_type: RelationshipType,
        target: _AnyOctiObject,
    ) -> Relationship:
        """Create a relationship between two SDK entities."""
        return Relationship(
            type=relationship_type,
            source=source,
            target=target,
            author=self.author,
        )

    def _create_observable(self, value: str) -> IPV4Address | IPV6Address | DomainName | None:
        """
        Create the appropriate observable based on the value type.

        Args:
            value: An IPv4 address, IPv6 address, or domain name string.

        Returns:
            The appropriate SDK observable, or None if the value is not recognized.
        """
        try:
            ipaddress.IPv6Address(value)
            return IPV6Address(value=value, author=self.author)
        except ipaddress.AddressValueError:
            pass

        try:
            ipaddress.ip_network(value, strict=False)
            return IPV4Address(value=value, author=self.author)
        except (ipaddress.AddressValueError, ValueError):
            pass

        if validators.domain(value):
            return DomainName(value=value, author=self.author)

        self.helper.connector_logger.error(
            "[CONNECTOR] Value is not a valid IPv4, IPv6, or domain name",
            {"value": value},
        )
        return None

    def _create_autonomous_system(self, number: int) -> AutonomousSystem:
        """Create an autonomous system observable."""
        return AutonomousSystem(
            number=number,
            name=f"ASN {number}",
            author=self.author,
        )

    def process_customer(self, customer_data: dict) -> List[_AnyOctiObject]:
        """
        Process customer data and return a list of SDK entities.

        Each customer maps to:
        - An Organization (the customer itself)
        - An Infrastructure (based on organization type label)
        - Sectors (ci sector and subsector) with part-of relationships
        - Domain name observables with belongs-to relationships
        - IP address observables with belongs-to and consists-of relationships
        - Autonomous system observables with related-to relationships

        Args:
            customer_data: Customer data dictionary from the Arctic Hub API.

        Returns:
            List of SDK entity objects (call `.to_stix2_object()` before bundling).
        """
        octi_objects: List[_AnyOctiObject] = []

        data = customer_data["data"]
        customer_name = data.get("name")
        labels = data["labels"]

        self.helper.connector_logger.info(
            "[CONNECTOR] Processing customer", {"customer": customer_name}
        )

        organization_type = labels.get("organization type")
        if not organization_type:
            return octi_objects

        # Flatten the address book to a contact information string if present
        address_book = data.get("address book")
        contact_information = None
        if address_book:
            if isinstance(address_book, list):
                contact_information = "; ".join(str(e) for e in address_book)
            else:
                contact_information = str(address_book)

        customer = self._create_organization(
            name=customer_name,
            description=labels.get("notes"),
            contact_information=contact_information,
        )
        octi_objects.append(customer)

        infrastructure = self._create_infrastructure(name=organization_type)
        octi_objects.append(infrastructure)

        octi_objects.extend(self._handle_sectors(labels, customer))
        octi_objects.extend(self._handle_domains(data, customer))
        octi_objects.extend(self._handle_ips(data, customer, infrastructure))
        octi_objects.extend(self._handle_autonomous_systems(data, customer))

        return octi_objects

    def _handle_sectors(self, labels: dict, customer: Organization) -> List[_AnyOctiObject]:
        """Build sector entities and part-of relationships from customer labels."""
        result: List[_AnyOctiObject] = []
        cisector = None
        subsector = None

        cisector_label = labels.get("ci sector")
        subsector_label = labels.get("subsector")

        if cisector_label:
            cisector = self._create_sector(name=cisector_label)
            result.append(cisector)
            result.append(
                self._create_relationship(
                    source=customer,
                    relationship_type=RelationshipType.PART_OF,
                    target=cisector,
                )
            )

        if subsector_label:
            subsector = self._create_sector(name=subsector_label)
            result.append(subsector)
            result.append(
                self._create_relationship(
                    source=customer,
                    relationship_type=RelationshipType.PART_OF,
                    target=subsector,
                )
            )

        if cisector and subsector:
            result.append(
                self._create_relationship(
                    source=subsector,
                    relationship_type=RelationshipType.PART_OF,
                    target=cisector,
                )
            )

        return result

    def _handle_domains(self, data: dict, customer: Organization) -> List[_AnyOctiObject]:
        """Build domain name observables and belongs-to relationships."""
        result: List[_AnyOctiObject] = []

        for domain_group in data.get("domain name", []):
            for domain_value in domain_group.get("domain name", []):
                observable = self._create_observable(value=domain_value)
                if observable is None:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Skipping unsupported domain name value",
                        {"customer": customer.name, "domain_name": domain_value},
                    )
                    continue

                result.append(observable)
                result.append(
                    self._create_relationship(
                        source=observable,
                        relationship_type=RelationshipType.BELONGS_TO,
                        target=customer,
                    )
                )

        return result

    def _handle_ips(
        self,
        data: dict,
        customer: Organization,
        infrastructure: Infrastructure,
    ) -> List[_AnyOctiObject]:
        """Build IP address observables and their relationships."""
        result: List[_AnyOctiObject] = []

        for ip_range_group in data.get("ip range", []):
            resolved_ips = self._resolve_ip_ranges(ip_range_group.get("ip range", []))

            for ip_value in resolved_ips:
                observable = self._create_observable(value=ip_value)
                if observable is None:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Skipping unsupported IP value",
                        {"customer": customer.name, "ip": ip_value},
                    )
                    continue

                result.append(observable)
                result.append(
                    self._create_relationship(
                        source=observable,
                        relationship_type=RelationshipType.BELONGS_TO,
                        target=customer,
                    )
                )
                result.append(
                    self._create_relationship(
                        source=infrastructure,
                        relationship_type=RelationshipType.CONSISTS_OF,
                        target=observable,
                    )
                )

        return result

    def _handle_autonomous_systems(
        self, data: dict, customer: Organization
    ) -> List[_AnyOctiObject]:
        """Build autonomous system observables and related-to relationships."""
        result: List[_AnyOctiObject] = []

        for asn_number in data.get("asn", []):
            autonomous_system = self._create_autonomous_system(number=asn_number)
            result.append(autonomous_system)
            result.append(
                self._create_relationship(
                    source=customer,
                    relationship_type=RelationshipType.RELATED_TO,
                    target=autonomous_system,
                )
            )

        return result

    def _resolve_ip_ranges(self, ip_ranges: list) -> List[str]:
        """Resolve a list of IP range entries into individual IP strings."""
        all_ips = []

        for ip_range in ip_ranges:
            if "/" in ip_range:
                all_ips.extend(self._resolve_cidr(ip_range))
            elif "-" in ip_range:
                all_ips.extend(self._expand_ip_range(ip_range))
            else:
                all_ips.append(ip_range)

        return all_ips

    def _resolve_cidr(self, cidr: str) -> List[str]:
        """
        Resolve a CIDR range, returning individual IPs if expansion is enabled and
        the range is within the configured size limit. Returns just the CIDR otherwise.
        IPv6 CIDRs are never expanded.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Resolving CIDR IP range", {"cidr": cidr}
        )

        try:
            ipaddress.IPv6Network(cidr, strict=False)
            self.helper.connector_logger.info(
                "[CONNECTOR] IPv6 ranges are not expanded, using CIDR format",
                {"cidr": cidr},
            )
            return [cidr]
        except (ipaddress.AddressValueError, ValueError):
            pass

        if not self.config.arctichub.ip_cidr_expansion:
            self.helper.connector_logger.info(
                "[CONNECTOR] CIDR expansion is disabled, using CIDR format",
                {"cidr": cidr},
            )
            return [cidr]

        network = ipaddress.ip_network(cidr, strict=False)

        if self.config.arctichub.ip_cidr_expansion_private_networks:
            hosts = [str(ip) for ip in network.hosts() if not ip.is_private]
        else:
            hosts = [str(ip) for ip in network.hosts()]

        if len(hosts) > self.config.arctichub.ip_cidr_expansion_max_host_size:
            self.helper.connector_logger.info(
                "[CONNECTOR] CIDR expansion exceeds max host size limit, using CIDR format",
                {"cidr": cidr, "total_hosts": len(hosts)},
            )
            return [cidr]

        return [cidr] + hosts

    def _expand_ip_range(self, ip_range: str) -> List[str]:
        """Expand an IP range interval (e.g. '10.0.0.1-10.0.0.5') into individual IPs."""
        self.helper.connector_logger.info(
            "[CONNECTOR] Expanding IP range interval", {"ip_range": ip_range}
        )

        start_str, end_str = ip_range.split("-")
        start_ip = ipaddress.ip_address(start_str.strip())
        end_ip = ipaddress.ip_address(end_str.strip())

        ip_list = []
        current = start_ip
        while current <= end_ip:
            ip_list.append(str(current))
            current += 1

        return ip_list

    # -------------------------------------------------------------------------
    # Events processing
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_event_datetime(value: str | None) -> datetime | None:
        """Parse an Arctic Hub datetime string (e.g. '2024-08-21 10:53:26Z') to an aware datetime."""
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _map_tlp_level(tlp_str: str | None) -> TLPLevel:
        """Map Arctic Hub TLP annotation string to a TLPLevel enum value."""
        mapping = {
            "red": TLPLevel.RED,
            "amber+strict": TLPLevel.AMBER_STRICT,
            "amber": TLPLevel.AMBER,
            "green": TLPLevel.GREEN,
            "white": TLPLevel.WHITE,
            "clear": TLPLevel.CLEAR,
        }
        return mapping.get((tlp_str or "").lower(), TLPLevel.RED)

    def _build_ip_indicator(
        self,
        ip: str,
        ip_version: str,
        tlp_marking: TLPMarking,
        ext_ref: ExternalReference,
        event: dict,
    ) -> Indicator:
        """Build an Indicator for the primary IP observable."""
        if ip_version == "6":
            pattern = f"[ipv6-addr:value = '{ip}']"
            obs_type = "IPv6-Addr"
        else:
            pattern = f"[ipv4-addr:value = '{ip}']"
            obs_type = "IPv4-Addr"

        return self._build_indicator(
            pattern=pattern,
            obs_type=obs_type,
            name=f"{event.get('type', 'unknown')}: {ip}",
            event=event,
            tlp_marking=tlp_marking,
            ext_ref=ext_ref,
        )

    def _build_domain_indicator(
        self,
        domain: str,
        tlp_marking: TLPMarking,
        ext_ref: ExternalReference,
        event: dict,
    ) -> Indicator:
        """Build an Indicator for a domain name observable."""
        return self._build_indicator(
            pattern=f"[domain-name:value = '{domain}']",
            obs_type="Domain-Name",
            name=f"{event.get('type', 'unknown')}: {domain}",
            event=event,
            tlp_marking=tlp_marking,
            ext_ref=ext_ref,
        )

    def _build_url_indicator(
        self,
        url: str,
        tlp_marking: TLPMarking,
        ext_ref: ExternalReference,
        event: dict,
    ) -> Indicator:
        """Build an Indicator for a URL observable."""
        return self._build_indicator(
            pattern=f"[url:value = '{url}']",
            obs_type="Url",
            name=f"{event.get('type', 'unknown')}: {url}",
            event=event,
            tlp_marking=tlp_marking,
            ext_ref=ext_ref,
        )

    def _build_hash_indicator(
        self,
        artifact_hash: str,
        artifact_hash_type: str,
        tlp_marking: TLPMarking,
        ext_ref: ExternalReference,
        event: dict,
    ) -> Indicator | None:
        """Build an Indicator for a file hash (artifact) observable."""
        hash_algo = _HASH_TYPE_MAP.get(artifact_hash_type.lower())
        if hash_algo is None:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Unsupported artifact hash type, skipping",
                {"hash_type": artifact_hash_type},
            )
            return None

        # STIX hash algorithm names use uppercase with hyphens (e.g. SHA-1, MD5)
        stix_hash_name = hash_algo.value
        return self._build_indicator(
            pattern=f"[file:hashes.'{stix_hash_name}' = '{artifact_hash}']",
            obs_type="StixFile",
            name=f"artifact: {artifact_hash_type.upper()} {artifact_hash[:16]}...",
            event=event,
            tlp_marking=tlp_marking,
            ext_ref=ext_ref,
        )

    def _build_indicator(
        self,
        pattern: str,
        obs_type: str,
        name: str,
        event: dict,
        tlp_marking: TLPMarking,
        ext_ref: ExternalReference,
    ) -> Indicator:
        """Build a generic Indicator from the provided pattern and event metadata."""
        event_type = event.get("type", "unknown")
        indicator_type = _EVENT_TYPE_TO_INDICATOR_TYPE.get(event_type, "unknown")

        description = event.get("description", "")
        additional_info = event.get("additional information")
        if additional_info:
            description = f"{description}\n\n{additional_info}"

        valid_from = (
            self._parse_event_datetime(event.get("first seen"))
            or self._parse_event_datetime(event.get("observation time"))
        )

        score = None
        mandiant_score = event.get("mandiant score")
        if mandiant_score is not None:
            try:
                score = int(mandiant_score)
            except (ValueError, TypeError):
                pass

        labels = [event_type]
        category = event.get("category")
        if category:
            labels.append(category)

        return Indicator(
            name=name,
            pattern=pattern,
            pattern_type="stix",
            main_observable_type=obs_type,
            description=description or None,
            indicator_types=[indicator_type],
            labels=labels,
            valid_from=valid_from,
            score=score,
            create_observables=True,
            author=self.author,
            markings=[tlp_marking],
            external_references=[ext_ref],
        )

    def process_event(self, event_data: dict) -> List[_AnyOctiObject]:
        """
        Process a single Arctic Hub event and return a list of SDK entities.

        Each event produces:
        - A TLPMarking from the event's TLP annotation
        - An Indicator for the primary IP address (always present)
        - An Indicator for the domain name, if present (phishing, defacement, attribution, etc.)
        - An Indicator for the URL, if present (malware url, defacement)
        - An Indicator for the artifact hash, if present (artifact type)

        All indicators have ``create_observables=True`` so OpenCTI will auto-create
        the corresponding observables.

        Args:
            event_data: A single event record from the Arctic Hub API.

        Returns:
            List of SDK entity objects (call ``.to_stix2_object()`` before bundling).
        """
        result: List[_AnyOctiObject] = []

        event = event_data.get("event", {})
        annotations = event_data.get("annotations", {})

        ip = event.get("ip")
        if not ip:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Skipping event without IP", {"uuid": event.get("uuid")}
            )
            return result

        # TLP marking — shared across all indicators from this event
        tlp_level = self._map_tlp_level(annotations.get("tlp"))
        tlp_marking = TLPMarking(level=tlp_level)
        result.append(tlp_marking)

        # External reference back to the data source
        feeder = event.get("feeder", "Arctic Hub")
        feed_url = event.get("description url") or event.get("feed url")
        ext_ref = ExternalReference(
            source_name=feeder,
            url=feed_url,
            external_id=event.get("uuid"),
        )

        # IP indicator (always)
        ip_version = event.get("ip version", "4")
        ip_indicator = self._build_ip_indicator(
            ip=ip,
            ip_version=ip_version,
            tlp_marking=tlp_marking,
            ext_ref=ext_ref,
            event=event,
        )
        result.append(ip_indicator)

        # Domain indicator (when present)
        domain = event.get("domain name")
        if domain:
            domain_indicator = self._build_domain_indicator(
                domain=domain,
                tlp_marking=tlp_marking,
                ext_ref=ext_ref,
                event=event,
            )
            result.append(domain_indicator)

        # URL indicator (when present)
        url = event.get("url")
        if url:
            url_indicator = self._build_url_indicator(
                url=url,
                tlp_marking=tlp_marking,
                ext_ref=ext_ref,
                event=event,
            )
            result.append(url_indicator)

        # Hash indicator (artifact type)
        artifact_hash = event.get("artifact hash")
        artifact_hash_type = event.get("artifact hash type", "")
        if artifact_hash and artifact_hash_type:
            hash_indicator = self._build_hash_indicator(
                artifact_hash=artifact_hash,
                artifact_hash_type=artifact_hash_type,
                tlp_marking=tlp_marking,
                ext_ref=ext_ref,
                event=event,
            )
            if hash_indicator:
                result.append(hash_indicator)

        return result
