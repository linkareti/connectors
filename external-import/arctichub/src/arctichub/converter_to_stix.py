from datetime import datetime
from typing import Dict, List, Optional

import ipaddress

import stix2

from stix2.v21 import _DomainObject, _Observable, _RelationshipObject

import validators

from pycti import (
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Location,
    Infrastructure,
)

from pycti.utils.constants import LocationTypes

class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.author = self.create_author()
    
    def create_identity(
            self, 
            name: str, 
            identity_class: str, 
            description: str = None, 
            created_by_ref: stix2.Identity = None,
            contact_information: list = None,

            ) -> stix2.Identity:
        """
        Create an identity.
        :return: Identity in Stix2 object
        """
        identity = stix2.Identity(
            id=Identity.generate_id(name=name, identity_class=identity_class),
            name=name,
            created_by_ref=created_by_ref,
            identity_class=identity_class,
            description=description,
            contact_information=contact_information
        )

        return identity    

    def create_author(self) -> stix2.Identity:

        """
        Create Author
        :return: Author in Stix2 object
        """
        author = self.create_identity(
            name="Arctic Hub",
            identity_class="organization",
            description="Arctic Security helps national cybersecurity authorities deploy early warning systems for cybersecurity. Arctic Hub is a powerful cybersecurity automation platform that collects, harmonizes, and packages threat information, and ensures quick and effective notifications for your stakeholders.",
        )
        
        return author

    def create_organization(
            self, 
            name: str, 
            description: str,
            contact_information: list = None
            ) -> stix2.Identity:
        """
        Create an organization.
        :return: Organization in Stix2 object
        """
        organization = self.create_identity(
            name=name,
            identity_class="organization",
            description=description,
            created_by_ref=self.author,
            contact_information=contact_information
            )

        return organization
    
    def create_sector(self, name: str, description: str = None) -> stix2.Identity:
        """
        Create a sector.
        :return: Sector in Stix2 object
        """
        #TODO - should the sector be added to the organization?
        sector = self.create_identity(
            name=name,
            identity_class="class",
            description=description,
            created_by_ref=self.author
            )

        return sector

    
    def create_infrastructure(self, name: str) -> stix2.Infrastructure:
        """
        Create an infraestructure.
        :return: Infraestructure in Stix2 object
        """
        #TODO infeactructure type?
        infraestructure = stix2.Infrastructure(
            id=Infrastructure.generate_id(name),
            name=name,
            created_by_ref=self.author
            )

        return infraestructure
    
    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> dict:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
        )
        return relationship

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value: Value in string
        :return: A boolean
        """
        is_valid_ipv6 = validators.ipv6(value)

        if is_valid_ipv6:
            return True
        else:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4
        :param value: Value in string
        :return: A boolean
        """
        is_valid_ipv4 = validators.ipv4(value)

        if is_valid_ipv4:
            return True
        else:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

    def create_obs(self, value: str) -> dict:
        """
        Create observable according to value given
        :param value: Value in string
        :return: Stix object for IPV4, IPV6 or Domain
        """
        if self._is_ipv6(value) is True:
            stix_ipv6_address = stix2.IPv6Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
            return stix_domain_name
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
                {"value": value},
            )


    def create_indicator(
        self,
        indicator_type: str,
        value: str,
        pattern_type: str = 'stix',
        name: Optional[str] = None,
        description: Optional[str] = None,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        valid_from: Optional[datetime] = None,
        labels: Optional[List[str]] = None,
        confidence: Optional[int] = None,
    ) -> stix2.Indicator:
        """
        Creates Indicator object
        """  
        pattern = self._generate_stix2_pattern(indicator_type, value)
        
        indicator =  stix2.Indicator(
            id=Indicator.generate_id(pattern),
            created_by_ref=self.author,
            created = created,
            modified = modified,
            name=name,
            description=description,
            pattern=pattern,
            pattern_type=pattern_type,
            valid_from=valid_from,
            labels=labels,
            confidence=confidence,
        )
        return indicator
    
    def create_location(
        self,
        country: str,
        latitude: float,
        longitude: float,
        
        ) -> list[dict]:
        
        stix_location = stix2.Location(
            id=Location.generate_id(country, "Country"),
            name=country,
            country=country,
            created_by_ref=self.author,
            latitude=latitude,
            longitude=longitude,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_created_by_ref": self.author.id
            },
        )

        return stix_location

    def create_autonomous_system(self, name: str, number: int) -> dict:
        """
        Create autonomous system according to value given
        :param autonomous_system: autonomous system value
        :return: AutonomousSystem STIX2 object
        """

        stix_autonomous_system = stix2.AutonomousSystem(
            number=number,
            name=name,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id
            }
        )
        
        return stix_autonomous_system

    def process_customer(self, data: dict) -> List[ _DomainObject | _RelationshipObject | _Observable ]:
        """
        Process customer data to extract stix2 objects
        
        - Each customer should be an organization with organization type constituent.
            - We ignore organizations that have no label “organization type” set, these are normally for testing
            - Labels should be translated to sectors with the right links (ci sector and subsector)
        - Make an infrastructure (observations>Infrastructures) per organization type:
            - For now, these are “standard”,”ovi”,” eradication”, but with NISII, these will probably change a bit
            - This is needed for the monitoring dashboards we want to make
        - Each domain and IP (resolve the subnets as OpenCTI does not have that capability) should be an observable:
            - Link the observable to the organization
            - Add the observable to the right Infrastructure
        - Email addresses:
            - These should be added to the Contact information of the organization, these are not observables
        - ASN:
            - Only organizations like EDPNET have this value set
            - This is if the organization has the whole ASN create “stix2.AutonomousSystem and relationship with identity”

        
        :return: List of STIX2 objects
        """

        stix_objects = []

        # we want to ignore organizations with no label "organization type"
        if 'data' not in data or 'labels' not in data['data']:
            return stix_objects
        
        data_content = data['data']
        customer_name = data_content.get('name')
        labels = data_content['labels']

        print(f"Customer {customer_name} have {len(stix_objects)} objects")

        self.helper.connector_logger.info("Processing customer ", {"customer": customer_name})

        organization_type = labels.get('organization type', None)
        if not organization_type:
            self.helper.connector_logger.info("Ignoring customer without organization type", {"customer": customer_name})
            return stix_objects

        #create the organization for the customer
        customer = self.create_organization(
            name=customer_name,
            description=labels.get('notes', None),
            contact_information=data_content.get('address book', None)
            )

        stix_objects.append(customer)


        #create the infrastructure based on organization_type
        infrastructure = self.create_infrastructure(
            name=organization_type
        )

        stix_objects.append(infrastructure)

        # hadle sectors
        sectors = self.handle_sectors(labels, customer)
        stix_objects.extend(sectors)

        # hadle domains
        domains = self.handle_domains(data_content, customer)
        stix_objects.extend(domains)

        # hadle ips
        ips = self.handle_ips(data_content, customer)
        stix_objects.extend(ips)

        # hadle autonomous systems
        autonomous_systems = self.handle_autonomous_systems(data_content, customer)
        stix_objects.extend(autonomous_systems)

        return stix_objects

    def handle_sectors(self, labels: dict, customer: stix2.Identity):
        
        stix_sectors = []
        cisector = None
        subsector = None
        
        cisector_label = labels.get('ci sector', None)
        subsector_label = labels.get('subsector', None)
        
        if cisector_label:
            cisector=self.create_sector(name=cisector_label)
            stix_sectors.append(cisector)

            customer_cisector_relationship = self.create_relationship(
                source_id=customer.id,
                relationship_type="part-of",
                target_id=cisector.id,
            )

            stix_sectors.append(customer_cisector_relationship)


        if subsector_label:
            subsector=self.create_sector(name=subsector_label)
            stix_sectors.append(subsector)

            customer_subsector_relationship = self.create_relationship(
                source_id=customer.id,
                relationship_type="part-of",
                target_id=subsector.id,
            )

            stix_sectors.append(customer_subsector_relationship)

        if cisector and subsector:
            sector_subsector_relationship = self.create_relationship(
                source_id=subsector.id,
                relationship_type="part-of",
                target_id=cisector.id,
            )

            stix_sectors.append(sector_subsector_relationship)

        return stix_sectors

    def handle_domains(self, data_content: dict, customer: stix2.Identity):

        stix_domains = []
    
        for domain_name_root in data_content.get('domain name', []):
            for domain_name in domain_name_root.get('domain name', []):
                domain_name_observable = self.create_obs(value=domain_name)
                if domain_name_observable:
                    stix_domains.append(domain_name_observable)

                    domain_relationship = self.create_relationship(
                        source_id=domain_name_observable.id,
                        relationship_type="belongs-to",
                        target_id=customer.id,
                    )

                    stix_domains.append(domain_relationship)
                else:
                    self.helper.connector_logger.warning(
                        "Customer with unsupported domain name value",
                        {"customer": customer.id, "domain_name": domain_name}
                    )

        return stix_domains

    def handle_ips(self, data_content: dict, customer: stix2.Identity):

        stix_ips = []

        for ip_range_root in data_content.get('ip range', []):

            resolved_ip_range = self.resolve_ip_ranges(ip_range_root.get('ip range', []))

            for ip in resolved_ip_range:
                ip_address = self.create_obs(value=ip)
                if ip_address:
                    stix_ips.append(ip_address)

                    ip_relationship = self.create_relationship(
                        source_id=ip_address.id,
                        relationship_type="belongs-to",
                        target_id=customer.id,
                    )

                    stix_ips.append(ip_relationship)
                else:
                    self.helper.connector_logger.warning(
                        "Customer with unsupported ip value",
                        {"customer": customer.id, "ip": ip}
                    )

        return stix_ips

    def handle_autonomous_systems(self, data_content: dict, customer: stix2.Identity):
        
        stix_as = []
        
        # If there are ASNs present, create the AutonomousSystem objects
        for asn in data_content.get('asn', []):
            autonomous_system = self.create_autonomous_system(
                number=asn,
                name=f"ASN {asn}"
            )
            
            stix_as.append(autonomous_system)

            asn_relationship = self.create_relationship(
                source_id=customer.id,
                relationship_type="related-to",
                target_id=autonomous_system.id,
            )

            stix_as.append(asn_relationship)

        return stix_as

    # Function to resolve CIDR to IP addresses
    def resolve_ip_ranges(ip_ranges):
        """
        Function to resolve CIDR to IP addresses
        """
        
        all_ips = []
        
        for cidr in ip_ranges:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in network.hosts():
                all_ips.append(str(ip))
        
        return all_ips


    def resolve_cidr(self, cidr):
        """
        # Resolve a CIDR range into individual IPs
        """
        self.helper.connector_logger.info("Resolving cidr ip range", {"cidr": cidr})

        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]

    def expand_ip_range(self, ip_range):
        """
        # Resolve ip range interval to individual IPs
        """
        self.helper.connector_logger.info("Expanding ip range interval", {"ip_range": ip_range})
        
        start_ip, end_ip = ip_range.split('-')
        
        start_ip_obj = ipaddress.ip_address(start_ip.strip())
        end_ip_obj = ipaddress.ip_address(end_ip.strip())
        
        ip_list = []
        # Generate all IPs in the range
        current_ip = start_ip_obj
        while current_ip <= end_ip_obj:
            ip_list.append(str(current_ip))
            current_ip += 1

        return ip_list

    # Main function to resolve all IP ranges
    def resolve_ip_ranges(self, ip_ranges):
        all_ips = []
        
        # for ip_range in ip_ranges:
        #     if "/" in ip_range:  # CIDR format
        #         all_ips.extend(self.resolve_cidr(ip_range))
        #     elif "-" in ip_range:  # Start-end range
        #         all_ips.extend(self.expand_ip_range(ip_range))
        #     else:  # Single IP
        #         all_ips.append(ip_range)
        
        for ip_range in ip_ranges:
            if "-" in ip_range:  # Start-end range
                all_ips.extend(self.expand_ip_range(ip_range))
            else:
                all_ips.append(ip_range)

        return all_ips


