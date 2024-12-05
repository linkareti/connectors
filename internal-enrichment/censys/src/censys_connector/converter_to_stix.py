from typing import Dict, List

import stix2
import validators
from pycti import (
    Identity, 
    StixCoreRelationship, 
    Vulnerability, 
    Location
)

class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="Censys", identity_class="organization"),
            name="Censys",
            identity_class="organization",
            description="Censys",
        )
        return author

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
        
    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str) -> dict:
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
            created_by_ref=self.author.id
        )
        return relationship
        
    def create_obs(self, value) -> dict:
        """
        Create observable according to value given
        :param value: Value in string
        :return: Stix object for IPV4, IPV6 or Domain
        """
        custom_properties={
            "x_opencti_created_by_ref": self.author.id
        }
        
        if self._is_ipv6(value) is True:
            stix_ipv6_address = stix2.IPv6Address(
                value=value,
                custom_properties=custom_properties
                )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                custom_properties=custom_properties
                )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                custom_properties=custom_properties,
            )
            return stix_domain_name

    def create_vulnerability(self, data: dict) -> dict:
        """
        Create observable according to value given
        :param data: Dictionary of vulnerability properties
        :return: Vulnerability STIX2 object
        """

        stix_vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(data["name"]),
            name=data["name"],
            created_by_ref=self.author.id
        )

        return stix_vulnerability

    def create_autonomous_system(self, autonomous_system: str, autonomous_system_number: int) -> dict:
        """
        Create autonomous system according to value given
        :param autonomous_system: autonomous system value
        :return: AutonomousSystem STIX2 object
        """

        stix_autonomous_system = stix2.AutonomousSystem(
            number=autonomous_system_number,
            name=autonomous_system,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id
            }
        )
        
        return stix_autonomous_system


    def create_x509(
        self, 
        issuer: str, 
        validity_not_before, 
        validity_not_after,
        subject: str,
        serial_number: str,
        signature_algorithm: str,
        subject_public_key_algorithm: str,
        hashes,
        version) -> dict:
        """
        Create x509 certificate according to value given
        :param ??: X509 value
        :return: X509Certificate STIX2 object
        """

        stix_x509 = stix2.X509Certificate(
            issuer=issuer,
            validity_not_before=validity_not_before,
            validity_not_after=validity_not_after,
            subject=subject,
            serial_number=serial_number,
            signature_algorithm=signature_algorithm,
            subject_public_key_algorithm=subject_public_key_algorithm,
            hashes=hashes,
            version=version,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id
            }
        )

        return stix_x509

    def create_location(
        self,
        city: str,
        country: str,
        latitude: float,
        longitude: float,
        
        ) -> list[dict]:
        
        stix_location = stix2.Location(
            id=Location.generate_id(city, "City"),
            name=city,
            country=country,
            latitude=latitude,
            longitude=longitude,
            custom_properties={
                "x_opencti_location_type": "City",
                "x_opencti_created_by_ref": self.author.id
            },
        )

        return stix_location
    
    def create_network_traffic(
        self, 
        dst_ip: str,
        dst_port: str, 
        protocols: list,
        ) -> dict:
        """
        Create a NetworkTraffic object to represent a service
        """
        stix_network_traffic = stix2.NetworkTraffic (
            dst_ref=dst_ip,
            dst_port=dst_port,
            protocols=protocols
        )

        return stix_network_traffic
    
    def create_software(
        self, 
        name: str,
        cpe: str,
        version: str,
        vendor: str
        ) -> dict:
        """
        Create a Software object to represent a service
        """
        stix_software = stix2.Software (
            name=name,
            cpe=cpe,
            version=version,
            vendor=vendor,
            allow_custom=True,
            custom_properties={
                "created_by_ref": self.author.id,
            }
        )

        return stix_software    
    
    def process_ip(self, ip_data: dict) -> List[Dict]:
        """Transform the retrieved Censys data for an IP address into STIX objects."""
        stix_objects = []

        if not ip_data:
            return stix_objects

        # Create an IPAddress STIX object
        ip_address = ip_data.get("ip")
        stix_ip = self.create_obs(ip_address)
        stix_objects.append(stix_ip)

        # Add location metadata if available
        location = ip_data.get("location", {})
        if location:
            coordinates = location.get("coordinates")
            stix_location = self.create_location(location.get("city"), location.get("country"), coordinates.get("latitude"), coordinates.get("longitude"))
            stix_objects.append(stix_location)

            location_relationship = self.create_relationship(stix_ip.id, "located-at", stix_location.id)
            stix_objects.append(location_relationship)

        # Add ASN metadata if available
        autonomous_system = ip_data.get("autonomous_system", None)
        if autonomous_system:
            stix_asn = self.create_autonomous_system(autonomous_system.get("name"), autonomous_system.get("asn"))
            stix_objects.append(stix_asn)

            asn_relationship = self.create_relationship(stix_ip.id, "related-to", stix_asn.id)
            stix_objects.append(asn_relationship)

        services = ip_data.get("services", [])
        for service in services:

            # Create NetworkTraffic STIX objects for each port
            port=service.get("port")
            protocol=service.get("transport_protocol")
            stix_traffic = self.create_network_traffic(stix_ip.id, port, [protocol])
            stix_objects.append(stix_traffic)

            service_relationship = self.create_relationship(stix_ip.id, "related-to", stix_traffic.id)
            stix_objects.append(service_relationship)

            # Create software objects for each service (if available)
            software_data = service.get("software", [])
            for software in software_data:
                cpe=software.get("uniform_resource_identifier")
                name=software.get("product")
                version=software.get("version")
                vendor=software.get("vendor")

                stix_software = self.create_software(name, cpe, version, vendor)
                stix_objects.append(stix_software)

                software_relationship = self.create_relationship(stix_ip.id, "related-to", stix_software.id)
                stix_objects.append(software_relationship)

        # Create Domain STIX objects for each dns
        if "dns" in ip_data and "names" in ip_data["dns"]:
            dns_names = ip_data["dns"]["names"]
            for dns in dns_names:
                stix_domain = self.create_obs(dns)
                stix_objects.append(stix_domain)

                dns_relationship = self.create_relationship(stix_domain.id, "resolves-to", stix_ip.id)
                stix_objects.append(dns_relationship)
 
        return stix_objects

    def process_domain(self, observable: Dict, domain_data: list) -> List[Dict]:

        stix_objects = []

        value = observable["value"]
        stix_domain = self.create_obs(value)
        stix_objects.append(stix_domain)

        for host in domain_data:

            ip_address = host.get("ip")
            stix_ip = self.create_obs(ip_address)
            stix_objects.append(stix_ip)

            dns_relationship = self.create_relationship(stix_domain.id, "resolves-to", stix_ip.id)
            stix_objects.append(dns_relationship)
        
        return stix_objects

    def process_domain_hosts(self, observable: Dict, domain_cert_data: list) -> List[Dict]:

        stix_objects = []

        value = observable["value"]
        stix_domain = self.create_obs(value)
        stix_objects.append(stix_domain)

        for certificate_data in domain_cert_data:

            issuer = certificate_data["parsed"]["issuer_dn"]
            validity_not_before = certificate_data["parsed"]["validity_period"]["not_before"]
            validity_not_after = certificate_data["parsed"]["validity_period"]["not_after"]
            subject = certificate_data["parsed"]["subject_dn"]

            hashes = {
                "SHA-256": certificate_data.get("fingerprint_sha256")
            }

            stix_x509 = self.create_x509(
                issuer,
                validity_not_before,
                validity_not_after,
                subject,
                "",
                "",
                "",
                hashes,
                "",
            )
            stix_objects.append(stix_x509)

            cert_relationship = self.create_relationship(stix_x509.id, "related-to", stix_domain.id)
            stix_objects.append(cert_relationship)

        return stix_objects


    def process_certificate(self, certificate_data: dict) -> List[Dict]:
        """Transform the retrieved Censys data for a certificate into STIX objects."""
        
        stix_objects = []
        
        if not certificate_data:
            return stix_objects

        # Create an X509 certificate STIX object
        issuer = certificate_data["parsed"]["issuer_dn"]
        validity_not_before = certificate_data["parsed"]["validity_period"]["not_before"]
        validity_not_after = certificate_data["parsed"]["validity_period"]["not_after"]
        subject = certificate_data["parsed"]["subject_dn"]
        serial_number = certificate_data["parsed"]["serial_number"]
        signature_algorithm = certificate_data["parsed"]["signature"]["signature_algorithm"]
        subject_public_key_algorithm = certificate_data["parsed"]["subject_key_info"]["key_algorithm"]["name"]

        hashes = {
            "SHA-256": certificate_data.get("fingerprint_sha256"),
            "SHA-1": certificate_data["fingerprint_sha1"],
            "MD5": certificate_data["fingerprint_md5"],
        }
   
        version = certificate_data["parsed"]["version"]

        stix_x509 = self.create_x509(
            issuer,
            validity_not_before,
            validity_not_after,
            subject,
            serial_number,
            signature_algorithm,
            subject_public_key_algorithm,
            hashes,
            version,
        )
        stix_objects.append(stix_x509)

        dns_names = certificate_data.get("names")
        for dns in dns_names:
            stix_domain = self.create_obs(dns)
            if stix_domain:
                stix_objects.append(stix_domain)

                dns_relationship = self.create_relationship(stix_x509.id, "related-to", stix_domain.id)
                stix_objects.append(dns_relationship)
 
        return stix_objects
