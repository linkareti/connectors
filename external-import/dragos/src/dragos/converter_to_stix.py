from datetime import datetime
from typing import Dict, List, Optional

import stix2
import validators
from pycti import (
    AttackPattern,
    Identity,
    Indicator,
    KillChainPhase,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    ThreatActor,
    Location,
)

from .constants import (
    INDICATOR_TYPE_MAPPING,
    STIX_TLP_MAP,
    X_MITRE_ID,
    CONFIDENCE_MAP,
    X_OPENCTI_REPORT_STATUS,
    X_OPENCTI_SCORE,
    DEFAULT_X_OPENCTI_SCORE,
    THREAT_LEVEL_MAP,
)

from .indicator_type_not_supported_error import IndicatorTypeNotSupportedError


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.author = self.create_author()

    @staticmethod
    def create_external_reference(
        source_name: str, url: str, description: str, external_id: Optional[str] = None
        ) -> stix2.ExternalReference:
        """
        Create external reference
        :return: STIX2 External reference 
        """
        external_reference = stix2.ExternalReference(
            source_name=source_name,
            url=url,
            description=description,
            external_id=external_id,
        )
        return external_reference
    
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
            contact_information=contact_information,
        )

        return identity
    
    def create_author(self) -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = self.create_identity(
            name="Dragos",
            identity_class="organization",
            description="Dragos WorldView",
        )

        return author


    def create_relationship(
        self, source_id: str, 
        relationship_type: str, 
        target_id: str,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
    ) -> stix2.Relationship:
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
            created_by_ref=self.author.id,
            created=created,
            modified=modified,
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

    @staticmethod
    def _is_md5(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_md5 = validators.md5(value)

        if is_valid_md5:
            return True
        else:
            return False

    @staticmethod
    def _is_sha1(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_sha1 = validators.sha1(value)

        if is_valid_sha1:
            return True
        else:
            return False

    @staticmethod
    def _is_sha256(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_sha256 = validators.sha256(value)

        if is_valid_sha256:
            return True

    @staticmethod
    def _is_url(value: str) -> bool:
        """
        Valid URL name 
        :param value: Value in string
        :return: A boolean
        """
        is_valid_url = validators.url(value)

        if is_valid_url:
            return True
        else:
            return False

    def create_obs(self, value: str) -> dict:
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
                custom_properties=custom_properties,
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                custom_properties=custom_properties,
            )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                custom_properties=custom_properties,
            )
            return stix_domain_name
        elif self._is_md5(value) is True:
            stix_md5 = stix2.File(
                hashes={'MD5': value},
                custom_properties=custom_properties,
            )
            return stix_md5
        elif self._is_sha1(value) is True:
            stix_sha1 = stix2.File(
                hashes={'SHA-1': value},
                custom_properties=custom_properties,
            )
            return stix_sha1
        elif self._is_sha256(value) is True:
            stix_sha256 = stix2.File(
                hashes={'SHA-256': value},
                custom_properties=custom_properties,
            )
            return stix_sha256
        elif self._is_url(value) is True:
            stix_url = stix2.URL(
                value=value,
                custom_properties=custom_properties,
            )
            return stix_url
        else:
            self.helper.connector_logger.warning(
                "Can't extract observable from value: ",
                {"value": value},
            )
            return None

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
        confidence: Optional[str] = None,
    ) -> stix2.Indicator:
        """
        Creates Indicator object
        """  
        pattern = self._generate_stix2_pattern(indicator_type, value)

        confidence = CONFIDENCE_MAP.get(confidence, 60)
        
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
    
    # def create_sighting(
    #     self, 
    #     first_seen, 
    #     last_seen,
    #     indicator: stix2.Indicator = None, 
    #     created: Optional[datetime] = None,
    #     modified: Optional[datetime] = None,
    # ) -> stix2.Sighting:
    #     """
    #     Creates Sighting object
    #     """
    #     sighting = stix2.Sighting(
    #         id = StixSightingRelationship.generate_id(
    #             indicator.id,
    #             self.author.id,
    #             first_seen,
    #             last_seen
    #         ),
    #         created = created,
    #         modified = modified,
    #         created_by_ref=self.author.id,
    #         first_seen=first_seen,
    #         last_seen=last_seen,
    #         count=1,
    #         sighting_of_ref=indicator.id,
    #         where_sighted_refs=None
            
    #     )
    #     return sighting
    
    def create_attack_pattern(
        self, 
        name: str, 
        kill_chain_phases: Optional[List[stix2.KillChainPhase]] = None,
        external_references: Optional[List[stix2.ExternalReference]] = None,
        object_markings: Optional[List[stix2.MarkingDefinition]] = None,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        confidence: Optional[str] = None,
        labels: Optional[List[str]] = None,
        ) -> stix2.AttackPattern:
            """
            Creates AttackPattern object
            """
            confidence = CONFIDENCE_MAP.get(confidence, 60)

            attack_pattern=stix2.AttackPattern(
                id=AttackPattern.generate_id(name, name),
                created_by_ref=self.author,
                created = created,
                modified = modified,
                name = name,
                confidence=confidence,
                external_references=external_references,
                object_marking_refs=object_markings,
                labels=labels,
                kill_chain_phases=kill_chain_phases,
                custom_properties={X_MITRE_ID: name},   
            )
            return attack_pattern

    def create_threat_actor(
        self, 
        name: str, 
        labels: Optional[List[str]] = None,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        ) -> stix2.ThreatActor:
            """
            Creates ThreatActor object
            """
            threat_actor=stix2.ThreatActor(
                id = ThreatActor.generate_id(name, "Threat-Actor-Group"),
                created_by_ref = self.author,
                created = created,
                modified = modified,
                name = name,
                resource_level=None,
                labels = labels,        
            )
            return threat_actor
        
    def create_kill_chain_phase(
        self, 
        phase_name: str, 
        kill_chain_name: str) -> stix2.KillChainPhase:
            """
            Creates KillChainPhase object
            """
            killChainPhase=stix2.KillChainPhase(
                id = KillChainPhase.generate_id(phase_name, kill_chain_name), 
                phase_name=phase_name,
                kill_chain_name=kill_chain_name,
                
            )
            return killChainPhase

    def _generate_stix2_pattern(self, indicator_type: str, value: str):
            
        mapping = INDICATOR_TYPE_MAPPING.get(indicator_type, None)

        if not mapping:
            raise IndicatorTypeNotSupportedError(f"Unsupported indicator type: {indicator_type}, value: {value}")

        indicator_pattern = mapping["pattern"].format(value=value)
        return indicator_pattern


    def create_country(
        self,
        name: str
        ) -> list[dict]:

        stix_location = stix2.Location(
            id=Location.generate_id(name, "Country"),
            name=name,
            country=name,
            created_by_ref=self.author,
            custom_properties={
                "x_opencti_location_type": "Country",
            },
        )

        return stix_location

    def create_region(
        self,
        name: str
        ) -> list[dict]:

        stix_location = stix2.Location(
            id=Location.generate_id(name, "Region"),
            name=name,
            region=name,
            created_by_ref=self.author,
            custom_properties={
                "x_opencti_location_type": "Region",
            },
        )

        return stix_location

    def create_sector(self, name: str, description: str = None) -> stix2.Identity:
        """
        Create a sector.
        :return: Sector in Stix2 object
        """
        sector = self.create_identity(
            name=name,
            identity_class="class",
            description=description,
            created_by_ref=self.author
            )

        return sector


    def create_report(
        self, 
        name: str,
        published: datetime,
        object_refs: List,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        description: Optional[str] = None,
        report_types: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        confidence: Optional[int] = None,
        tlp_level: Optional[str] = None,
        report_status: Optional[str] = None,
        threat_level: Optional[int] = None,
        report_link: Optional[str] = None,
        slides_link: Optional[str] = None,

        ) -> stix2.Report:
            """
            Creates Report object
            """
            object_markings = STIX_TLP_MAP.get(tlp_level, stix2.TLP_WHITE)

            opencti_score = THREAT_LEVEL_MAP.get(threat_level, DEFAULT_X_OPENCTI_SCORE)

            external_references = []

            self.add_external_reference(report_link, 'Report link', external_references)
            self.add_external_reference(slides_link, 'Slides link', external_references)
            
            report=stix2.Report(
                id=Report.generate_id(name, published),
                created_by_ref=self.author.id,
                created = created,
                modified = modified,
                name = name,
                description=description,
                report_types=report_types,
                published=published,
                object_refs=object_refs,
                labels=labels,
                confidence=confidence,
                external_references=external_references,
                object_marking_refs=object_markings,
                custom_properties={
                    # X_OPENCTI_REPORT_STATUS: report_status,
                    X_OPENCTI_SCORE: opencti_score
                },
                allow_custom=True,
            )
            
            return report

    def add_external_reference(self, link, link_type, external_references):
        """
        Helper function to create and append an external reference if the link exists.
        """
        if link:
            external_reference = self.create_external_reference(self.author.name, link, link_type)
            external_references.append(external_reference)
         
    def get_default_labels(self) -> list:
        
        return [self.author.name]
