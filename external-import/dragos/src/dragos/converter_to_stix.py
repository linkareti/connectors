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
    StixSightingRelationship,
    ThreatActor,
)

from .constants import (
    INDICATOR_TYPE_MAPPING,
    STIX_TLP_MAP,
    CONFIDENCE_MAP,
    X_MITRE_ID,
    X_OPENCTI_EXTERNAL_REFERENCES,
    X_OPENCTI_LABELS,
    X_OPENCTI_REPORT_STATUS,
    X_OPENCTI_SCORE,
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
    
    @staticmethod
    def create_author() -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        #name=self.helper.connect_name
        author = stix2.Identity(
            id=Identity.generate_id(name="Dragos", identity_class="organization"),
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
    
    def create_sighting(
        self, 
        first_seen, 
        last_seen,
        indicator: stix2.Indicator = None, 
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
    ) -> stix2.Sighting:
        """
        Creates Sighting object
        """
        default_now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        sighting = stix2.Sighting(
            id = StixSightingRelationship.generate_id(
                indicator.id,
                self.author.id,
                first_seen,
                last_seen
            ),
            created = created,
            modified = modified,
            created_by_ref=self.author.id,
            first_seen=first_seen,
            last_seen=last_seen,
            count=1,
            sighting_of_ref=indicator.id
            #confidence=confidence,
            #labels ???
            
            #sighting_of_ref=stix_indicator["id"],
            #where_sighted_refs=[self.greynoise_identity["id"]],
            #external_references=external_reference,
            #object_marking_refs=stix2.TLP_WHITE,
            #            custom_properties={
            #    "x_opencti_sighting_of_ref": self.stix_entity["id"],
            #    "x_opencti_negative": True,
            #},
        )
        return sighting
    
    def create_attack_pattern(
        self, 
        name: str, 
        kill_chain_phases: Optional[List[stix2.KillChainPhase]] = None,
        external_references: Optional[List[stix2.ExternalReference]] = None,
        object_markings: Optional[List[stix2.MarkingDefinition]] = None,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        confidence: Optional[int] = None,
        labels: Optional[List[str]] = None,
        ) -> stix2.AttackPattern:
            """
            Creates AttackPattern object
            """
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
                id = ThreatActor.generate_id(name),
                created_by_ref = self.author,
                created = created,
                modified = modified,
                name = name,
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
    
    
    def process_indicator(self, data: Dict) -> List[Dict]:
        stix_objects = []

        observable = self.create_obs(data["value"])
        if observable is not None:
            stix_objects.append(observable)

        labels = self.get_default_labels() #["malicious-activity"], FIXME: what labels to use? malicious-activity? hacker?
        
        confidence = CONFIDENCE_MAP.get(data["confidence"], 60)
        
        indicator = self.create_indicator(
            indicator_type = data["indicator_type"],
            value = data["value"],
            name = f"Indicator for {data['value']}",
            description = data.get("comment"),
            valid_from = data.get("first_seen"),
            created = data.get("first_seen"),
            modified = data.get("updated_at"),
            labels=labels,
            confidence=confidence
        )
        stix_objects.append(indicator)

        sighting = self.create_sighting(
            indicator = indicator,
            first_seen = data.get("first_seen"),
            last_seen = data.get("last_seen")
        )
        stix_objects.append(sighting)

        attack_patterns = self.handle_attack_techniques(indicator, data)
        if attack_patterns:
            stix_objects.extend(attack_patterns)

        threat_actors = self.handle_threat_groups(indicator, data)
        if threat_actors:
            stix_objects.extend(threat_actors)

        # Additional handlers can be added here as needed for other fields
        # e.g., handle_kill_chains(indicator, data)
        
        return stix_objects

    def handle_attack_techniques(self, indicator, data: Dict) -> List[Dict]:
        
        stix_objects = []
        
        labels = self.get_default_labels() #["malicious-activity"], FIXME: what labels to use? malicious-activity? hacker?
        confidence = CONFIDENCE_MAP.get(indicator["confidence"], 60)
        
        # A helper function to process both attack and ICS techniques
        def add_technique(techniques, technique_type="attack"):
            for technique in techniques:
                # Handle the technique names differently for ics_attack_techniques if needed
                attack_pattern = self.create_attack_pattern(
                    name=technique, 
                    #kill_chain_phases= #FIXME: extract kill chain phases
                    created=indicator.get("first_seen"),
                    modified=indicator.get("updated_at"),
                    labels=labels,
                    confidence=confidence
                )
                
                stix_objects.append(attack_pattern)

                # Create the relationship between indicator and attack pattern
                relationship = self.create_relationship(
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


    def handle_threat_groups(self, indicator, data: Dict) -> List[Dict]:
        stix_objects = []
        if data.get("threat_groups"):
            for group in data["threat_groups"]:
                threat_actor = self.create_threat_actor(group)
                stix_objects.append(threat_actor)
                
                relationship = self.create_relationship(
                    source_id = indicator.id, 
                    relationship_type = 'indicates', 
                    target_id = threat_actor.id,
                    created=indicator.get("first_seen"),
                    modified=indicator.get("updated_at")
                )     
                
                stix_objects.append(relationship)
        
        return stix_objects
                
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
        external_references: Optional[List[stix2.ExternalReference]] = None,
        object_markings: Optional[List[stix2.MarkingDefinition]] = None,
        custom_properties: Optional[Dict[str, str]] = None,
        ) -> stix2.Report:
            """
            Creates Report object
            """        
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
                custom_properties = custom_properties,
                allow_custom=True,
            )
            
            return report

    def _get_report_external_references(self, report: Dict) -> List[stix2.ExternalReference]:
            """
            Creates External References for all the report links
            """
            external_references = []
            
            report_link = report["report_link"]
            if report_link:
                report_link_external_reference = self.create_external_reference(self.author.name, report_link, 'Report link')
                external_references.append(report_link_external_reference)
                
            slides_link = report["slides_link"]
            if slides_link:
                slides_link_external_reference = self.create_external_reference(self.author.name, slides_link, 'Slides link')
                external_references.append(slides_link_external_reference)
                                
            return external_references
    
    def add_external_reference(self, link, link_type, external_references):
        """
        Helper function to create and append an external reference if the link exists.
        """
        if link:
            external_reference = self.create_external_reference(self.author.name, link, link_type)
            external_references.append(external_reference)
         
    def process_report(self, data: Dict) -> List[Dict]:
        stix_objects = []
        external_references = []
        
        report_link = data.get("report_link")
        slides_link = data.get("slides_link")

        self.add_external_reference(report_link, 'Report link', external_references)
        self.add_external_reference(slides_link, 'Slides link', external_references)
        
        object_markings = STIX_TLP_MAP.get(data["tlp_level"], stix2.TLP_WHITE)

        labels = self.get_default_labels()

        report = self.create_report(
            name=data["title"],
            published=data["release_date"],
            object_refs=data['object_refs'],
            created=data["release_date"],
            modified=data["updated_at"],
            description=data["executive_summary"],
            report_types=None,
            labels=labels,
            confidence=None,
            external_references=external_references,
            object_markings=[object_markings],
            custom_properties={   # FIXME: what custom properties?
                    X_OPENCTI_SCORE: None,
                    X_OPENCTI_LABELS: None,
                    X_OPENCTI_EXTERNAL_REFERENCES: None,
                    X_OPENCTI_REPORT_STATUS: None
                }
        )

        stix_objects.append(report)
        
        return stix_objects

    def enrich_reports_with_indicators(self, reports: list, report_indicators: list) -> List[Dict]:
        """
        Enrich reports with indicators data and generate STIX2 patterns.
        :return: The list of reports enriched with indicator data
        """ 
        
        # Iterate over each report and match indicators by 'serial'
        for report in reports:
            report_serial = report['serial']
            
            # Find all indicators matching the current report serial
            matching_indicators = [
                indicator for indicator in report_indicators 
                if any(product['serial'] == report_serial for product in indicator['products'])
            ]
            
            # For each matching indicator, generate STIX2 pattern and update report
            for indicator in matching_indicators:
                indicator_type = indicator['indicator_type']
                value = indicator['value']

                if 'object_refs' not in report:
                    report['object_refs'] = []
                
                try:
                    pattern = self._generate_stix2_pattern(indicator_type, value)
                    indicator_id = Indicator.generate_id(pattern)
                 
                    report['object_refs'].append(indicator_id)
                except IndicatorTypeNotSupportedError as e:
                    self.helper.connector_logger.warning(
                        "Report with unsupported indicator",
                        {"report": report_serial, "indicator_type": indicator_type}
                    )
        
        return reports
    
    def get_default_labels(self) -> list:
        
        return [self.author.name]
