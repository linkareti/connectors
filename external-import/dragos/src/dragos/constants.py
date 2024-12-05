
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

X_OPENCTI_ALIASES = "x_opencti_aliases"
X_OPENCTI_ORGANIZATION_TYPE = "x_opencti_organization_type"
X_OPENCTI_RELIABILITY = "x_opencti_reliability"
X_OPENCTI_LOCATION_TYPE = "x_opencti_location_type"
X_MITRE_ID = "x_mitre_id"
X_OPENCTI_REPORT_STATUS = "x_opencti_report_status"
X_OPENCTI_SCORE = "x_opencti_score"
X_OPENCTI_LABELS = "x_opencti_labels"
X_OPENCTI_CREATED_BY_REF = "x_opencti_created_by_ref"
X_OPENCTI_MAIN_OBSERVABLE_TYPE = "x_opencti_main_observable_type"
X_OPENCTI_EXTERNAL_REFERENCES = "x_opencti_external_references"

DEFAULT_X_OPENCTI_SCORE = 50

INDICATOR_TYPE_MAPPING = {
    "domain": {
        "pattern": "[domain-name:value = '{value}']",
        "observable_type": "Domain-Name"
    },
    "ip": {
        "pattern": "[ipv4-addr:value = '{value}']",
        "observable_type": "IPv4-Addr",
    },
    "md5": {
        "pattern": "[file:hashes.'MD5' = '{value}']",
        "observable_type": "StixFile",
    },
    "sha1": {
        "pattern": "[file:hashes.'SHA-1' = '{value}']",
        "observable_type": "StixFile",
    },
    "sha256": {
        "pattern": "[file:hashes.'SHA-256' = '{value}']",
        "observable_type": "StixFile",
    },
        "url": {
        "pattern": "[url:value = '{value}']",
        "observable_type": "StixFile",
    },
}

STIX_TLP_MAP = {
    "white": TLP_WHITE,
    "green": TLP_GREEN,
    "amber": TLP_AMBER,
    "red": TLP_RED,
}

CONFIDENCE_MAP = {
    "low": 40,
    "moderate": 60,
    "high": 100,   
}
