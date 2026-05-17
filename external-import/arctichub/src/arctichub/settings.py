from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="a3f2e1d0-c4b5-6789-abcd-ef0123456789",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Arctic Hub",
    )
    scope: ListFromString = Field(
        description="The scope or type of data the connector is importing.",
        default=["arctichub"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )
    update_existing_data: bool = Field(
        description="Whether to update existing data in OpenCTI.",
        default=False,
    )


class ArctichubConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ConnectorArctichub`.
    """

    api_base_url: HttpUrl = Field(
        description="Arctic Hub API base URL.",
    )
    api_events_path: str = Field(
        description="Path to the events API endpoint.",
        default="storage/v1/events",
    )
    api_customers_path: str = Field(
        description="Path to the customers API endpoint.",
        default="config/v1/customers",
    )
    api_customers_key: SecretStr = Field(
        description="API key for the customers endpoint.",
    )
    enable_events: bool = Field(
        description="Whether to enable events ingestion from Arctic Hub.",
        default=False,
    )
    api_events_key: SecretStr | None = Field(
        description="API key for the events endpoint. Required when enable_events is true.",
        default=None,
    )
    events_batch_size: int = Field(
        description="Number of events to include in each STIX bundle.",
        default=500,
    )
    ip_cidr_expansion: bool = Field(
        description="Whether to expand CIDR ranges into individual IP addresses.",
        default=False,
    )
    ip_cidr_expansion_max_host_size: int = Field(
        description="Maximum number of hosts in a CIDR range before falling back to CIDR notation.",
        default=65536,
    )
    ip_cidr_expansion_private_networks: bool = Field(
        description="Whether to filter out private network addresses during CIDR expansion.",
        default=False,
    )
    customers_ignored_names: ListFromString = Field(
        description="Regex patterns for customer names to ignore. Accepts a list or a comma-separated string.",
        default=[],
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ArctichubConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    arctichub: ArctichubConfig = Field(default_factory=ArctichubConfig)
