"""
Data models for Azure Sentinel data connectors.
"""

from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field
from .enums import DataConnectorKind


class DataConnectorTenantId(BaseModel):
    """Data connector tenant ID configuration."""
    tenant_id: str = Field(..., description="Tenant ID")


class DataConnector(BaseModel):
    """Base data connector configuration."""
    kind: DataConnectorKind = Field(..., description="Data connector kind")
    tenant_id: Optional[str] = Field(None, description="Tenant ID")
    subscription_id: Optional[str] = Field(None, description="Subscription ID")


class AzureActivityLogDataConnector(DataConnector):
    """Azure Activity Log data connector."""
    kind: Literal[DataConnectorKind.AZURE_ACTIVITY_LOG] = DataConnectorKind.AZURE_ACTIVITY_LOG
    subscription_id: str = Field(..., description="Azure subscription ID")


class AzureSecurityCenterDataConnector(DataConnector):
    """Azure Security Center data connector."""
    kind: Literal[DataConnectorKind.AZURE_SECURITY_CENTER] = DataConnectorKind.AZURE_SECURITY_CENTER
    subscription_id: str = Field(..., description="Azure subscription ID")


class MicrosoftCloudAppSecurityDataConnector(DataConnector):
    """Microsoft Cloud App Security data connector."""
    kind: Literal[DataConnectorKind.MICROSOFT_CLOUD_APP_SECURITY] = DataConnectorKind.MICROSOFT_CLOUD_APP_SECURITY
    tenant_id: str = Field(..., description="Tenant ID")
    data_types: Optional[Dict[str, Any]] = Field(None, description="Data types configuration")


class ThreatIntelligenceDataConnector(DataConnector):
    """Threat Intelligence data connector."""
    kind: Literal[DataConnectorKind.THREAT_INTELLIGENCE] = DataConnectorKind.THREAT_INTELLIGENCE
    tenant_id: str = Field(..., description="Tenant ID")
    tip_lookbacks_lookups_state: Optional[str] = Field(None, description="TIP lookbacks state")


class Office365DataConnector(DataConnector):
    """Office 365 data connector."""
    kind: Literal[DataConnectorKind.OFFICE_365] = DataConnectorKind.OFFICE_365
    tenant_id: str = Field(..., description="Tenant ID")
    data_types: Optional[Dict[str, Any]] = Field(None, description="Data types configuration")


class AmazonWebServicesCloudTrailDataConnector(DataConnector):
    """AWS CloudTrail data connector."""
    kind: Literal[DataConnectorKind.AWS_CLOUD_TRAIL] = DataConnectorKind.AWS_CLOUD_TRAIL
    aws_role_arn: str = Field(..., description="AWS role ARN")


class AzureActiveDirectoryDataConnector(DataConnector):
    """Azure Active Directory data connector."""
    kind: Literal[DataConnectorKind.AZURE_ACTIVE_DIRECTORY] = DataConnectorKind.AZURE_ACTIVE_DIRECTORY
    tenant_id: str = Field(..., description="Tenant ID")
    data_types: Optional[Dict[str, Any]] = Field(None, description="Data types configuration")


class GenericUIDataConnector(DataConnector):
    """Generic UI data connector."""
    kind: Literal[DataConnectorKind.GENERIC_UI] = DataConnectorKind.GENERIC_UI
    connector_ui_config: Dict[str, Any] = Field(..., description="Connector UI configuration")


class DataConnectorWithMetadata(BaseModel):
    """Data connector with Azure metadata."""
    id: Optional[str] = Field(None, description="Data connector ID")
    name: Optional[str] = Field(None, description="Data connector name")
    etag: Optional[str] = Field(None, description="Data connector etag")
    type: Optional[str] = Field(None, description="Data connector type")
    properties: DataConnector = Field(..., description="Data connector properties")


class DataConnectorCollection(BaseModel):
    """Collection of data connectors."""
    data_connectors: List[DataConnector] = Field(default_factory=list, alias="DataConnectors")

    class Config:
        populate_by_name = True
