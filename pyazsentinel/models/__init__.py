"""
Data models for Azure Sentinel operations.
"""

from .enums import *
from .alert_rule import *
from .hunting_rule import *
from .incident import *
from .data_connector import *

__all__ = [
    # Enums
    "AlertRuleKind",
    "AlertSeverity",
    "TriggerOperator",
    "IncidentStatus",
    "IncidentSeverity",
    "IncidentClassification",
    "IncidentClassificationReason",
    "AttackTactic",
    "DataConnectorKind",
    "EntityType",
    "AggregationKind",

    # Alert Rules
    "AlertRuleTemplate",
    "ScheduledAlertRule",
    "FusionAlertRule",
    "MLBehaviorAnalyticsAlertRule",
    "MicrosoftSecurityIncidentCreationAlertRule",
    "ThreatIntelligenceAlertRule",
    "AlertRuleAction",
    "AlertRule",
    "AlertRuleCollection",

    # Hunting Rules
    "HuntingRule",
    "HuntingRuleWithMetadata",
    "HuntingRuleCollection",

    # Incidents
    "IncidentLabel",
    "IncidentOwner",
    "IncidentComment",
    "Incident",
    "IncidentWithMetadata",
    "IncidentUpdate",

    # Data Connectors
    "DataConnectorTenantId",
    "DataConnector",
    "AzureActivityLogDataConnector",
    "AzureSecurityCenterDataConnector",
    "MicrosoftCloudAppSecurityDataConnector",
    "ThreatIntelligenceDataConnector",
    "Office365DataConnector",
    "AmazonWebServicesCloudTrailDataConnector",
    "AzureActiveDirectoryDataConnector",
    "GenericUIDataConnector",
    "DataConnectorWithMetadata",
    "DataConnectorCollection",
]
