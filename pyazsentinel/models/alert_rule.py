"""
Data models for Azure Sentinel alert rules.
"""

from typing import Optional, List, Dict, Any, Union, Literal
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, field_validator
from .enums import AlertRuleKind, AlertSeverity, TriggerOperator, AttackTactic, AggregationKind


class AlertRuleTemplate(BaseModel):
    """Base template for alert rule configuration."""
    display_name: str = Field(..., description="Display name of the alert rule", alias="displayName")
    description: Optional[str] = Field(None, description="Description of the alert rule")
    severity: AlertSeverity = Field(..., description="Severity of the alert")
    enabled: bool = Field(True, description="Whether the rule is enabled")
    tactics: Optional[List[AttackTactic]] = Field(None, description="MITRE ATT&CK tactics")
    techniques: Optional[List[str]] = Field(None, description="MITRE ATT&CK techniques")


class ScheduledAlertRule(AlertRuleTemplate):
    """Scheduled alert rule configuration."""
    kind: Literal[AlertRuleKind.SCHEDULED] = AlertRuleKind.SCHEDULED
    query: str = Field(..., description="KQL query for the alert rule")
    query_frequency: str = Field(..., description="How often the query runs (ISO 8601)", alias="queryFrequency")
    query_period: str = Field(..., description="Time period for query data (ISO 8601)", alias="queryPeriod")
    trigger_operator: TriggerOperator = Field(..., description="Trigger operator", alias="triggerOperator")
    trigger_threshold: int = Field(..., description="Trigger threshold value", alias="triggerThreshold")
    suppression_duration: Optional[str] = Field(None, description="Suppression duration", alias="suppressionDuration")
    suppression_enabled: bool = Field(False, description="Whether suppression is enabled", alias="suppressionEnabled")
    event_grouping_aggregation_kind: Optional[AggregationKind] = Field(
        None, description="Event grouping aggregation method"
    )
    alert_details_override: Optional[Dict[str, Any]] = Field(
        None, description="Alert details override configuration"
    )
    entity_mappings: Optional[List[Dict[str, Any]]] = Field(
        None, description="Entity mappings configuration"
    )
    custom_details: Optional[Dict[str, str]] = Field(
        None, description="Custom details mapping"
    )
    incident_configuration: Optional[Dict[str, Any]] = Field(
        None, description="Incident configuration"
    )

    @field_validator('query_frequency', 'query_period', 'suppression_duration')
    @classmethod
    def validate_iso8601_duration(cls, v):
        """Validate ISO 8601 duration format."""
        if v is None:
            return v
        # Basic validation for ISO 8601 duration format (PT1H, P1D, etc.)
        if not v.startswith('P'):
            raise ValueError('Duration must be in ISO 8601 format (e.g., PT1H, P1D)')
        return v


class FusionAlertRule(AlertRuleTemplate):
    """Fusion alert rule configuration."""
    kind: Literal[AlertRuleKind.FUSION] = AlertRuleKind.FUSION
    source_settings: Optional[List[Dict[str, Any]]] = Field(
        None, description="Source settings for fusion rule"
    )


class MLBehaviorAnalyticsAlertRule(AlertRuleTemplate):
    """ML Behavior Analytics alert rule configuration."""
    kind: Literal[AlertRuleKind.ML_BEHAVIOR_ANALYTICS] = AlertRuleKind.ML_BEHAVIOR_ANALYTICS


class MicrosoftSecurityIncidentCreationAlertRule(AlertRuleTemplate):
    """Microsoft Security Incident Creation alert rule configuration."""
    kind: Literal[AlertRuleKind.MICROSOFT_SECURITY_INCIDENT_CREATION] = AlertRuleKind.MICROSOFT_SECURITY_INCIDENT_CREATION
    product_filter: str = Field(..., description="Product filter")
    display_names_filter: Optional[List[str]] = Field(
        None, description="Display names filter"
    )
    severities_filter: Optional[List[AlertSeverity]] = Field(
        None, description="Severities filter"
    )


class ThreatIntelligenceAlertRule(AlertRuleTemplate):
    """Threat Intelligence alert rule configuration."""
    kind: Literal[AlertRuleKind.THREAT_INTELLIGENCE] = AlertRuleKind.THREAT_INTELLIGENCE


class AlertRuleAction(BaseModel):
    """Alert rule action configuration."""
    logic_app_resource_id: str = Field(..., description="Logic app resource ID")
    trigger_uri: str = Field(..., description="Logic app trigger URI")


class AlertRule(BaseModel):
    """Complete alert rule with metadata."""
    id: Optional[str] = Field(None, description="Alert rule ID")
    name: Optional[str] = Field(None, description="Alert rule name")
    etag: Optional[str] = Field(None, description="Alert rule etag")
    type: Optional[str] = Field(None, description="Alert rule type")
    properties: Union[
        ScheduledAlertRule,
        FusionAlertRule,
        MLBehaviorAnalyticsAlertRule,
        MicrosoftSecurityIncidentCreationAlertRule,
        ThreatIntelligenceAlertRule
    ] = Field(..., description="Alert rule properties")
    actions: Optional[List[AlertRuleAction]] = Field(
        None, description="Alert rule actions"
    )
    created_date_utc: Optional[datetime] = Field(None, description="Creation date")
    last_modified_utc: Optional[datetime] = Field(None, description="Last modified date")


class AlertRuleCollection(BaseModel):
    """Collection of alert rules organized by type."""
    scheduled: Optional[List[ScheduledAlertRule]] = Field(None, alias="Scheduled")
    fusion: Optional[List[FusionAlertRule]] = Field(None, alias="Fusion")
    ml_behavior_analytics: Optional[List[MLBehaviorAnalyticsAlertRule]] = Field(
        None, alias="MLBehaviorAnalytics"
    )
    microsoft_security_incident_creation: Optional[List[MicrosoftSecurityIncidentCreationAlertRule]] = Field(
        None, alias="MicrosoftSecurityIncidentCreation"
    )
    threat_intelligence: Optional[List[ThreatIntelligenceAlertRule]] = Field(
        None, alias="ThreatIntelligence"
    )

    class Config:
        populate_by_name = True
