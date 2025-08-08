"""
Azure Sentinel Alert Rules service operations.
"""

import logging
from typing import Optional, List, Dict, Any, Union
from uuid import uuid4
from ..models import (
    AlertRule,
    AlertRuleCollection,
    ScheduledAlertRule,
    FusionAlertRule,
    MLBehaviorAnalyticsAlertRule,
    MicrosoftSecurityIncidentCreationAlertRule,
    ThreatIntelligenceAlertRule,
    AlertRuleKind
)
from ..utils.exceptions import ResourceNotFoundError, ValidationError
from .base_service import BaseService


logger = logging.getLogger(__name__)


class AlertRulesService(BaseService):
    """Service for managing Azure Sentinel alert rules."""

    def list(
        self,
        rule_kind: Optional[AlertRuleKind] = None,
        last_modified: Optional[str] = None
    ) -> List[AlertRule]:
        """
        List all alert rules in the workspace.

        Args:
            rule_kind: Filter by alert rule kind
            last_modified: Filter by last modified date (ISO 8601)

        Returns:
            List of alert rules
        """
        params = {"api-version": "2024-03-01"}
        if rule_kind:
            params["$filter"] = f"properties/kind eq '{rule_kind.value}'"
        if last_modified:
            if "$filter" in params:
                params["$filter"] += f" and properties/lastModifiedUtc gt {last_modified}"
            else:
                params["$filter"] = f"properties/lastModifiedUtc gt {last_modified}"

        response = self._list_resources("alertRules", params=params)
        return [AlertRule.parse_obj(rule) for rule in response]

    def get(self, rule_id: str) -> AlertRule:
        """
        Get a specific alert rule by ID.

        Args:
            rule_id: Alert rule ID or name

        Returns:
            Alert rule details

        Raises:
            ResourceNotFoundError: If rule doesn't exist
        """
        params = {"api-version": "2024-03-01"}
        try:
            response = self._get(f"alertRules/{rule_id}", params=params)
            return AlertRule.parse_obj(response)
        except ResourceNotFoundError:
            raise ResourceNotFoundError(f"Alert rule '{rule_id}' not found")

    def create(self, alert_rule: Union[Dict[str, Any], AlertRule]) -> AlertRule:
        """
        Create a new alert rule.

        Args:
            alert_rule: Alert rule configuration

        Returns:
            Created alert rule

        Raises:
            ValidationError: If rule configuration is invalid
        """
        if isinstance(alert_rule, dict):
            # Convert dict to appropriate model based on kind
            kind = alert_rule.get("kind", AlertRuleKind.SCHEDULED)
            alert_rule = self._dict_to_alert_rule(alert_rule, kind)

        rule_id = str(uuid4())
        params = {"api-version": "2024-03-01"}

        # Prepare request body
        request_body = {
            "properties": alert_rule.dict(by_alias=True, exclude_none=True)
        }

        response = self._put(f"alertRules/{rule_id}", data=request_body, params=params)
        return AlertRule.parse_obj(response)

    def update(self, rule_id: str, alert_rule: Union[Dict[str, Any], AlertRule]) -> AlertRule:
        """
        Update an existing alert rule.

        Args:
            rule_id: Alert rule ID
            alert_rule: Updated alert rule configuration

        Returns:
            Updated alert rule

        Raises:
            ResourceNotFoundError: If rule doesn't exist
            ValidationError: If rule configuration is invalid
        """
        # First check if rule exists
        existing_rule = self.get(rule_id)

        if isinstance(alert_rule, dict):
            kind = alert_rule.get("kind", existing_rule.properties.kind)
            alert_rule = self._dict_to_alert_rule(alert_rule, kind)

        # Prepare request body
        request_body = {
            "properties": alert_rule.dict(by_alias=True, exclude_none=True)
        }

        params = {"api-version": "2024-03-01"}
        response = self._put(f"alertRules/{rule_id}", data=request_body, params=params)
        return AlertRule.parse_obj(response)

    def delete(self, rule_id: str) -> None:
        """
        Delete an alert rule.

        Args:
            rule_id: Alert rule ID

        Raises:
            ResourceNotFoundError: If rule doesn't exist
        """
        params = {"api-version": "2024-03-01"}
        try:
            url = f"{self._get_workspace_url()}/alertRules/{rule_id}"
            self._make_request("DELETE", url, params=params)
            logger.info(f"Deleted alert rule: {rule_id}")
        except ResourceNotFoundError:
            raise ResourceNotFoundError(f"Alert rule '{rule_id}' not found")

    def enable(self, rule_id: str) -> AlertRule:
        """
        Enable an alert rule.

        Args:
            rule_id: Alert rule ID

        Returns:
            Updated alert rule
        """
        rule = self.get(rule_id)
        rule.properties.enabled = True
        return self.update(rule_id, rule.properties)

    def disable(self, rule_id: str) -> AlertRule:
        """
        Disable an alert rule.

        Args:
            rule_id: Alert rule ID

        Returns:
            Updated alert rule
        """
        rule = self.get(rule_id)
        rule.properties.enabled = False
        return self.update(rule_id, rule.properties)

    def import_from_collection(self, collection: AlertRuleCollection) -> List[AlertRule]:
        """
        Import multiple alert rules from a collection.

        Args:
            collection: Alert rule collection

        Returns:
            List of created alert rules
        """
        created_rules = []

        # Import scheduled rules
        if collection.scheduled:
            for rule in collection.scheduled:
                created_rule = self.create(rule)
                created_rules.append(created_rule)

        # Import fusion rules
        if collection.fusion:
            for rule in collection.fusion:
                created_rule = self.create(rule)
                created_rules.append(created_rule)

        # Import ML behavior analytics rules
        if collection.ml_behavior_analytics:
            for rule in collection.ml_behavior_analytics:
                created_rule = self.create(rule)
                created_rules.append(created_rule)

        # Import Microsoft security incident creation rules
        if collection.microsoft_security_incident_creation:
            for rule in collection.microsoft_security_incident_creation:
                created_rule = self.create(rule)
                created_rules.append(created_rule)

        # Import threat intelligence rules
        if collection.threat_intelligence:
            for rule in collection.threat_intelligence:
                created_rule = self.create(rule)
                created_rules.append(created_rule)

        logger.info(f"Imported {len(created_rules)} alert rules")
        return created_rules

    def export_to_collection(self, rule_kind: Optional[AlertRuleKind] = None) -> AlertRuleCollection:
        """
        Export alert rules to a collection.

        Args:
            rule_kind: Filter by alert rule kind

        Returns:
            Alert rule collection
        """
        rules = self.list(rule_kind=rule_kind)

        collection_data = {
            "Scheduled": [],
            "Fusion": [],
            "MLBehaviorAnalytics": [],
            "MicrosoftSecurityIncidentCreation": [],
            "ThreatIntelligence": []
        }

        for rule in rules:
            if rule.properties.kind == AlertRuleKind.SCHEDULED:
                collection_data["Scheduled"].append(rule.properties.dict(by_alias=True))
            elif rule.properties.kind == AlertRuleKind.FUSION:
                collection_data["Fusion"].append(rule.properties.dict(by_alias=True))
            elif rule.properties.kind == AlertRuleKind.ML_BEHAVIOR_ANALYTICS:
                collection_data["MLBehaviorAnalytics"].append(rule.properties.dict(by_alias=True))
            elif rule.properties.kind == AlertRuleKind.MICROSOFT_SECURITY_INCIDENT_CREATION:
                collection_data["MicrosoftSecurityIncidentCreation"].append(rule.properties.dict(by_alias=True))
            elif rule.properties.kind == AlertRuleKind.THREAT_INTELLIGENCE:
                collection_data["ThreatIntelligence"].append(rule.properties.dict(by_alias=True))

        return AlertRuleCollection.parse_obj(collection_data)

    def _dict_to_alert_rule(self, data: Dict[str, Any], kind: AlertRuleKind):
        """Convert dictionary to appropriate alert rule model."""
        try:
            if kind == AlertRuleKind.SCHEDULED:
                return ScheduledAlertRule.parse_obj(data)
            elif kind == AlertRuleKind.FUSION:
                return FusionAlertRule.parse_obj(data)
            elif kind == AlertRuleKind.ML_BEHAVIOR_ANALYTICS:
                return MLBehaviorAnalyticsAlertRule.parse_obj(data)
            elif kind == AlertRuleKind.MICROSOFT_SECURITY_INCIDENT_CREATION:
                return MicrosoftSecurityIncidentCreationAlertRule.parse_obj(data)
            elif kind == AlertRuleKind.THREAT_INTELLIGENCE:
                return ThreatIntelligenceAlertRule.parse_obj(data)
            else:
                raise ValidationError(f"Unsupported alert rule kind: {kind}")
        except Exception as e:
            raise ValidationError(f"Failed to parse alert rule: {e}")
