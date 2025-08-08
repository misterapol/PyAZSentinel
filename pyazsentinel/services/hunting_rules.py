"""
Azure Sentinel Hunting Rules Service

This module provides functionality for managing Azure Sentinel hunting rules,
including creating, reading, updating, and deleting hunting rules.
"""

from typing import List, Optional, Dict, Any
import json
from ..models.hunting_rule import HuntingRule
from .base_service import BaseService


class HuntingRulesService(BaseService):
    """Service for managing Azure Sentinel hunting rules."""

    def __init__(self, credential, subscription_id: str, resource_group_name: str, workspace_name: str):
        """
        Initialize the hunting rules service.

        Args:
            credential: Azure credential object
            subscription_id: Azure subscription ID
            resource_group_name: Name of the resource group
            workspace_name: Name of the Log Analytics workspace
        """
        super().__init__(credential, subscription_id, resource_group_name, workspace_name)

    def _get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Override _get to use Log Analytics URL instead of SecurityInsights."""
        url = f"{self._get_loganalytics_url()}/{endpoint}"
        return self._make_request("GET", url, params=params)

    def _put(self, endpoint: str, data: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Override _put to use Log Analytics URL instead of SecurityInsights."""
        url = f"{self._get_loganalytics_url()}/{endpoint}"
        return self._make_request("PUT", url, data=data, params=params)

    def _delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Override _delete to use Log Analytics URL instead of SecurityInsights."""
        url = f"{self._get_loganalytics_url()}/{endpoint}"
        return self._make_request("DELETE", url, params=params)

    def list_hunting_rules(self, skip_token: Optional[str] = None) -> List[HuntingRule]:
        """
        List all hunting rules in the workspace.

        Args:
            skip_token: Skip token for pagination

        Returns:
            List of hunting rules
        """
        params = {"api-version": "2020-08-01"}
        if skip_token:
            params["$skipToken"] = skip_token

        response = self._get("savedSearches", params=params)

        hunting_rules = []
        if "value" in response:
            for item in response["value"]:
                # Filter for hunting rules (saved searches with category 'Hunting Queries')
                if (item.get("properties", {}).get("category") == "Hunting Queries" or
                    "hunting" in item.get("properties", {}).get("tags", {}).get("tactics", [])):
                    hunting_rules.append(HuntingRule.model_validate(item))

        return hunting_rules

    def get_hunting_rule(self, rule_id: str) -> Optional[HuntingRule]:
        """
        Get a specific hunting rule by ID.

        Args:
            rule_id: The hunting rule identifier

        Returns:
            The hunting rule if found, None otherwise
        """
        params = {"api-version": "2020-08-01"}

        try:
            response = self._get(f"savedSearches/{rule_id}", params=params)
            return HuntingRule.model_validate(response)
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                return None
            raise

    def create_hunting_rule(self, hunting_rule: HuntingRule) -> HuntingRule:
        """
        Create a new hunting rule.

        Args:
            hunting_rule: The hunting rule to create

        Returns:
            The created hunting rule
        """
        params = {"api-version": "2020-08-01"}

        # Convert to API format
        data = hunting_rule.model_dump(by_alias=True, exclude_none=True)

        response = self._put(f"savedSearches/{hunting_rule.name}", data=data, params=params)
        return HuntingRule.model_validate(response)

    def update_hunting_rule(self, rule_id: str, hunting_rule: HuntingRule) -> HuntingRule:
        """
        Update an existing hunting rule.

        Args:
            rule_id: The hunting rule identifier
            hunting_rule: The updated hunting rule data

        Returns:
            The updated hunting rule
        """
        params = {"api-version": "2020-08-01"}

        # Convert to API format
        data = hunting_rule.model_dump(by_alias=True, exclude_none=True)

        response = self._put(f"savedSearches/{rule_id}", data=data, params=params)
        return HuntingRule.model_validate(response)

    def delete_hunting_rule(self, rule_id: str) -> bool:
        """
        Delete a hunting rule.

        Args:
            rule_id: The hunting rule identifier

        Returns:
            True if deleted successfully
        """
        params = {"api-version": "2020-08-01"}

        self._delete(f"savedSearches/{rule_id}", params=params)
        return True

    def import_hunting_rules(self, file_path: str) -> List[HuntingRule]:
        """
        Import hunting rules from a JSON or YAML file.

        Args:
            file_path: Path to the file containing hunting rules

        Returns:
            List of imported hunting rules
        """
        from ..utils.json_helper import load_json_file
        from ..utils.yaml_helper import load_yaml_file

        imported_rules = []

        try:
            if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                data = load_yaml_file(file_path)
            else:
                data = load_json_file(file_path)

            # Handle both single rule and array of rules
            if isinstance(data, list):
                rules_data = data
            else:
                rules_data = [data]

            for rule_data in rules_data:
                hunting_rule = HuntingRule.model_validate(rule_data)
                created_rule = self.create_hunting_rule(hunting_rule)
                imported_rules.append(created_rule)

        except Exception as e:
            raise Exception(f"Failed to import hunting rules from {file_path}: {str(e)}")

        return imported_rules

    def export_hunting_rules(self, file_path: str, rule_ids: Optional[List[str]] = None) -> None:
        """
        Export hunting rules to a JSON or YAML file.

        Args:
            file_path: Path where to save the hunting rules
            rule_ids: Optional list of specific rule IDs to export. If None, exports all rules.
        """
        from ..utils.json_helper import save_json_file
        from ..utils.yaml_helper import save_yaml_file

        if rule_ids:
            rules = []
            for rule_id in rule_ids:
                rule = self.get_hunting_rule(rule_id)
                if rule:
                    rules.append(rule)
        else:
            rules = self.list_hunting_rules()

        # Convert to serializable format
        rules_data = [rule.model_dump(by_alias=True, exclude_none=True) for rule in rules]

        try:
            if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                save_yaml_file(file_path, rules_data)
            else:
                save_json_file(file_path, rules_data)
        except Exception as e:
            raise Exception(f"Failed to export hunting rules to {file_path}: {str(e)}")

    def get_hunting_rule_by_name(self, name: str) -> Optional[HuntingRule]:
        """
        Get a hunting rule by its display name.

        Args:
            name: The display name of the hunting rule

        Returns:
            The hunting rule if found, None otherwise
        """
        rules = self.list_hunting_rules()
        for rule in rules:
            if rule.properties and rule.properties.display_name == name:
                return rule
        return None

    def search_hunting_rules(self, query: str) -> List[HuntingRule]:
        """
        Search hunting rules by query text in name or description.

        Args:
            query: Search query

        Returns:
            List of matching hunting rules
        """
        rules = self.list_hunting_rules()
        matching_rules = []

        query_lower = query.lower()
        for rule in rules:
            if rule.properties:
                if (query_lower in (rule.properties.display_name or "").lower() or
                    query_lower in (rule.properties.description or "").lower() or
                    query_lower in (rule.properties.query or "").lower()):
                    matching_rules.append(rule)

        return matching_rules
