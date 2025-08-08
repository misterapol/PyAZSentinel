"""
Utility functions for JSON operations.
"""

import json
import logging
from typing import Dict, Any, List, Union
from pathlib import Path
from ..models import AlertRuleCollection, HuntingRuleCollection, DataConnectorCollection
from ..utils.exceptions import ValidationError, ConfigurationError


logger = logging.getLogger(__name__)


class JSONHelper:
    """Helper class for JSON import/export operations."""

    @staticmethod
    def load_file(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load JSON data from file.

        Args:
            file_path: Path to JSON file

        Returns:
            Parsed JSON data

        Raises:
            ConfigurationError: If file cannot be read or parsed
        """
        try:
            path = Path(file_path)
            if not path.exists():
                raise ConfigurationError(f"File not found: {file_path}")

            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in file {file_path}: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to read file {file_path}: {e}")

    @staticmethod
    def save_file(data: Dict[str, Any], file_path: Union[str, Path], indent: int = 2) -> None:
        """
        Save data to JSON file.

        Args:
            data: Data to save
            file_path: Output file path
            indent: JSON indentation

        Raises:
            ConfigurationError: If file cannot be written
        """
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent, ensure_ascii=False, default=str)

            logger.info(f"Saved JSON data to {file_path}")
        except Exception as e:
            raise ConfigurationError(f"Failed to save file {file_path}: {e}")

    @staticmethod
    def parse_alert_rules(data: Dict[str, Any]) -> AlertRuleCollection:
        """
        Parse alert rules from JSON data.

        Args:
            data: JSON data containing alert rules

        Returns:
            Parsed alert rule collection

        Raises:
            ValidationError: If data is invalid
        """
        try:
            return AlertRuleCollection.parse_obj(data)
        except Exception as e:
            raise ValidationError(f"Failed to parse alert rules: {e}")

    @staticmethod
    def parse_single_alert_rule(data: Dict[str, Any]) -> AlertRuleCollection:
        """
        Parse a single alert rule from JSON data and wrap it in a collection.

        Args:
            data: JSON data containing a single alert rule

        Returns:
            Alert rule collection containing the single rule

        Raises:
            ValidationError: If data is invalid
        """
        try:
            # Try to determine the rule type based on properties
            rule_kind = data.get('kind', 'Scheduled')  # Default to Scheduled

            # Create a collection with the single rule
            collection_data = {}
            if rule_kind == 'Scheduled':
                collection_data['Scheduled'] = [data]
            elif rule_kind == 'Fusion':
                collection_data['Fusion'] = [data]
            elif rule_kind == 'MLBehaviorAnalytics':
                collection_data['MLBehaviorAnalytics'] = [data]
            elif rule_kind == 'MicrosoftSecurityIncidentCreation':
                collection_data['MicrosoftSecurityIncidentCreation'] = [data]
            elif rule_kind == 'ThreatIntelligence':
                collection_data['ThreatIntelligence'] = [data]
            else:
                # Default to Scheduled if unknown
                collection_data['Scheduled'] = [data]

            return AlertRuleCollection.parse_obj(collection_data)
        except Exception as e:
            raise ValidationError(f"Failed to parse single alert rule: {e}")

    @staticmethod
    def is_alert_rule_collection(data: Dict[str, Any]) -> bool:
        """
        Check if data represents an alert rule collection or a single alert rule.

        Args:
            data: JSON data to check

        Returns:
            True if data is a collection, False if it's a single rule
        """
        if data is None:
            return False

        # Check if data has collection keys
        collection_keys = {'Scheduled', 'Fusion', 'MLBehaviorAnalytics',
                          'MicrosoftSecurityIncidentCreation', 'ThreatIntelligence'}
        return any(key in data for key in collection_keys)

    @staticmethod
    def parse_hunting_rules(data: Dict[str, Any]) -> HuntingRuleCollection:
        """
        Parse hunting rules from JSON data.

        Args:
            data: JSON data containing hunting rules

        Returns:
            Parsed hunting rule collection

        Raises:
            ValidationError: If data is invalid
        """
        try:
            return HuntingRuleCollection.parse_obj(data)
        except Exception as e:
            raise ValidationError(f"Failed to parse hunting rules: {e}")

    @staticmethod
    def parse_data_connectors(data: Dict[str, Any]) -> DataConnectorCollection:
        """
        Parse data connectors from JSON data.

        Args:
            data: JSON data containing data connectors

        Returns:
            Parsed data connector collection

        Raises:
            ValidationError: If data is invalid
        """
        try:
            return DataConnectorCollection.parse_obj(data)
        except Exception as e:
            raise ValidationError(f"Failed to parse data connectors: {e}")

    @staticmethod
    def to_dict(obj: Any) -> Dict[str, Any]:
        """
        Convert Pydantic model to dictionary.

        Args:
            obj: Pydantic model instance

        Returns:
            Dictionary representation
        """
        if hasattr(obj, 'model_dump'):
            return obj.model_dump(by_alias=True, exclude_none=True)
        elif hasattr(obj, 'dict'):
            return obj.dict(by_alias=True, exclude_none=True)
        return obj
