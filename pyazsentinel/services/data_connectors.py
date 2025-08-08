"""
Azure Sentinel Data Connectors Service

This module provides functionality for managing Azure Sentinel data connectors,
including listing, enabling, disabling, and configuring data connectors.
"""

from typing import List, Optional, Dict, Any
from ..models.data_connector import DataConnector
from .base_service import BaseService


class DataConnectorsService(BaseService):
    """Service for managing Azure Sentinel data connectors."""

    def __init__(self, credential, subscription_id: str, resource_group_name: str, workspace_name: str):
        """
        Initialize the data connectors service.

        Args:
            credential: Azure credential object
            subscription_id: Azure subscription ID
            resource_group_name: Name of the resource group
            workspace_name: Name of the Log Analytics workspace
        """
        super().__init__(credential, subscription_id, resource_group_name, workspace_name)

    def list_data_connectors(self, skip_token: Optional[str] = None) -> List[DataConnector]:
        """
        List all data connectors in the workspace.

        Args:
            skip_token: Skip token for pagination

        Returns:
            List of data connectors
        """
        params = {"api-version": "2024-03-01"}
        if skip_token:
            params["$skipToken"] = skip_token

        response = self._get("dataConnectors", params=params)

        connectors = []
        if "value" in response:
            for item in response["value"]:
                connectors.append(DataConnector.model_validate(item))

        return connectors

    def get_data_connector(self, connector_id: str) -> Optional[DataConnector]:
        """
        Get a specific data connector by ID.

        Args:
            connector_id: The data connector identifier

        Returns:
            The data connector if found, None otherwise
        """
        params = {"api-version": "2024-03-01"}

        try:
            response = self._get(f"dataConnectors/{connector_id}", params=params)
            return DataConnector.model_validate(response)
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                return None
            raise

    def create_data_connector(self, data_connector: DataConnector) -> DataConnector:
        """
        Create a new data connector.

        Args:
            data_connector: The data connector to create

        Returns:
            The created data connector
        """
        params = {"api-version": "2024-03-01"}

        # Convert to API format
        data = data_connector.model_dump(by_alias=True, exclude_none=True)

        response = self._put(f"dataConnectors/{data_connector.name}", params=params, data=data)
        return DataConnector.model_validate(response)

    def update_data_connector(self, connector_id: str, data_connector: DataConnector) -> DataConnector:
        """
        Update an existing data connector.

        Args:
            connector_id: The data connector identifier
            data_connector: The updated data connector data

        Returns:
            The updated data connector
        """
        params = {"api-version": "2024-03-01"}

        # Convert to API format
        data = data_connector.model_dump(by_alias=True, exclude_none=True)

        response = self._put(f"dataConnectors/{connector_id}", params=params, data=data)
        return DataConnector.model_validate(response)

    def delete_data_connector(self, connector_id: str) -> bool:
        """
        Delete a data connector.

        Args:
            connector_id: The data connector identifier

        Returns:
            True if deleted successfully
        """
        params = {"api-version": "2024-03-01"}

        self._delete(f"dataConnectors/{connector_id}", params=params)
        return True

    def enable_data_connector(self, connector_id: str) -> DataConnector:
        """
        Enable a data connector.

        Args:
            connector_id: The data connector identifier

        Returns:
            The updated data connector
        """
        connector = self.get_data_connector(connector_id)
        if not connector:
            raise Exception(f"Data connector {connector_id} not found")

        # Update state to enabled
        if connector.properties:
            connector.properties.state = "Enabled"

        return self.update_data_connector(connector_id, connector)

    def disable_data_connector(self, connector_id: str) -> DataConnector:
        """
        Disable a data connector.

        Args:
            connector_id: The data connector identifier

        Returns:
            The updated data connector
        """
        connector = self.get_data_connector(connector_id)
        if not connector:
            raise Exception(f"Data connector {connector_id} not found")

        # Update state to disabled
        if connector.properties:
            connector.properties.state = "Disabled"

        return self.update_data_connector(connector_id, connector)

    def import_data_connectors(self, file_path: str) -> List[DataConnector]:
        """
        Import data connectors from a JSON or YAML file.

        Args:
            file_path: Path to the file containing data connectors

        Returns:
            List of imported data connectors
        """
        from ..utils.json_helper import load_json_file
        from ..utils.yaml_helper import load_yaml_file

        imported_connectors = []

        try:
            if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                data = load_yaml_file(file_path)
            else:
                data = load_json_file(file_path)

            # Handle both single connector and array of connectors
            if isinstance(data, list):
                connectors_data = data
            else:
                connectors_data = [data]

            for connector_data in connectors_data:
                data_connector = DataConnector.model_validate(connector_data)
                created_connector = self.create_data_connector(data_connector)
                imported_connectors.append(created_connector)

        except Exception as e:
            raise Exception(f"Failed to import data connectors from {file_path}: {str(e)}")

        return imported_connectors

    def export_data_connectors(self, file_path: str, connector_ids: Optional[List[str]] = None) -> None:
        """
        Export data connectors to a JSON or YAML file.

        Args:
            file_path: Path where to save the data connectors
            connector_ids: Optional list of specific connector IDs to export. If None, exports all connectors.
        """
        from ..utils.json_helper import save_json_file
        from ..utils.yaml_helper import save_yaml_file

        if connector_ids:
            connectors = []
            for connector_id in connector_ids:
                connector = self.get_data_connector(connector_id)
                if connector:
                    connectors.append(connector)
        else:
            connectors = self.list_data_connectors()

        # Convert to serializable format
        connectors_data = [connector.model_dump(by_alias=True, exclude_none=True) for connector in connectors]

        try:
            if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                save_yaml_file(file_path, connectors_data)
            else:
                save_json_file(file_path, connectors_data)
        except Exception as e:
            raise Exception(f"Failed to export data connectors to {file_path}: {str(e)}")

    def get_data_connector_by_kind(self, kind: str) -> List[DataConnector]:
        """
        Get data connectors by their kind/type.

        Args:
            kind: The kind of data connector (e.g., 'AzureActiveDirectory', 'AzureSecurityCenter')

        Returns:
            List of data connectors of the specified kind
        """
        connectors = self.list_data_connectors()
        return [c for c in connectors if c.kind == kind]

    def get_available_data_connector_types(self) -> List[str]:
        """
        Get list of available data connector types in the workspace.

        Returns:
            List of data connector kinds/types
        """
        connectors = self.list_data_connectors()
        return list(set(c.kind for c in connectors if c.kind))

    def get_data_connector_status(self, connector_id: str) -> Dict[str, Any]:
        """
        Get the status and health information of a data connector.

        Args:
            connector_id: The data connector identifier

        Returns:
            Dictionary with connector status information
        """
        connector = self.get_data_connector(connector_id)
        if not connector:
            return {"error": f"Data connector {connector_id} not found"}

        status = {
            "id": connector.name,
            "kind": connector.kind,
            "state": connector.properties.state if connector.properties else "Unknown",
            "created_time": connector.properties.created_time_utc if connector.properties else None,
            "last_modified_time": connector.properties.last_modified_time_utc if connector.properties else None
        }

        return status

    def get_connector_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about data connectors in the workspace.

        Returns:
            Dictionary with connector statistics
        """
        connectors = self.list_data_connectors()

        stats = {
            "total": len(connectors),
            "by_kind": {},
            "by_state": {"Enabled": 0, "Disabled": 0, "Unknown": 0}
        }

        for connector in connectors:
            # Count by kind
            kind = connector.kind or "Unknown"
            stats["by_kind"][kind] = stats["by_kind"].get(kind, 0) + 1

            # Count by state
            state = connector.properties.state if connector.properties else "Unknown"
            if state in stats["by_state"]:
                stats["by_state"][state] += 1
            else:
                stats["by_state"]["Unknown"] += 1

        return stats

    def check_connector_prerequisites(self, kind: str) -> Dict[str, Any]:
        """
        Check prerequisites for a data connector type.

        Args:
            kind: The kind of data connector

        Returns:
            Dictionary with prerequisite information
        """
        # Common prerequisites by connector type
        prerequisites = {
            "AzureActiveDirectory": {
                "permissions": ["Security Reader", "Global Reader"],
                "requirements": ["Azure AD Premium P1 or P2 license"]
            },
            "AzureSecurityCenter": {
                "permissions": ["Security Reader", "Security Admin"],
                "requirements": ["Azure Security Center Standard tier"]
            },
            "Office365": {
                "permissions": ["Exchange Administrator", "Security Administrator"],
                "requirements": ["Office 365 or Microsoft 365 subscription"]
            },
            "ThreatIntelligence": {
                "permissions": ["Security Administrator"],
                "requirements": ["Azure Sentinel contributor role"]
            }
        }

        return prerequisites.get(kind, {
            "permissions": ["Security Administrator"],
            "requirements": ["Check connector-specific documentation"]
        })
