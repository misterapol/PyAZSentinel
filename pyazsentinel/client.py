"""
Main Azure Sentinel client for managing resources.
"""

import logging
from typing import Optional, Union
from azure.core.credentials import TokenCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient

from .auth import AzureSentinelAuth
from .services.alert_rules import AlertRulesService
from .services.hunting_rules import HuntingRulesService
from .services.incidents import IncidentsService
from .services.data_connectors import DataConnectorsService
from .utils.exceptions import ConfigurationError


logger = logging.getLogger(__name__)


class AzureSentinelClient:
    """
    Main client for Azure Sentinel operations.

    This client provides access to all Azure Sentinel services including
    alert rules, hunting rules, incidents, and data connectors.
    """

    def __init__(
        self,
        subscription_id: str,
        workspace_name: str,
        resource_group_name: Optional[str] = None,
        credential: Optional[TokenCredential] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        use_cli: bool = False,
        use_managed_identity: bool = False,
        auto_discover_resource_group: bool = True
    ):
        """
        Initialize Azure Sentinel client.

        Args:
            subscription_id: Azure subscription ID
            workspace_name: Log Analytics workspace name
            resource_group_name: Resource group name (auto-discovered if not provided)
            credential: Pre-configured Azure credential
            tenant_id: Azure tenant ID (required for service principal)
            client_id: Application client ID (required for service principal)
            client_secret: Application client secret (required for service principal)
            use_cli: Use Azure CLI authentication
            use_managed_identity: Use managed identity authentication
            auto_discover_resource_group: Auto-discover resource group if not provided
        """
        self.subscription_id = subscription_id
        self.workspace_name = workspace_name
        self.resource_group_name = resource_group_name

        # Set up authentication
        self.auth = AzureSentinelAuth(
            credential=credential,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            use_cli=use_cli,
            use_managed_identity=use_managed_identity
        )

        # Auto-discover resource group if not provided
        if not self.resource_group_name and auto_discover_resource_group:
            self.resource_group_name = self._discover_resource_group()

        if not self.resource_group_name:
            raise ConfigurationError(
                "Resource group name is required. Either provide it explicitly "
                "or enable auto_discover_resource_group."
            )

        # Initialize services
        self._init_services()

        logger.info(
            f"Initialized Azure Sentinel client for workspace '{workspace_name}' "
            f"in resource group '{self.resource_group_name}'"
        )

    def _init_services(self):
        """Initialize all service instances."""
        credential = self.auth.get_credential()

        # Alert Rules service
        self.alert_rules = AlertRulesService(
            credential=credential,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            workspace_name=self.workspace_name
        )

        # Hunting Rules service
        self.hunting_rules = HuntingRulesService(
            credential=credential,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            workspace_name=self.workspace_name
        )

        # Incidents service
        self.incidents = IncidentsService(
            credential=credential,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            workspace_name=self.workspace_name
        )

        # Data Connectors service
        self.data_connectors = DataConnectorsService(
            credential=credential,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            workspace_name=self.workspace_name
        )

    def _discover_resource_group(self) -> str:
        """
        Auto-discover the resource group containing the workspace.

        Returns:
            Resource group name

        Raises:
            ConfigurationError: If workspace cannot be found or multiple matches
        """
        try:
            credential = self.auth.get_credential()

            # Use Azure Resource Management client to find the workspace
            resource_client = ResourceManagementClient(credential, self.subscription_id)

            # Search for Log Analytics workspaces
            workspaces = []
            for resource_group in resource_client.resource_groups.list():
                try:
                    log_analytics_client = LogAnalyticsManagementClient(
                        credential, self.subscription_id
                    )
                    for workspace in log_analytics_client.workspaces.list_by_resource_group(
                        resource_group.name
                    ):
                        if workspace.name == self.workspace_name:
                            workspaces.append((workspace, resource_group.name))
                except Exception:
                    # Skip resource groups where we don't have access
                    continue

            if not workspaces:
                raise ConfigurationError(
                    f"Workspace '{self.workspace_name}' not found in subscription '{self.subscription_id}'"
                )

            if len(workspaces) > 1:
                resource_groups = [rg for _, rg in workspaces]
                raise ConfigurationError(
                    f"Multiple workspaces named '{self.workspace_name}' found in resource groups: "
                    f"{', '.join(resource_groups)}. Please specify resource_group_name explicitly."
                )

            workspace, resource_group_name = workspaces[0]
            logger.info(f"Auto-discovered resource group: {resource_group_name}")
            return resource_group_name

        except Exception as e:
            if isinstance(e, ConfigurationError):
                raise
            raise ConfigurationError(f"Failed to discover resource group: {e}")

    def test_connection(self) -> bool:
        """
        Test the connection to Azure Sentinel.

        Returns:
            True if connection is successful

        Raises:
            Various exceptions if connection fails
        """
        try:
            # Try to list alert rules as a connectivity test
            self.alert_rules.list()
            logger.info("Azure Sentinel connection test successful")
            return True
        except Exception as e:
            logger.error(f"Azure Sentinel connection test failed: {e}")
            raise

    def get_workspace_info(self) -> dict:
        """
        Get information about the current workspace.

        Returns:
            Workspace information dictionary
        """
        return {
            "subscription_id": self.subscription_id,
            "resource_group_name": self.resource_group_name,
            "workspace_name": self.workspace_name
        }
