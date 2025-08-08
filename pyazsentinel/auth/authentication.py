"""
Authentication implementation for Azure Sentinel.
"""

from typing import Optional, Union
from azure.identity import (
    DefaultAzureCredential,
    ClientSecretCredential,
    AzureCliCredential,
    ManagedIdentityCredential
)
from azure.core.credentials import TokenCredential


class AzureSentinelAuth:
    """Handles authentication for Azure Sentinel operations."""

    def __init__(
        self,
        credential: Optional[TokenCredential] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        use_cli: bool = False,
        use_managed_identity: bool = False
    ):
        """
        Initialize Azure Sentinel authentication.

        Args:
            credential: Pre-configured Azure credential
            tenant_id: Azure tenant ID (required for service principal)
            client_id: Application client ID (required for service principal)
            client_secret: Application client secret (required for service principal)
            use_cli: Use Azure CLI authentication
            use_managed_identity: Use managed identity authentication
        """
        if credential:
            self.credential = credential
        elif client_id and client_secret and tenant_id:
            # Service Principal authentication
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        elif use_cli:
            # Azure CLI authentication
            self.credential = AzureCliCredential()
        elif use_managed_identity:
            # Managed Identity authentication
            self.credential = ManagedIdentityCredential()
        else:
            # Default credential chain
            self.credential = DefaultAzureCredential()

    def get_credential(self) -> TokenCredential:
        """Get the configured credential."""
        return self.credential
