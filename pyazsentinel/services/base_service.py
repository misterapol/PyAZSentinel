"""
Base service class for Azure Sentinel API operations.
"""

import logging
from typing import Optional, Dict, Any, List
from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
import requests
from ..utils.exceptions import AzureSentinelError, ResourceNotFoundError, AuthenticationError


logger = logging.getLogger(__name__)


class BaseService:
    """Base class for Azure Sentinel service operations."""

    def __init__(
        self,
        credential: TokenCredential,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str
    ):
        """
        Initialize base service.

        Args:
            credential: Azure credential for authentication
            subscription_id: Azure subscription ID
            resource_group_name: Resource group name
            workspace_name: Log Analytics workspace name
        """
        self.credential = credential
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.workspace_name = workspace_name
        self.base_url = "https://management.azure.com"
        self._access_token = None
        self._token_expires_on = None

    def _get_access_token(self) -> str:
        """Get access token for Azure Management API."""
        try:
            token = self.credential.get_token("https://management.azure.com/.default")
            self._access_token = token.token
            self._token_expires_on = token.expires_on
            return self._access_token
        except Exception as e:
            logger.error(f"Failed to get access token: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for API requests."""
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _get_workspace_url(self) -> str:
        """Get the base URL for workspace operations."""
        return (
            f"{self.base_url}/subscriptions/{self.subscription_id}/"
            f"resourceGroups/{self.resource_group_name}/"
            f"providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/"
            f"providers/Microsoft.SecurityInsights"
        )

    def _get_loganalytics_url(self) -> str:
        """Get the base URL for Log Analytics operations (for saved searches/hunting rules)."""
        return (
            f"{self.base_url}/subscriptions/{self.subscription_id}/"
            f"resourceGroups/{self.resource_group_name}/"
            f"providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )

    def _make_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP request to Azure API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            url: Request URL
            data: Request body data
            params: Query parameters

        Returns:
            Response data as dictionary

        Raises:
            AzureSentinelError: For API errors
            ResourceNotFoundError: For 404 errors
        """
        headers = self._get_headers()

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
                timeout=30
            )

            if response.status_code == 404:
                raise ResourceNotFoundError(f"Resource not found: {url}")

            response.raise_for_status()

            if response.content:
                return response.json()
            return {}

        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            error_msg = f"API request failed: {e}"
            if hasattr(e.response, 'text'):
                error_msg += f" - {e.response.text}"
            raise AzureSentinelError(error_msg)
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise AzureSentinelError(f"Request failed: {e}")

    def _get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make GET request to API endpoint."""
        url = f"{self._get_workspace_url()}/{endpoint}"
        return self._make_request("GET", url, params=params)

    def _post(self, endpoint: str, data: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make POST request to API endpoint."""
        url = f"{self._get_workspace_url()}/{endpoint}"
        return self._make_request("POST", url, data=data, params=params)

    def _put(self, endpoint: str, data: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make PUT request to API endpoint."""
        url = f"{self._get_workspace_url()}/{endpoint}"
        return self._make_request("PUT", url, data=data, params=params)

    def _delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make DELETE request to API endpoint."""
        url = f"{self._get_workspace_url()}/{endpoint}"
        return self._make_request("DELETE", url, params=params)

    def _list_resources(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        List resources with pagination support.

        Args:
            endpoint: API endpoint
            params: Query parameters

        Returns:
            List of resources
        """
        all_resources = []
        next_link = None

        while True:
            if next_link:
                response = self._make_request("GET", next_link, params=None)
            else:
                response = self._get(endpoint, params=params)

            if "value" in response:
                all_resources.extend(response["value"])
            else:
                # Single resource response
                all_resources.append(response)
                break

            # Check for pagination
            next_link = response.get("nextLink")
            if not next_link:
                break

        return all_resources
