"""
Azure Sentinel Incidents Service

This module provides functionality for managing Azure Sentinel incidents,
including creating, reading, updating, and managing incident properties.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from ..models.incident import Incident, IncidentComment
from .base_service import BaseService


class IncidentsService(BaseService):
    """Service for managing Azure Sentinel incidents."""

    def __init__(self, credential, subscription_id: str, resource_group_name: str, workspace_name: str):
        """
        Initialize the incidents service.

        Args:
            credential: Azure credential object
            subscription_id: Azure subscription ID
            resource_group_name: Name of the resource group
            workspace_name: Name of the Log Analytics workspace
        """
        super().__init__(credential, subscription_id, resource_group_name, workspace_name)

    def list_incidents(self,
                      filter_expr: Optional[str] = None,
                      order_by: Optional[str] = None,
                      top: Optional[int] = None,
                      skip_token: Optional[str] = None) -> List[Incident]:
        """
        List incidents in the workspace.

        Args:
            filter_expr: OData filter expression
            order_by: Order by expression
            top: Maximum number of incidents to return
            skip_token: Skip token for pagination

        Returns:
            List of incidents
        """
        params = {"api-version": "2024-03-01"}

        if filter_expr:
            params["$filter"] = filter_expr
        if order_by:
            params["$orderby"] = order_by
        if top:
            params["$top"] = top
        if skip_token:
            params["$skipToken"] = skip_token

        response = self._get("incidents", params=params)

        incidents = []
        if "value" in response:
            for item in response["value"]:
                incidents.append(Incident.model_validate(item))

        return incidents

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """
        Get a specific incident by ID.

        Args:
            incident_id: The incident identifier

        Returns:
            The incident if found, None otherwise
        """
        url = f"{self.base_url}/incidents/{incident_id}"
        params = {"api-version": "2024-03-01"}

        try:
            response = self._make_request("GET", url, params=params)
            return Incident.model_validate(response)
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                return None
            raise

    def update_incident(self, incident_id: str, incident: Incident) -> Incident:
        """
        Update an incident.

        Args:
            incident_id: The incident identifier
            incident: The updated incident data

        Returns:
            The updated incident
        """
        url = f"{self.base_url}/incidents/{incident_id}"
        params = {"api-version": "2024-03-01"}

        # Convert to API format
        data = incident.model_dump(by_alias=True, exclude_none=True)

        response = self._make_request("PUT", url, params=params, json=data)
        return Incident.model_validate(response)

    def close_incident(self,
                      incident_id: str,
                      close_reason: str = "FalsePositive",
                      close_reason_text: Optional[str] = None) -> Incident:
        """
        Close an incident.

        Args:
            incident_id: The incident identifier
            close_reason: Reason for closing (FalsePositive, TruePositive, Benign, etc.)
            close_reason_text: Additional text explaining the closure

        Returns:
            The updated incident
        """
        # Get current incident
        incident = self.get_incident(incident_id)
        if not incident:
            raise Exception(f"Incident {incident_id} not found")

        # Update status and close reason
        if incident.properties:
            incident.properties.status = "Closed"
            incident.properties.close_reason = close_reason
            if close_reason_text:
                incident.properties.close_reason_text = close_reason_text
            incident.properties.last_modified_time_utc = datetime.utcnow()

        return self.update_incident(incident_id, incident)

    def reopen_incident(self, incident_id: str) -> Incident:
        """
        Reopen a closed incident.

        Args:
            incident_id: The incident identifier

        Returns:
            The updated incident
        """
        # Get current incident
        incident = self.get_incident(incident_id)
        if not incident:
            raise Exception(f"Incident {incident_id} not found")

        # Update status
        if incident.properties:
            incident.properties.status = "Active"
            incident.properties.close_reason = None
            incident.properties.close_reason_text = None
            incident.properties.last_modified_time_utc = datetime.utcnow()

        return self.update_incident(incident_id, incident)

    def assign_incident(self, incident_id: str, assignee_email: str) -> Incident:
        """
        Assign an incident to a user.

        Args:
            incident_id: The incident identifier
            assignee_email: Email of the user to assign to

        Returns:
            The updated incident
        """
        # Get current incident
        incident = self.get_incident(incident_id)
        if not incident:
            raise Exception(f"Incident {incident_id} not found")

        # Update owner
        if incident.properties:
            incident.properties.owner = {
                "email": assignee_email,
                "objectId": None,  # Will be resolved by Azure
                "userPrincipalName": assignee_email
            }
            incident.properties.last_modified_time_utc = datetime.utcnow()

        return self.update_incident(incident_id, incident)

    def add_comment(self, incident_id: str, message: str) -> IncidentComment:
        """
        Add a comment to an incident.

        Args:
            incident_id: The incident identifier
            message: Comment message

        Returns:
            The created comment
        """
        url = f"{self.base_url}/incidents/{incident_id}/comments"
        params = {"api-version": "2024-03-01"}

        data = {
            "properties": {
                "message": message
            }
        }

        response = self._make_request("POST", url, params=params, json=data)
        return IncidentComment.model_validate(response)

    def list_comments(self, incident_id: str) -> List[IncidentComment]:
        """
        List comments for an incident.

        Args:
            incident_id: The incident identifier

        Returns:
            List of incident comments
        """
        url = f"{self.base_url}/incidents/{incident_id}/comments"
        params = {"api-version": "2024-03-01"}

        response = self._make_request("GET", url, params=params)

        comments = []
        if "value" in response:
            for item in response["value"]:
                comments.append(IncidentComment.model_validate(item))

        return comments

    def get_incident_entities(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Get entities associated with an incident.

        Args:
            incident_id: The incident identifier

        Returns:
            List of incident entities
        """
        url = f"{self.base_url}/incidents/{incident_id}/entities"
        params = {"api-version": "2024-03-01"}

        response = self._make_request("GET", url, params=params)
        return response.get("entities", [])

    def get_incident_alerts(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Get alerts associated with an incident.

        Args:
            incident_id: The incident identifier

        Returns:
            List of incident alerts
        """
        url = f"{self.base_url}/incidents/{incident_id}/alerts"
        params = {"api-version": "2024-03-01"}

        response = self._make_request("GET", url, params=params)
        return response.get("value", [])

    def search_incidents(self,
                        title_filter: Optional[str] = None,
                        severity: Optional[str] = None,
                        status: Optional[str] = None,
                        created_after: Optional[datetime] = None,
                        created_before: Optional[datetime] = None) -> List[Incident]:
        """
        Search incidents with filters.

        Args:
            title_filter: Filter by incident title
            severity: Filter by severity (High, Medium, Low, Informational)
            status: Filter by status (New, Active, Closed)
            created_after: Filter incidents created after this date
            created_before: Filter incidents created before this date

        Returns:
            List of matching incidents
        """
        filters = []

        if title_filter:
            filters.append(f"contains(properties/title,'{title_filter}')")
        if severity:
            filters.append(f"properties/severity eq '{severity}'")
        if status:
            filters.append(f"properties/status eq '{status}'")
        if created_after:
            filters.append(f"properties/createdTimeUtc ge {created_after.isoformat()}Z")
        if created_before:
            filters.append(f"properties/createdTimeUtc le {created_before.isoformat()}Z")

        filter_expr = " and ".join(filters) if filters else None

        return self.list_incidents(filter_expr=filter_expr)

    def get_incident_statistics(self) -> Dict[str, Any]:
        """
        Get incident statistics for the workspace.

        Returns:
            Dictionary with incident statistics
        """
        incidents = self.list_incidents()

        stats = {
            "total": len(incidents),
            "by_severity": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
            "by_status": {"New": 0, "Active": 0, "Closed": 0},
            "unassigned": 0
        }

        for incident in incidents:
            if incident.properties:
                # Count by severity
                severity = incident.properties.severity or "Informational"
                if severity in stats["by_severity"]:
                    stats["by_severity"][severity] += 1

                # Count by status
                status = incident.properties.status or "New"
                if status in stats["by_status"]:
                    stats["by_status"][status] += 1

                # Count unassigned
                if not incident.properties.owner:
                    stats["unassigned"] += 1

        return stats
