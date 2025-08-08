"""
Data models for Azure Sentinel incidents.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from .enums import IncidentStatus, IncidentSeverity, IncidentClassification, IncidentClassificationReason


class IncidentLabel(BaseModel):
    """Incident label configuration."""
    label_name: str = Field(..., description="Label name")
    label_type: str = Field(..., description="Label type")


class IncidentOwner(BaseModel):
    """Incident owner information."""
    object_id: Optional[str] = Field(None, description="Owner object ID")
    email: Optional[str] = Field(None, description="Owner email")
    assigned_to: Optional[str] = Field(None, description="Assigned to")
    user_principal_name: Optional[str] = Field(None, description="User principal name")


class IncidentComment(BaseModel):
    """Incident comment."""
    message: str = Field(..., description="Comment message")
    created_time_utc: Optional[datetime] = Field(None, description="Creation time")
    author: Optional[Dict[str, Any]] = Field(None, description="Comment author")


class Incident(BaseModel):
    """Azure Sentinel incident."""
    title: str = Field(..., description="Incident title")
    description: Optional[str] = Field(None, description="Incident description")
    status: IncidentStatus = Field(..., description="Incident status")
    severity: IncidentSeverity = Field(..., description="Incident severity")
    classification: Optional[IncidentClassification] = Field(
        None, description="Incident classification"
    )
    classification_reason: Optional[IncidentClassificationReason] = Field(
        None, description="Classification reason"
    )
    classification_comment: Optional[str] = Field(
        None, description="Classification comment"
    )
    owner: Optional[IncidentOwner] = Field(None, description="Incident owner")
    labels: Optional[List[IncidentLabel]] = Field(None, description="Incident labels")
    first_activity_time_utc: Optional[datetime] = Field(
        None, description="First activity time"
    )
    last_activity_time_utc: Optional[datetime] = Field(
        None, description="Last activity time"
    )
    last_modified_time_utc: Optional[datetime] = Field(
        None, description="Last modified time"
    )
    created_time_utc: Optional[datetime] = Field(None, description="Creation time")
    incident_number: Optional[int] = Field(None, description="Incident number")
    additional_data: Optional[Dict[str, Any]] = Field(
        None, description="Additional incident data"
    )
    related_analytic_rule_ids: Optional[List[str]] = Field(
        None, description="Related analytic rule IDs"
    )
    incident_url: Optional[str] = Field(None, description="Incident URL")


class IncidentWithMetadata(BaseModel):
    """Incident with Azure metadata."""
    id: Optional[str] = Field(None, description="Incident ID")
    name: Optional[str] = Field(None, description="Incident name")
    etag: Optional[str] = Field(None, description="Incident etag")
    type: Optional[str] = Field(None, description="Incident type")
    properties: Incident = Field(..., description="Incident properties")


class IncidentUpdate(BaseModel):
    """Incident update parameters."""
    title: Optional[str] = Field(None, description="Updated title")
    description: Optional[str] = Field(None, description="Updated description")
    status: Optional[IncidentStatus] = Field(None, description="Updated status")
    severity: Optional[IncidentSeverity] = Field(None, description="Updated severity")
    classification: Optional[IncidentClassification] = Field(
        None, description="Updated classification"
    )
    classification_reason: Optional[IncidentClassificationReason] = Field(
        None, description="Updated classification reason"
    )
    classification_comment: Optional[str] = Field(
        None, description="Updated classification comment"
    )
    owner: Optional[IncidentOwner] = Field(None, description="Updated owner")
    labels: Optional[List[IncidentLabel]] = Field(None, description="Updated labels")
