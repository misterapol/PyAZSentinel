"""
Data models for Azure Sentinel hunting rules.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from .enums import AttackTactic


class HuntingRule(BaseModel):
    """Hunting rule configuration."""
    display_name: str = Field(..., description="Display name of the hunting rule", alias="displayName")
    description: Optional[str] = Field(None, description="Description of the hunting rule")
    category: Optional[str] = Field(None, description="Category of the hunting rule")
    query: str = Field(..., description="KQL query for the hunting rule")
    input_entity_type: Optional[str] = Field(None, description="Input entity type", alias="inputEntityType")
    required_data_connectors: Optional[List[Dict[str, Any]]] = Field(
        None, description="Required data connectors", alias="requiredDataConnectors"
    )
    tactics: Optional[List[AttackTactic]] = Field(None, description="MITRE ATT&CK tactics")
    techniques: Optional[List[str]] = Field(None, description="MITRE ATT&CK techniques")
    relevant_techniques: Optional[List[str]] = Field(None, description="Relevant techniques", alias="relevantTechniques")
    tags: Optional[List[str]] = Field(None, description="Tags for the hunting rule")


class HuntingRuleWithMetadata(BaseModel):
    """Hunting rule with Azure metadata."""
    id: Optional[str] = Field(None, description="Hunting rule ID")
    name: Optional[str] = Field(None, description="Hunting rule name")
    etag: Optional[str] = Field(None, description="Hunting rule etag")
    type: Optional[str] = Field(None, description="Hunting rule type")
    properties: HuntingRule = Field(..., description="Hunting rule properties")
    created_date_utc: Optional[datetime] = Field(None, description="Creation date")
    last_modified_utc: Optional[datetime] = Field(None, description="Last modified date")


class HuntingRuleCollection(BaseModel):
    """Collection of hunting rules."""
    hunting_rules: List[HuntingRule] = Field(default_factory=list, alias="HuntingRules")

    class Config:
        populate_by_name = True
