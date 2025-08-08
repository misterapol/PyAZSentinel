"""
Enumerations used in Azure Sentinel operations.
"""

from enum import Enum


class AlertRuleKind(str, Enum):
    """Alert rule types in Azure Sentinel."""
    SCHEDULED = "Scheduled"
    FUSION = "Fusion"
    ML_BEHAVIOR_ANALYTICS = "MLBehaviorAnalytics"
    MICROSOFT_SECURITY_INCIDENT_CREATION = "MicrosoftSecurityIncidentCreation"
    THREAT_INTELLIGENCE = "ThreatIntelligence"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class TriggerOperator(str, Enum):
    """Query trigger operators."""
    GREATER_THAN = "GreaterThan"
    LESS_THAN = "LessThan"
    EQUAL = "Equal"
    NOT_EQUAL = "NotEqual"


class IncidentStatus(str, Enum):
    """Incident status values."""
    NEW = "New"
    ACTIVE = "Active"
    CLOSED = "Closed"


class IncidentSeverity(str, Enum):
    """Incident severity levels."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class IncidentClassification(str, Enum):
    """Incident classification types."""
    UNDETERMINED = "Undetermined"
    TRUE_POSITIVE = "TruePositive"
    BENIGN_POSITIVE = "BenignPositive"
    FALSE_POSITIVE = "FalsePositive"


class IncidentClassificationReason(str, Enum):
    """Incident classification reasons."""
    SUSPICIOUS_ACTIVITY = "SuspiciousActivity"
    MALICIOUS_ACTIVITY = "MaliciousActivity"
    SECURITY_TESTING = "SecurityTesting"
    INCORRECT_ALERT_LOGIC = "IncorrectAlertLogic"
    INACCURATE_DATA = "InaccurateData"


class AttackTactic(str, Enum):
    """MITRE ATT&CK tactics."""
    INITIAL_ACCESS = "InitialAccess"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    DEFENSE_EVASION = "DefenseEvasion"
    CREDENTIAL_ACCESS = "CredentialAccess"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "LateralMovement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "CommandAndControl"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class DataConnectorKind(str, Enum):
    """Data connector types."""
    AZURE_ACTIVITY_LOG = "AzureActivityLog"
    AZURE_SECURITY_CENTER = "AzureSecurityCenter"
    MICROSOFT_CLOUD_APP_SECURITY = "MicrosoftCloudAppSecurity"
    THREAT_INTELLIGENCE = "ThreatIntelligence"
    OFFICE_365 = "Office365"
    AWS_CLOUD_TRAIL = "AmazonWebServicesCloudTrail"
    AZURE_ACTIVE_DIRECTORY = "AzureActiveDirectory"
    DNS = "DNS"
    MICROSOFT_DEFENDER_ATP = "MicrosoftDefenderAdvancedThreatProtection"
    AZURE_ATP = "AzureAdvancedThreatProtection"
    GENERIC_UI = "GenericUI"


class EntityType(str, Enum):
    """Entity types in Azure Sentinel."""
    ACCOUNT = "Account"
    HOST = "Host"
    FILE = "File"
    AZURE_RESOURCE = "AzureResource"
    CLOUD_APPLICATION = "CloudApplication"
    DNS = "DNS"
    FILE_HASH = "FileHash"
    IP = "IP"
    MALWARE = "Malware"
    PROCESS = "Process"
    REGISTRY_KEY = "RegistryKey"
    REGISTRY_VALUE = "RegistryValue"
    SECURITY_GROUP = "SecurityGroup"
    URL = "URL"
    IOT_DEVICE = "IoTDevice"
    MAILBOX = "Mailbox"
    MAIL_CLUSTER = "MailCluster"
    MAIL_MESSAGE = "MailMessage"
    SUBMISSION_MAIL = "SubmissionMail"


class AggregationKind(str, Enum):
    """Aggregation methods for alert rules."""
    SINGLE_ALERT = "SingleAlert"
    ALERT_PER_RESULT = "AlertPerResult"
