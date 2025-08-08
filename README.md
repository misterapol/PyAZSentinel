# PyAZSentinel

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python SDK and CLI tool for managing Azure Sentinel resources. This is a Python port of the original PowerShell AzSentinel module.

## Overview

PyAZSentinel provides a comprehensive Python interface for managing Azure Sentinel resources including:

- **Alert Rules**: Create, read, update, delete, and manage alert rules
- **Hunting Rules**: Manage hunting rules for threat detection
- **Incidents**: View and update security incidents
- **Data Connectors**: Manage data source connections
- **Alert Rule Actions**: Configure automated responses
- **Import/Export**: Support for JSON and YAML configuration files

## Installation

### From PyPI (when available)
```bash
pip install pyazsentinel
```

### Development Installation
```bash
git clone https://github.com/misterapol/PyAZSentinel.git
cd PyAZSentinel
pip install -e .
```

### Development with Optional Dependencies
```bash
pip install -e ".[dev]"
```

## Quick Start

### Authentication

PyAZSentinel uses Azure Identity for authentication. You can authenticate using:

1. **Azure CLI** (recommended for development):
   ```bash
   az login
   ```

2. **Service Principal** (recommended for automation):
   ```python
   from pyazsentinel import AzureSentinelClient

   client = AzureSentinelClient(
       subscription_id="your-subscription-id",
       workspace_name="your-workspace-name",
       tenant_id="your-tenant-id",
       client_id="your-client-id",
       client_secret="your-client-secret"
   )
   ```

3. **Managed Identity** (for Azure resources):
   ```python
   from pyazsentinel import AzureSentinelClient

   client = AzureSentinelClient(
       subscription_id="your-subscription-id",
       workspace_name="your-workspace-name"
   )
   ```

### Python SDK Usage

```python
from pyazsentinel import AzureSentinelClient

# Initialize client
client = AzureSentinelClient(
    subscription_id="your-subscription-id",
    workspace_name="your-workspace-name"
)

# List all alert rules
alert_rules = client.alert_rules.list()

# Get specific alert rule
rule = client.alert_rules.get("rule-name")

# Create new alert rule from JSON
with open("alert_rule.json", "r") as f:
    rule_config = json.load(f)
new_rule = client.alert_rules.create(rule_config)

# List incidents
incidents = client.incidents.list()

# Update incident
client.incidents.update(
    incident_id="incident-id",
    status="Closed",
    classification="BenignPositive"
)
```

### CLI Usage

The CLI provides command-line access to all functionality:

```bash
# List alert rules
pyazsentinel alert-rules list --workspace-name "my-workspace"

# Get specific alert rule
pyazsentinel alert-rules get --workspace-name "my-workspace" --rule-name "my-rule"

# Create alert rule from JSON file
pyazsentinel alert-rules create --workspace-name "my-workspace" --file "rule.json"

# Import multiple alert rules
pyazsentinel alert-rules import --workspace-name "my-workspace" --file "rules.json"

# List hunting rules
pyazsentinel hunting-rules list --workspace-name "my-workspace"

# List incidents
pyazsentinel incidents list --workspace-name "my-workspace"

# Export all configurations
pyazsentinel export --workspace-name "my-workspace" --output-dir "./backup"
```

## Configuration File Formats

PyAZSentinel supports the same JSON and YAML formats as the original PowerShell module:

### Alert Rules JSON Format
```json
{
  "Scheduled": [
    {
      "displayName": "Suspicious Process Execution",
      "description": "Detects suspicious process execution patterns",
      "severity": "Medium",
      "enabled": true,
      "query": "SecurityEvent | where EventID == 4688",
      "queryFrequency": "PT1H",
      "queryPeriod": "PT1H",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 0
    }
  ],
  "Fusion": [],
  "MLBehaviorAnalytics": [],
  "MicrosoftSecurityIncidentCreation": []
}
```

### YAML Support
```yaml
Scheduled:
  - displayName: "Suspicious Process Execution"
    description: "Detects suspicious process execution patterns"
    severity: "Medium"
    enabled: true
    query: "SecurityEvent | where EventID == 4688"
    queryFrequency: "PT1H"
    queryPeriod: "PT1H"
    triggerOperator: "GreaterThan"
    triggerThreshold: 0
```

## Features

### Alert Rules
- ✅ Create, read, update, delete alert rules
- ✅ Support for all rule types (Scheduled, Fusion, ML Behavior Analytics, etc.)
- ✅ Import/export functionality
- ✅ Enable/disable rules
- ✅ Rule validation

### Hunting Rules
- ✅ Create, read, update, delete hunting rules
- ✅ Import/export functionality
- ✅ Query validation

### Incidents
- ✅ List and filter incidents
- ✅ Update incident status and classification
- ✅ Add comments to incidents
- ✅ Incident analytics

### Data Connectors
- ✅ List available data connectors
- ✅ Configure data source connections
- ✅ Import connector configurations

### Import/Export
- ✅ JSON format support
- ✅ YAML format support
- ✅ Bulk operations
- ✅ Configuration validation

## Development

### Setting up Development Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/misterapol/PyAZSentinel.git
   cd PyAZSentinel
   ```

2. Create virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=pyazsentinel

# Run specific test file
pytest tests/test_alert_rules.py
```

### Code Formatting

```bash
# Format code
black pyazsentinel tests

# Sort imports
isort pyazsentinel tests

# Type checking
mypy pyazsentinel
```

## Migration from PowerShell Module

If you're migrating from the PowerShell AzSentinel module, here's the mapping:

| PowerShell Function | Python SDK | CLI Command |
|-------------------|------------|-------------|
| `Get-AzSentinelAlertRule` | `client.alert_rules.get()` | `pyazsentinel alert-rules get` |
| `New-AzSentinelAlertRule` | `client.alert_rules.create()` | `pyazsentinel alert-rules create` |
| `Import-AzSentinelAlertRule` | `client.alert_rules.import_from_file()` | `pyazsentinel alert-rules import` |
| `Get-AzSentinelIncident` | `client.incidents.get()` | `pyazsentinel incidents get` |
| `Update-AzSentinelIncident` | `client.incidents.update()` | `pyazsentinel incidents update` |
| `Export-AzSentinel` | `client.export_all()` | `pyazsentinel export` |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original PowerShell module by [Wortell](https://github.com/wortell/AZSentinel)
- Azure Sentinel team for the underlying APIs
- Python community for excellent libraries and tools
