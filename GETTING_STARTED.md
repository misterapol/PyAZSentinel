# Getting Started with PyAZSentinel

This guide will help you set up and use PyAZSentinel to manage your Azure Sentinel environment.

## Prerequisites

1. **Python 3.8 or higher**
2. **Azure Subscription** with Azure Sentinel enabled
3. **Appropriate permissions** to manage Azure Sentinel resources

## Installation

### Option 1: Development Installation (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/misterapol/PyAZSentinel.git
cd PyAZSentinel
```

2. Create a virtual environment:
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On Linux/Mac
source venv/bin/activate
```

3. Install the package in development mode:
```bash
pip install -e .
```

### Option 2: Install from PyPI (when available)
```bash
pip install pyazsentinel
```

## Authentication Setup

PyAZSentinel supports multiple authentication methods:

### Method 1: Azure CLI (Recommended for Development)

1. Install Azure CLI if not already installed
2. Login to Azure:
```bash
az login
```

3. Set your default subscription:
```bash
az account set --subscription "your-subscription-id"
```

### Method 2: Service Principal (Recommended for Automation)

1. Create a service principal:
```bash
az ad sp create-for-rbac --name "pyazsentinel-sp" --role contributor --scopes /subscriptions/your-subscription-id
```

2. Note down the output values:
   - `appId` (client ID)
   - `password` (client secret)
   - `tenant` (tenant ID)

3. Assign Azure Sentinel permissions to the service principal

### Method 3: Managed Identity (For Azure Resources)

If running on Azure resources (VMs, Function Apps, etc.), managed identity can be used automatically.

## Quick Start

### 1. Test Connection

First, verify your setup works:

```bash
pyazsentinel --subscription-id "your-sub-id" --workspace-name "your-workspace" --use-cli test
```

### 2. List Existing Alert Rules

```bash
pyazsentinel --subscription-id "your-sub-id" --workspace-name "your-workspace" --use-cli alert-rules list
```

### 3. Create an Alert Rule

Create a JSON file with your alert rule configuration:

```json
{
  "displayName": "Test Alert Rule",
  "description": "A test alert rule created with PyAZSentinel",
  "severity": "Medium",
  "enabled": true,
  "query": "SecurityEvent | where EventID == 4625 | limit 10",
  "queryFrequency": "PT1H",
  "queryPeriod": "PT1H",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 0
}
```

Then create the rule:

```bash
pyazsentinel --subscription-id "your-sub-id" --workspace-name "your-workspace" --use-cli alert-rules create --file rule.json
```

### 4. Import Multiple Rules

Use the example files in the `examples/` directory:

```bash
pyazsentinel --subscription-id "your-sub-id" --workspace-name "your-workspace" --use-cli alert-rules import --file examples/alert_rules.json
```

### 5. Export Existing Rules

```bash
pyazsentinel --subscription-id "your-sub-id" --workspace-name "your-workspace" --use-cli alert-rules export --output-dir ./backup --format json
```

## Python SDK Usage

You can also use PyAZSentinel as a Python library:

```python
from pyazsentinel import AzureSentinelClient

# Initialize client
client = AzureSentinelClient(
    subscription_id="your-subscription-id",
    workspace_name="your-workspace-name",
    use_cli=True  # Use Azure CLI authentication
)

# Test connection
client.test_connection()

# List alert rules
rules = client.alert_rules.list()
print(f"Found {len(rules)} alert rules")

# Get specific rule
rule = client.alert_rules.get("rule-id-or-name")
print(f"Rule: {rule.properties.display_name}")

# Create new rule
new_rule_config = {
    "displayName": "My New Rule",
    "description": "Created via Python SDK",
    "severity": "High",
    "enabled": True,
    "query": "SecurityEvent | where EventID == 4624",
    "queryFrequency": "PT5M",
    "queryPeriod": "PT5M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0
}

new_rule = client.alert_rules.create(new_rule_config)
print(f"Created rule: {new_rule.id}")

# Enable/disable rules
client.alert_rules.enable("rule-id")
client.alert_rules.disable("rule-id")

# Delete rule
client.alert_rules.delete("rule-id")
```

## Configuration Files

PyAZSentinel supports both JSON and YAML formats for configuration files.

### Alert Rules Structure

```json
{
  "Scheduled": [
    {
      "displayName": "Rule Name",
      "description": "Rule description",
      "severity": "Medium",
      "enabled": true,
      "query": "KQL query here",
      "queryFrequency": "PT1H",
      "queryPeriod": "PT1H",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 0,
      "tactics": ["Execution"],
      "techniques": ["T1059"]
    }
  ],
  "Fusion": [],
  "MLBehaviorAnalytics": [],
  "MicrosoftSecurityIncidentCreation": []
}
```

### YAML Format

```yaml
Scheduled:
  - displayName: "Rule Name"
    description: "Rule description"
    severity: "Medium"
    enabled: true
    query: |
      SecurityEvent
      | where EventID == 4688
      | limit 10
    queryFrequency: "PT1H"
    queryPeriod: "PT1H"
    triggerOperator: "GreaterThan"
    triggerThreshold: 0
    tactics:
      - "Execution"
    techniques:
      - "T1059"
```

## Common CLI Commands

### Alert Rules
```bash
# List all rules
pyazsentinel ... alert-rules list

# List rules with filtering
pyazsentinel ... alert-rules list --kind Scheduled --last-modified 2024-01-01

# Get specific rule
pyazsentinel ... alert-rules get "rule-id"

# Create from file
pyazsentinel ... alert-rules create --file rule.json

# Import multiple rules
pyazsentinel ... alert-rules import --file rules.json

# Export all rules
pyazsentinel ... alert-rules export --output-dir ./backup

# Enable/disable rules
pyazsentinel ... alert-rules enable "rule-id"
pyazsentinel ... alert-rules disable "rule-id"

# Delete rule (with confirmation)
pyazsentinel ... alert-rules delete "rule-id"
```

### Output Formats
Most commands support different output formats:
- `--output table` (default, human-readable)
- `--output json` (JSON format)
- `--output yaml` (YAML format)

## Environment Variables

You can set environment variables to avoid repeating common parameters:

```bash
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_SENTINEL_WORKSPACE="your-workspace-name"
export AZURE_SENTINEL_RESOURCE_GROUP="your-resource-group"

# Now you can use shorter commands
pyazsentinel alert-rules list
```

## Troubleshooting

### Authentication Issues

1. **Azure CLI not logged in:**
   ```bash
   az login
   az account show  # Verify you're logged in
   ```

2. **Insufficient permissions:**
   - Ensure your account has Azure Sentinel Contributor role
   - Check resource group and subscription permissions

3. **Service Principal issues:**
   - Verify client ID, secret, and tenant ID are correct
   - Ensure service principal has proper role assignments

### Common Errors

1. **"Workspace not found":**
   - Verify workspace name and subscription ID
   - Ensure workspace has Azure Sentinel enabled
   - Check if workspace is in a different resource group

2. **"Resource group not found":**
   - Use `--resource-group` parameter to specify explicitly
   - Ensure the workspace exists in the specified resource group

3. **"Invalid query frequency":**
   - Use ISO 8601 duration format (e.g., PT1H, PT5M, P1D)
   - Ensure query frequency is not less than 5 minutes

## Migration from PowerShell Module

If you're migrating from the original PowerShell AzSentinel module:

| PowerShell Command | PyAZSentinel CLI Equivalent |
|-------------------|---------------------------|
| `Get-AzSentinelAlertRule` | `pyazsentinel alert-rules list` |
| `Get-AzSentinelAlertRule -RuleName "rule"` | `pyazsentinel alert-rules get "rule"` |
| `New-AzSentinelAlertRule` | `pyazsentinel alert-rules create --file rule.json` |
| `Import-AzSentinelAlertRule` | `pyazsentinel alert-rules import --file rules.json` |
| `Export-AzSentinel` | `pyazsentinel alert-rules export --output-dir ./backup` |
| `Enable-AzSentinelAlertRule` | `pyazsentinel alert-rules enable "rule-id"` |
| `Disable-AzSentinelAlertRule` | `pyazsentinel alert-rules disable "rule-id"` |
| `Remove-AzSentinelAlertRule` | `pyazsentinel alert-rules delete "rule-id"` |

## Next Steps

1. **Explore Examples:** Check the `examples/` directory for sample configurations
2. **Read the Documentation:** See README.md for detailed API reference
3. **Contribute:** Report issues or contribute improvements on GitHub
4. **Advanced Usage:** Explore the Python SDK for programmatic access

## Support

- **GitHub Issues:** Report bugs and feature requests
- **Documentation:** Check README.md and code comments
- **Examples:** Use the provided example files as templates
