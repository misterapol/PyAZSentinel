"""
Command-line interface for PyAZSentinel.
"""

import logging
import click
from pathlib import Path
from typing import Optional

from ..client import AzureSentinelClient
from ..utils import JSONHelper, YAMLHelper
from ..utils.exceptions import AzureSentinelError


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


@click.group()
@click.option('--subscription-id', required=True, help='Azure subscription ID')
@click.option('--workspace-name', required=True, help='Log Analytics workspace name')
@click.option('--resource-group', help='Resource group name (auto-discovered if not provided)')
@click.option('--tenant-id', help='Azure tenant ID (for service principal auth)')
@click.option('--client-id', help='Application client ID (for service principal auth)')
@click.option('--client-secret', help='Application client secret (for service principal auth)')
@click.option('--use-cli', is_flag=True, help='Use Azure CLI authentication')
@click.option('--use-managed-identity', is_flag=True, help='Use managed identity authentication')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(
    ctx,
    subscription_id: str,
    workspace_name: str,
    resource_group: Optional[str],
    tenant_id: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    use_cli: bool,
    use_managed_identity: bool,
    verbose: bool
):
    """PyAZSentinel - Python CLI for Azure Sentinel management."""

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Initialize Azure Sentinel client
        client = AzureSentinelClient(
            subscription_id=subscription_id,
            workspace_name=workspace_name,
            resource_group_name=resource_group,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            use_cli=use_cli,
            use_managed_identity=use_managed_identity
        )

        # Store client in context for subcommands
        ctx.ensure_object(dict)
        ctx.obj['client'] = client

    except Exception as e:
        click.echo(f"Error initializing client: {e}", err=True)
        ctx.exit(1)


@cli.group()
@click.pass_context
def alert_rules(ctx):
    """Manage Azure Sentinel alert rules."""
    pass


@alert_rules.command('list')
@click.option('--kind', help='Filter by alert rule kind')
@click.option('--last-modified', help='Filter by last modified date (ISO 8601)')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.pass_context
def list_alert_rules(ctx, kind, last_modified, output):
    """List alert rules."""
    try:
        client = ctx.obj['client']
        rules = client.alert_rules.list(rule_kind=kind, last_modified=last_modified)

        if output == 'json':
            import json
            click.echo(json.dumps([rule.dict() for rule in rules], indent=2, default=str))
        elif output == 'yaml':
            import yaml
            click.echo(yaml.dump([rule.dict() for rule in rules], default_flow_style=False))
        else:
            # Table output
            click.echo(f"Found {len(rules)} alert rules:")
            for rule in rules:
                status = "Enabled" if rule.properties.enabled else "Disabled"
                click.echo(f"  - {rule.properties.display_name} ({rule.properties.kind}) - {status}")

    except AzureSentinelError as e:
        click.echo(f"Error listing alert rules: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('get')
@click.argument('rule_id')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.pass_context
def get_alert_rule(ctx, rule_id, output):
    """Get a specific alert rule."""
    try:
        client = ctx.obj['client']
        rule = client.alert_rules.get(rule_id)

        if output == 'json':
            import json
            click.echo(json.dumps(rule.dict(), indent=2, default=str))
        elif output == 'yaml':
            import yaml
            click.echo(yaml.dump(rule.dict(), default_flow_style=False))
        else:
            # Table output
            click.echo(f"Alert Rule: {rule.properties.display_name}")
            click.echo(f"  ID: {rule.id}")
            click.echo(f"  Kind: {rule.properties.kind}")
            click.echo(f"  Severity: {rule.properties.severity}")
            click.echo(f"  Enabled: {rule.properties.enabled}")
            if rule.properties.description:
                click.echo(f"  Description: {rule.properties.description}")

    except AzureSentinelError as e:
        click.echo(f"Error getting alert rule: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('create')
@click.option('--file', '-f', required=True, type=click.Path(exists=True),
              help='JSON or YAML file with alert rule configuration')
@click.pass_context
def create_alert_rule(ctx, file):
    """Create a new alert rule from file."""
    try:
        client = ctx.obj['client']
        file_path = Path(file)

        if file_path.suffix.lower() in ['.json']:
            data = JSONHelper.load_file(file_path)
        elif file_path.suffix.lower() in ['.yaml', '.yml']:
            data = YAMLHelper.load_file(file_path)
        else:
            click.echo("Unsupported file format. Use .json, .yaml, or .yml", err=True)
            ctx.exit(1)

        rule = client.alert_rules.create(data)
        click.echo(f"Created alert rule: {rule.properties.display_name} (ID: {rule.id})")

    except AzureSentinelError as e:
        click.echo(f"Error creating alert rule: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('import')
@click.option('--file', '-f', required=True, type=click.Path(exists=True),
              help='JSON or YAML file with alert rules collection')
@click.pass_context
def import_alert_rules(ctx, file):
    """Import multiple alert rules from file."""
    try:
        client = ctx.obj['client']
        file_path = Path(file)

        if file_path.suffix.lower() in ['.json']:
            data = JSONHelper.load_file(file_path)
            if JSONHelper.is_alert_rule_collection(data):
                collection = JSONHelper.parse_alert_rules(data)
            else:
                collection = JSONHelper.parse_single_alert_rule(data)
        elif file_path.suffix.lower() in ['.yaml', '.yml']:
            data = YAMLHelper.load_file(file_path)
            if YAMLHelper.is_alert_rule_collection(data):
                collection = YAMLHelper.parse_alert_rules(data)
            else:
                collection = YAMLHelper.parse_single_alert_rule(data)
        else:
            click.echo("Unsupported file format. Use .json, .yaml, or .yml", err=True)
            ctx.exit(1)

        rules = client.alert_rules.import_from_collection(collection)
        click.echo(f"Imported {len(rules)} alert rules")

    except AzureSentinelError as e:
        click.echo(f"Error importing alert rules: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('import-directory')
@click.option('--directory', '-d', required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True),
              help='Directory containing YAML/JSON alert rule files')
@click.option('--pattern', '-p', default='*.yaml,*.yml,*.json',
              help='File patterns to match (default: *.yaml,*.yml,*.json)')
@click.option('--recursive', '-r', is_flag=True,
              help='Search subdirectories recursively')
@click.pass_context
def import_alert_rules_directory(ctx, directory, pattern, recursive):
    """Import multiple alert rules from all files in a directory."""
    try:
        client = ctx.obj['client']
        directory_path = Path(directory)

        # Parse pattern list
        patterns = [p.strip() for p in pattern.split(',')]

        # Find all matching files
        found_files = []
        for file_pattern in patterns:
            if recursive:
                found_files.extend(directory_path.rglob(file_pattern))
            else:
                found_files.extend(directory_path.glob(file_pattern))

        if not found_files:
            click.echo(f"No files matching patterns {patterns} found in {directory_path}")
            return

        total_imported = 0
        successful_files = 0
        failed_files = []

        for file_path in sorted(found_files):
            try:
                click.echo(f"Processing {file_path.name}...")

                if file_path.suffix.lower() in ['.json']:
                    data = JSONHelper.load_file(file_path)
                    if JSONHelper.is_alert_rule_collection(data):
                        collection = JSONHelper.parse_alert_rules(data)
                    else:
                        collection = JSONHelper.parse_single_alert_rule(data)
                elif file_path.suffix.lower() in ['.yaml', '.yml']:
                    data = YAMLHelper.load_file(file_path)
                    if YAMLHelper.is_alert_rule_collection(data):
                        collection = YAMLHelper.parse_alert_rules(data)
                    else:
                        collection = YAMLHelper.parse_single_alert_rule(data)
                else:
                    click.echo(f"  ⚠️  Skipping {file_path.name} - unsupported format")
                    continue

                rules = client.alert_rules.import_from_collection(collection)
                imported_count = len(rules)
                total_imported += imported_count
                successful_files += 1

                click.echo(f"  ✅ Imported {imported_count} alert rules from {file_path.name}")

            except Exception as e:
                failed_files.append((file_path.name, str(e)))
                click.echo(f"  ❌ Failed to import {file_path.name}: {e}")

        # Summary
        click.echo(f"\n📊 Import Summary:")
        click.echo(f"  • Total files processed: {successful_files + len(failed_files)}")
        click.echo(f"  • Successful imports: {successful_files}")
        click.echo(f"  • Failed imports: {len(failed_files)}")
        click.echo(f"  • Total alert rules imported: {total_imported}")

        if failed_files:
            click.echo(f"\n❌ Failed files:")
            for filename, error in failed_files:
                click.echo(f"  • {filename}: {error}")

    except AzureSentinelError as e:
        click.echo(f"Error importing alert rules from directory: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('export')
@click.option('--output-dir', '-o', required=True, type=click.Path(),
              help='Output directory for exported files')
@click.option('--format', '-f', type=click.Choice(['json', 'yaml']), default='json',
              help='Export format')
@click.pass_context
def export_alert_rules(ctx, output_dir, format):
    """Export all alert rules to files."""
    try:
        client = ctx.obj['client']
        collection = client.alert_rules.export_to_collection()

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        if format == 'json':
            file_path = output_path / "alert_rules.json"
            JSONHelper.save_file(collection.dict(by_alias=True), file_path)
        else:
            file_path = output_path / "alert_rules.yaml"
            YAMLHelper.save_file(collection.dict(by_alias=True), file_path)

        click.echo(f"Exported alert rules to {file_path}")

    except AzureSentinelError as e:
        click.echo(f"Error exporting alert rules: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('enable')
@click.argument('rule_id')
@click.pass_context
def enable_alert_rule(ctx, rule_id):
    """Enable an alert rule."""
    try:
        client = ctx.obj['client']
        rule = client.alert_rules.enable(rule_id)
        click.echo(f"Enabled alert rule: {rule.properties.display_name}")

    except AzureSentinelError as e:
        click.echo(f"Error enabling alert rule: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('disable')
@click.argument('rule_id')
@click.pass_context
def disable_alert_rule(ctx, rule_id):
    """Disable an alert rule."""
    try:
        client = ctx.obj['client']
        rule = client.alert_rules.disable(rule_id)
        click.echo(f"Disabled alert rule: {rule.properties.display_name}")

    except AzureSentinelError as e:
        click.echo(f"Error disabling alert rule: {e}", err=True)
        ctx.exit(1)


@alert_rules.command('delete')
@click.argument('rule_id')
@click.confirmation_option(prompt='Are you sure you want to delete this alert rule?')
@click.pass_context
def delete_alert_rule(ctx, rule_id):
    """Delete an alert rule."""
    try:
        client = ctx.obj['client']
        client.alert_rules.delete(rule_id)
        click.echo(f"Deleted alert rule: {rule_id}")

    except AzureSentinelError as e:
        click.echo(f"Error deleting alert rule: {e}", err=True)
        ctx.exit(1)


@cli.command('test')
@click.pass_context
def test_connection(ctx):
    """Test connection to Azure Sentinel."""
    try:
        client = ctx.obj['client']
        if client.test_connection():
            click.echo("✅ Connection to Azure Sentinel successful!")

            # Show workspace info
            info = client.get_workspace_info()
            click.echo(f"Workspace: {info['workspace_name']}")
            click.echo(f"Resource Group: {info['resource_group_name']}")
            click.echo(f"Subscription: {info['subscription_id']}")

    except Exception as e:
        click.echo(f"❌ Connection failed: {e}", err=True)
        ctx.exit(1)


@cli.group()
@click.pass_context
def hunting_rules(ctx):
    """Manage Azure Sentinel hunting rules."""
    pass


@hunting_rules.command('list')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.pass_context
def list_hunting_rules(ctx, output):
    """List hunting rules."""
    try:
        client = ctx.obj['client']
        rules = client.hunting_rules.list_hunting_rules()

        if output == 'json':
            import json
            click.echo(json.dumps([rule.model_dump() for rule in rules], indent=2, default=str))
        elif output == 'yaml':
            import yaml
            click.echo(yaml.dump([rule.model_dump() for rule in rules], default_flow_style=False))
        else:
            # Table output
            click.echo(f"Found {len(rules)} hunting rules:")
            for rule in rules:
                props = rule.properties or {}
                click.echo(f"  - {rule.name}: {props.get('display_name', 'N/A')}")

    except Exception as e:
        click.echo(f"❌ Error listing hunting rules: {e}", err=True)
        ctx.exit(1)


@hunting_rules.command('search')
@click.argument('query')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.pass_context
def search_hunting_rules(ctx, query, output):
    """Search hunting rules by query."""
    try:
        client = ctx.obj['client']
        rules = client.hunting_rules.search_hunting_rules(query)

        if output == 'json':
            import json
            click.echo(json.dumps([rule.model_dump() for rule in rules], indent=2, default=str))
        elif output == 'yaml':
            import yaml
            click.echo(yaml.dump([rule.model_dump() for rule in rules], default_flow_style=False))
        else:
            # Table output
            click.echo(f"Found {len(rules)} hunting rules matching '{query}':")
            for rule in rules:
                props = rule.properties or {}
                click.echo(f"  - {rule.name}: {props.get('display_name', 'N/A')}")

    except Exception as e:
        click.echo(f"❌ Error searching hunting rules: {e}", err=True)
        ctx.exit(1)


@hunting_rules.command('import')
@click.argument('file_path', type=click.Path(exists=True))
@click.pass_context
def import_hunting_rules(ctx, file_path):
    """Import hunting rules from file."""
    try:
        client = ctx.obj['client']
        rules = client.hunting_rules.import_hunting_rules(file_path)

        click.echo(f"✅ Successfully imported {len(rules)} hunting rules from {file_path}")

    except Exception as e:
        click.echo(f"❌ Error importing hunting rules: {e}", err=True)
        ctx.exit(1)


@hunting_rules.command('import-directory')
@click.option('--directory', '-d', required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True),
              help='Directory containing YAML/JSON hunting rule files')
@click.option('--pattern', '-p', default='*.yaml,*.yml,*.json',
              help='File patterns to match (default: *.yaml,*.yml,*.json)')
@click.option('--recursive', '-r', is_flag=True,
              help='Search subdirectories recursively')
@click.pass_context
def import_hunting_rules_directory(ctx, directory, pattern, recursive):
    """Import multiple hunting rules from all files in a directory."""
    try:
        client = ctx.obj['client']
        directory_path = Path(directory)

        # Parse pattern list
        patterns = [p.strip() for p in pattern.split(',')]

        # Find all matching files
        found_files = []
        for file_pattern in patterns:
            if recursive:
                found_files.extend(directory_path.rglob(file_pattern))
            else:
                found_files.extend(directory_path.glob(file_pattern))

        if not found_files:
            click.echo(f"No files matching patterns {patterns} found in {directory_path}")
            return

        total_imported = 0
        successful_files = 0
        failed_files = []

        for file_path in sorted(found_files):
            try:
                click.echo(f"Processing {file_path.name}...")

                rules = client.hunting_rules.import_hunting_rules(str(file_path))
                imported_count = len(rules)
                total_imported += imported_count
                successful_files += 1

                click.echo(f"  ✅ Imported {imported_count} hunting rules from {file_path.name}")

            except Exception as e:
                failed_files.append((file_path.name, str(e)))
                click.echo(f"  ❌ Failed to import {file_path.name}: {e}")

        # Summary
        click.echo(f"\n📊 Import Summary:")
        click.echo(f"  • Total files processed: {successful_files + len(failed_files)}")
        click.echo(f"  • Successful imports: {successful_files}")
        click.echo(f"  • Failed imports: {len(failed_files)}")
        click.echo(f"  • Total hunting rules imported: {total_imported}")

        if failed_files:
            click.echo(f"\n❌ Failed files:")
            for filename, error in failed_files:
                click.echo(f"  • {filename}: {error}")

    except Exception as e:
        click.echo(f"Error importing hunting rules from directory: {e}", err=True)
        ctx.exit(1)


@hunting_rules.command('export')
@click.argument('file_path', type=click.Path())
@click.option('--rule-ids', help='Comma-separated list of rule IDs to export')
@click.pass_context
def export_hunting_rules(ctx, file_path, rule_ids):
    """Export hunting rules to file."""
    try:
        client = ctx.obj['client']
        rule_ids_list = rule_ids.split(',') if rule_ids else None
        client.hunting_rules.export_hunting_rules(file_path, rule_ids_list)

        click.echo(f"✅ Successfully exported hunting rules to {file_path}")

    except Exception as e:
        click.echo(f"❌ Error exporting hunting rules: {e}", err=True)
        ctx.exit(1)


@cli.group()
@click.pass_context
def incidents(ctx):
    """Manage Azure Sentinel incidents."""
    pass


@incidents.command('list')
@click.option('--severity', type=click.Choice(['High', 'Medium', 'Low', 'Informational']),
              help='Filter by severity')
@click.option('--status', type=click.Choice(['New', 'Active', 'Closed']),
              help='Filter by status')
@click.option('--top', type=int, help='Maximum number of incidents to return')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.pass_context
def list_incidents(ctx, severity, status, top, output):
    """List incidents."""
    try:
        client = ctx.obj['client']

        # Build filter
        filters = []
        if severity:
            filters.append(f"properties/severity eq '{severity}'")
        if status:
            filters.append(f"properties/status eq '{status}'")
        filter_expr = " and ".join(filters) if filters else None

        incidents = client.incidents.list_incidents(filter_expr=filter_expr, top=top)

        if output == 'json':
            import json
            click.echo(json.dumps([incident.model_dump() for incident in incidents], indent=2, default=str))
        elif output == 'yaml':
            import yaml
            click.echo(yaml.dump([incident.model_dump() for incident in incidents], default_flow_style=False))
        else:
            # Table output
            click.echo(f"Found {len(incidents)} incidents:")
            for incident in incidents:
                props = incident.properties or {}
                click.echo(f"  - {incident.name}: {props.get('title', 'N/A')} "
                          f"[{props.get('severity', 'N/A')}] ({props.get('status', 'N/A')})")

    except Exception as e:
        click.echo(f"❌ Error listing incidents: {e}", err=True)
        ctx.exit(1)


@incidents.command('get')
@click.argument('incident_id')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.pass_context
def get_incident(ctx, incident_id, output):
    """Get incident details."""
    try:
        client = ctx.obj['client']
        incident = client.incidents.get_incident(incident_id)

        if not incident:
            click.echo(f"❌ Incident {incident_id} not found")
            ctx.exit(1)

        if output == 'json':
            import json
            click.echo(json.dumps(incident.model_dump(), indent=2, default=str))
        elif output == 'yaml':
            import yaml
            click.echo(yaml.dump(incident.model_dump(), default_flow_style=False))
        else:
            # Table output
            props = incident.properties or {}
            click.echo(f"Incident: {incident.name}")
            click.echo(f"Title: {props.get('title', 'N/A')}")
            click.echo(f"Severity: {props.get('severity', 'N/A')}")
            click.echo(f"Status: {props.get('status', 'N/A')}")
            click.echo(f"Created: {props.get('created_time_utc', 'N/A')}")

    except Exception as e:
        click.echo(f"❌ Error getting incident: {e}", err=True)
        ctx.exit(1)


@incidents.command('close')
@click.argument('incident_id')
@click.option('--reason', type=click.Choice(['FalsePositive', 'TruePositive', 'Benign']),
              default='FalsePositive', help='Close reason')
@click.option('--comment', help='Close reason comment')
@click.pass_context
def close_incident(ctx, incident_id, reason, comment):
    """Close an incident."""
    try:
        client = ctx.obj['client']
        incident = client.incidents.close_incident(incident_id, reason, comment)

        click.echo(f"✅ Successfully closed incident {incident_id} with reason '{reason}'")

    except Exception as e:
        click.echo(f"❌ Error closing incident: {e}", err=True)
        ctx.exit(1)


@incidents.command('assign')
@click.argument('incident_id')
@click.argument('assignee_email')
@click.pass_context
def assign_incident(ctx, incident_id, assignee_email):
    """Assign an incident to a user."""
    try:
        client = ctx.obj['client']
        incident = client.incidents.assign_incident(incident_id, assignee_email)

        click.echo(f"✅ Successfully assigned incident {incident_id} to {assignee_email}")

    except Exception as e:
        click.echo(f"❌ Error assigning incident: {e}", err=True)
        ctx.exit(1)


@incidents.command('comment')
@click.argument('incident_id')
@click.argument('message')
@click.pass_context
def add_incident_comment(ctx, incident_id, message):
    """Add a comment to an incident."""
    try:
        client = ctx.obj['client']
        comment = client.incidents.add_comment(incident_id, message)

        click.echo(f"✅ Successfully added comment to incident {incident_id}")

    except Exception as e:
        click.echo(f"❌ Error adding comment: {e}", err=True)
        ctx.exit(1)


@incidents.command('stats')
@click.pass_context
def incident_statistics(ctx):
    """Show incident statistics."""
    try:
        client = ctx.obj['client']
        stats = client.incidents.get_incident_statistics()

        click.echo("📊 Incident Statistics:")
        click.echo(f"Total incidents: {stats['total']}")
        click.echo("\nBy Severity:")
        for severity, count in stats['by_severity'].items():
            click.echo(f"  {severity}: {count}")
        click.echo("\nBy Status:")
        for status, count in stats['by_status'].items():
            click.echo(f"  {status}: {count}")
        click.echo(f"\nUnassigned: {stats['unassigned']}")

    except Exception as e:
        click.echo(f"❌ Error getting statistics: {e}", err=True)
        ctx.exit(1)


@cli.group()
@click.pass_context
def data_connectors(ctx):
    """Manage Azure Sentinel data connectors."""
    pass


@data_connectors.command('list')
@click.option('--kind', help='Filter by connector kind/type')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'yaml']), default='table',
              help='Output format')
@click.pass_context
def list_data_connectors(ctx, kind, output):
    """List data connectors."""
    try:
        client = ctx.obj['client']

        if kind:
            connectors = client.data_connectors.get_data_connector_by_kind(kind)
        else:
            connectors = client.data_connectors.list_data_connectors()

        if output == 'json':
            import json
            click.echo(json.dumps([connector.model_dump() for connector in connectors], indent=2, default=str))
        elif output == 'yaml':
            import yaml
            click.echo(yaml.dump([connector.model_dump() for connector in connectors], default_flow_style=False))
        else:
            # Table output
            click.echo(f"Found {len(connectors)} data connectors:")
            for connector in connectors:
                props = connector.properties or {}
                state = props.get('state', 'Unknown')
                click.echo(f"  - {connector.name}: {connector.kind} [{state}]")

    except Exception as e:
        click.echo(f"❌ Error listing data connectors: {e}", err=True)
        ctx.exit(1)


@data_connectors.command('enable')
@click.argument('connector_id')
@click.pass_context
def enable_data_connector(ctx, connector_id):
    """Enable a data connector."""
    try:
        client = ctx.obj['client']
        connector = client.data_connectors.enable_data_connector(connector_id)

        click.echo(f"✅ Successfully enabled data connector {connector_id}")

    except Exception as e:
        click.echo(f"❌ Error enabling data connector: {e}", err=True)
        ctx.exit(1)


@data_connectors.command('disable')
@click.argument('connector_id')
@click.pass_context
def disable_data_connector(ctx, connector_id):
    """Disable a data connector."""
    try:
        client = ctx.obj['client']
        connector = client.data_connectors.disable_data_connector(connector_id)

        click.echo(f"✅ Successfully disabled data connector {connector_id}")

    except Exception as e:
        click.echo(f"❌ Error disabling data connector: {e}", err=True)
        ctx.exit(1)


@data_connectors.command('stats')
@click.pass_context
def data_connector_statistics(ctx):
    """Show data connector statistics."""
    try:
        client = ctx.obj['client']
        stats = client.data_connectors.get_connector_statistics()

        click.echo("📊 Data Connector Statistics:")
        click.echo(f"Total connectors: {stats['total']}")
        click.echo("\nBy Type:")
        for kind, count in stats['by_kind'].items():
            click.echo(f"  {kind}: {count}")
        click.echo("\nBy State:")
        for state, count in stats['by_state'].items():
            click.echo(f"  {state}: {count}")

    except Exception as e:
        click.echo(f"❌ Error getting statistics: {e}", err=True)
        ctx.exit(1)


@data_connectors.command('import')
@click.argument('file_path', type=click.Path(exists=True))
@click.pass_context
def import_data_connectors(ctx, file_path):
    """Import data connectors from file."""
    try:
        client = ctx.obj['client']
        connectors = client.data_connectors.import_data_connectors(file_path)

        click.echo(f"✅ Successfully imported {len(connectors)} data connectors from {file_path}")

    except Exception as e:
        click.echo(f"❌ Error importing data connectors: {e}", err=True)
        ctx.exit(1)


@data_connectors.command('export')
@click.argument('file_path', type=click.Path())
@click.option('--connector-ids', help='Comma-separated list of connector IDs to export')
@click.pass_context
def export_data_connectors(ctx, file_path, connector_ids):
    """Export data connectors to file."""
    try:
        client = ctx.obj['client']
        connector_ids_list = connector_ids.split(',') if connector_ids else None
        client.data_connectors.export_data_connectors(file_path, connector_ids_list)

        click.echo(f"✅ Successfully exported data connectors to {file_path}")

    except Exception as e:
        click.echo(f"❌ Error exporting data connectors: {e}", err=True)
        ctx.exit(1)


def main():
    """Main CLI entry point."""
    cli()
