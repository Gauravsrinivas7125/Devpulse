#!/usr/bin/env python3
"""
DevPulse CLI Tool
Command-line interface for DevPulse API operations
"""

import click
import json
import requests
from typing import Optional
import os
from pathlib import Path

# Configuration
DEFAULT_API_URL = os.getenv("DEVPULSE_API_URL", "http://localhost:8000")
CONFIG_DIR = Path.home() / ".devpulse"
CONFIG_FILE = CONFIG_DIR / "config.json"


class DevPulseConfig:
    """Manage CLI configuration"""
    
    def __init__(self):
        self.config_dir = CONFIG_DIR
        self.config_file = CONFIG_FILE
        self.load()
    
    def load(self):
        """Load configuration from file"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {
                "api_url": DEFAULT_API_URL,
                "api_key": None,
                "workspace_id": None
            }
    
    def save(self):
        """Save configuration to file"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.data.get(key, default)
    
    def set(self, key: str, value):
        """Set configuration value"""
        self.data[key] = value
        self.save()


config = DevPulseConfig()


@click.group()
def cli():
    """DevPulse CLI - API Security & Compliance Platform"""
    pass


@cli.command()
@click.option('--api-url', default=DEFAULT_API_URL, help='DevPulse API URL')
@click.option('--api-key', prompt='API Key', hide_input=True, help='DevPulse API Key')
def login(api_url: str, api_key: str):
    """Authenticate with DevPulse"""
    config.set("api_url", api_url)
    config.set("api_key", api_key)
    click.echo(f"✅ Logged in to {api_url}")


@cli.command()
def logout():
    """Logout from DevPulse"""
    config.set("api_key", None)
    config.set("workspace_id", None)
    click.echo("✅ Logged out")


@cli.command()
@click.argument('collection_file', type=click.Path(exists=True))
@click.option('--name', default=None, help='Collection name')
def import_collection(collection_file: str, name: Optional[str]):
    """Import a Postman collection"""
    api_url = config.get("api_url")
    api_key = config.get("api_key")
    
    if not api_key:
        click.echo("❌ Not authenticated. Run 'devpulse login' first.")
        return
    
    with open(collection_file, 'r') as f:
        collection_data = json.load(f)
    
    collection_name = name or collection_data.get("info", {}).get("name", "Imported Collection")
    
    try:
        response = requests.post(
            f"{api_url}/api/collections/import",
            json={
                "name": collection_name,
                "data": collection_data
            },
            headers={"Authorization": f"Bearer {api_key}"}
        )
        
        if response.status_code == 200:
            result = response.json()
            click.echo(f"✅ Collection imported successfully")
            click.echo(f"   Collection ID: {result.get('collection_id')}")
            click.echo(f"   Total Requests: {result.get('total_requests')}")
        else:
            click.echo(f"❌ Import failed: {response.text}")
    
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")


@cli.command()
@click.option('--collection-id', required=True, help='Collection ID to scan')
def scan(collection_id: str):
    """Run security scan on a collection"""
    api_url = config.get("api_url")
    api_key = config.get("api_key")
    
    if not api_key:
        click.echo("❌ Not authenticated. Run 'devpulse login' first.")
        return
    
    try:
        with click.progressbar(length=100, label='Scanning') as bar:
            response = requests.post(
                f"{api_url}/api/security/scan",
                json={"collection_id": collection_id},
                headers={"Authorization": f"Bearer {api_key}"}
            )
            bar.update(100)
        
        if response.status_code == 200:
            result = response.json()
            click.echo(f"\n✅ Scan completed")
            click.echo(f"   Scan ID: {result.get('scan_id')}")
            click.echo(f"   Risk Score: {result.get('risk_score')}/100")
            click.echo(f"   Risk Level: {result.get('risk_level')}")
            click.echo(f"   Total Findings: {result.get('total_findings')}")
        else:
            click.echo(f"❌ Scan failed: {response.text}")
    
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")


@cli.command()
@click.option('--collection-id', required=True, help='Collection ID')
def compliance(collection_id: str):
    """Generate PCI DSS compliance report"""
    api_url = config.get("api_url")
    api_key = config.get("api_key")
    
    if not api_key:
        click.echo("❌ Not authenticated. Run 'devpulse login' first.")
        return
    
    try:
        response = requests.post(
            f"{api_url}/api/compliance/pci-dss",
            json={"collection_id": collection_id, "export_pdf": True},
            headers={"Authorization": f"Bearer {api_key}"}
        )
        
        if response.status_code == 200:
            result = response.json()
            click.echo(f"✅ Compliance report generated")
            click.echo(f"   Status: {result.get('compliance_status')}")
            click.echo(f"   Compliance: {result.get('compliance_percentage')}%")
            if result.get('pdf_url'):
                click.echo(f"   PDF: {result.get('pdf_url')}")
        else:
            click.echo(f"❌ Report generation failed: {response.text}")
    
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")


@cli.command()
def status():
    """Get DevPulse server status"""
    api_url = config.get("api_url")
    
    try:
        response = requests.get(f"{api_url}/api/health")
        if response.status_code == 200:
            click.echo(f"✅ DevPulse is running at {api_url}")
        else:
            click.echo(f"❌ DevPulse is not responding correctly")
    except Exception as e:
        click.echo(f"❌ Cannot connect to {api_url}: {str(e)}")


@cli.command()
def config_show():
    """Show current configuration"""
    click.echo("Current Configuration:")
    for key, value in config.data.items():
        if key == "api_key" and value:
            value = "***" + value[-4:] if len(value) > 4 else "****"
        click.echo(f"  {key}: {value}")


if __name__ == '__main__':
    cli()
