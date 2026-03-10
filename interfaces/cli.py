import click
from rich.console import Console
from rich.table import Table
from core.recon.waf import WafDetector
from core.recon.subdomain import SubdomainScanner
from modules.web.sqli import SQLiEngine
from intel.manager import IntelManager

console = Console()

@click.group()
def cli():
    """Arsenal CLI: Weaponized Python Offensive Toolkit"""
    pass

@cli.command()
@click.argument('target')
def scan(target):
    """Perform a full reconnaissance scan on a target."""
    console.print(f"[bold red][*][/bold red] Starting Arsenal Recon on: [bold cyan]{target}[/bold cyan]")
    
    # WAF Detection
    waf = WafDetector()
    results = waf.detect(target, callback=lambda m, c=None: console.print(f"  [yellow]>>[/yellow] {m}"))
    
    # Subdomains
    sub = SubdomainScanner()
    console.print(f"\n[bold green][+][/bold green] Enumerating subdomains...")
    subs = sub.scan(target, callback=lambda m, c=None: console.print(f"    [dim]{m}[/dim]"))
    
    # Store in Intel
    intel = IntelManager()
    intel.add_target(target, {"subdomains": subs, "waf": results})
    console.print(f"\n[bold blue][!][/bold blue] Recon complete. Data synced to Intel Vault.")

@cli.command()
def loot():
    """View captured loot from the intel database."""
    intel = IntelManager()
    table = Table(title="Captured Loot")
    table.add_column("Target", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Timestamp", style="dim")
    
    # Logic to fetch from dataset could be added here
    console.print(table)

if __name__ == "__main__":
    cli()
