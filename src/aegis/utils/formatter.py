"""
Advanced output formatting for Project Aegis
Professional reporting and visualization
"""

from typing import Dict, List, Any
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.box import ROUNDED
from rich.markdown import Markdown

class OutputFormatter:
    """Advanced output formatting with rich visualization"""
    
    def __init__(self):
        self.console = Console()
        self.color_map = {
            "HIGH": "red",
            "MEDIUM": "yellow", 
            "LOW": "green",
            "INFO": "blue",
            "SUCCESS": "green",
            "WARNING": "yellow",
            "ERROR": "red"
        }
    
    def print_banner(self, title: str, subtitle: str = ""):
        """Print professional banner"""
        banner = Panel.fit(
            f"[bold cyan]{title}[/]\n[dim]{subtitle}[/]",
            border_style="cyan",
            box=ROUNDED
        )
        self.console.print(banner)
    
    def print_results(self, results: Dict, format: str = "rich"):
        """Print results in specified format"""
        if format == "json":
            self._print_json(results)
        elif format == "csv":
            self._print_csv(results)
        elif format == "text":
            self._print_text(results)
        else:
            self._print_rich(results)
    
    def _print_rich(self, results: Dict):
        """Rich formatted output with tables and panels"""
        
        # Executive Summary Panel
        summary = results.get('summary', {})
        summary_panel = Panel(
            f"[bold]Domain Age:[/] {summary.get('domain_age', 'N/A')}\n"
            f"[bold]Threat Level:[/] [{self.color_map.get(summary.get('threat_level', 'INFO'))}]{summary.get('threat_level', 'N/A')}[/]\n"
            f"[bold]Open Ports:[/] {summary.get('open_ports', 0)}\n"
            f"[bold]Subdomains:[/] {summary.get('subdomains_found', 0)}\n"
            f"[bold]DNS Records:[/] {summary.get('dns_records', 0)}",
            title="[bold]Executive Summary[/]",
            border_style="green"
        )
        self.console.print(summary_panel)
        
        # Threat Assessment
        threat = results.get('threat_assessment', {})
        if threat:
            threat_panel = Panel(
                f"[bold]Threat Score:[/] {threat.get('threat_score', 0)}/100\n"
                f"[bold]Level:[/] [{self.color_map.get(threat.get('threat_level', 'INFO'))}]{threat.get('threat_level', 'N/A')}[/]\n\n"
                f"[bold]Warnings:[/]\n" + "\n".join(f"• {w}" for w in threat.get('warnings', [])) + "\n\n"
                f"[bold]Recommendations:[/]\n" + "\n".join(f"• {r}" for r in threat.get('recommendations', [])),
                title="[bold]Threat Assessment[/]",
                border_style=self.color_map.get(threat.get('threat_level', 'INFO'), 'blue')
            )
            self.console.print(threat_panel)
        
        # DNS Records Table
        dns_records = results.get('dns_records', {})
        if dns_records:
            dns_table = Table(title="[bold]DNS Records[/]", box=ROUNDED)
            dns_table.add_column("Type", style="cyan")
            dns_table.add_column("Values", style="white")
            
            for record_type, values in dns_records.items():
                if values:
                    dns_table.add_row(record_type.upper(), "\n".join(values[:3]) + ("\n..." if len(values) > 3 else ""))
            
            self.console.print(dns_table)
        
        # Open Ports Table
        shodan_data = results.get('shodan_data', {})
        if shodan_data.get('ports'):
            ports_table = Table(title="[bold]Open Ports & Services[/]", box=ROUNDED)
            ports_table.add_column("Port", style="cyan")
            ports_table.add_column("Service", style="green")
            ports_table.add_column("Version", style="yellow")
            ports_table.add_column("Info", style="white")
            
            for service in shodan_data.get('services', []):
                ports_table.add_row(
                    str(service.get('port', '')),
                    service.get('service', ''),
                    service.get('version', ''),
                    service.get('info', '')
                )
            
            self.console.print(ports_table)
    
    def _print_json(self, results: Dict):
        """JSON formatted output"""
        self.console.print(json.dumps(results, indent=2, default=str))
    
    def _print_csv(self, results: Dict):
        """CSV formatted output"""
        # Flatten results for CSV
        flat_data = self._flatten_dict(results)
        
        writer = csv.writer(self.console.file)
        writer.writerow(['Key', 'Value'])
        for key, value in flat_data.items():
            writer.writerow([key, value])
    
    def _print_text(self, results: Dict):
        """Simple text output"""
        for key, value in results.items():
            if isinstance(value, dict):
                self.console.print(f"\n[{key.upper()}]")
                for k, v in value.items():
                    self.console.print(f"  {k}: {v}")
            else:
                self.console.print(f"{key}: {value}")
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str='.') -> Dict:
        """Flatten nested dictionary for CSV output"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, '; '.join(map(str, v))))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def generate_html_report(self, results: Dict, filename: str):
        """Generate HTML report"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Project Aegis OSINT Report - {datetime.now().strftime('%Y-%m-%d')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 10px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .threat-high {{ background: #ffebee; border-left: 5px solid #f44336; }}
                .threat-medium {{ background: #fff3e0; border-left: 5px solid #ff9800; }}
                .threat-low {{ background: #e8f5e8; border-left: 5px solid #4caf50; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Project Aegis OSINT Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p><strong>Target:</strong> {results.get('target', 'N/A')}</p>
                <p><strong>Threat Level:</strong> <span class="threat-{results.get('threat_assessment', {}).get('threat_level', 'low').lower()}">{results.get('threat_assessment', {}).get('threat_level', 'N/A')}</span></p>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_template)