#!/usr/bin/env python3
"""
Project Aegis CLI - Advanced Reconnaissance Framework
Command-line interface for Project Aegis
"""

import argparse
import sys
from datetime import datetime
from typing import Dict, List, Any

from aegis.core.framework import Target
from aegis.modules.recon.osint.osint import OSINTModule
from aegis.utils.formatter import OutputFormatter
from aegis.core.config import config

class AegisCLI:
    """Command-line interface for Project Aegis"""
    
    def __init__(self):
        self.parser = self.setup_parser()
        self.args = self.parser.parse_args()
        self.formatter = OutputFormatter()
    
    def setup_parser(self) -> argparse.ArgumentParser:
        """Setup command line argument parser"""
        parser = argparse.ArgumentParser(
            description="Project Aegis - Advanced Reconnaissance Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  aegis config set shodan YOUR_API_KEY
  aegis recon osint example.com --format rich
  aegis recon osint 192.168.1.1 --format json
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Config command
        config_parser = subparsers.add_parser('config', help='Manage configuration')
        config_subparsers = config_parser.add_subparsers(dest='subcommand', help='Config subcommand')
        
        # Config set command
        set_parser = config_subparsers.add_parser('set', help='Set an API key')
        set_parser.add_argument('service', help='Service name (shodan, virustotal, etc)')
        set_parser.add_argument('key', help='API key')
        
        # Config list command  
        config_subparsers.add_parser('list', help='List configured API keys')
        
        # Recon command
        recon_parser = subparsers.add_parser('recon', help='Reconnaissance operations')
        recon_subparsers = recon_parser.add_subparsers(dest='recon_module', help='Reconnaissance module')
        
        # OSINT module
        osint_parser = recon_subparsers.add_parser('osint', help='OSINT gathering')
        osint_parser.add_argument('target', help='Target domain or IP address')
        osint_parser.add_argument('--format', choices=['rich', 'json', 'csv', 'text'], 
                                 default='rich', help='Output format')
        osint_parser.add_argument('--html-report', action='store_true', 
                                 help='Generate HTML report')
        
        return parser
    
    def handle_config(self):
        """Handle configuration commands"""
        if self.args.command == 'config':
            if self.args.subcommand == 'set':
                config.set_api_key(self.args.service, self.args.key)
                print(f"✅ API key for {self.args.service} saved successfully.")
            elif self.args.subcommand == 'list':
                api_keys = config.list_api_keys()
                if api_keys:
                    print("🔐 Configured API Keys:")
                    for service, key in api_keys.items():
                        masked_key = f"{key[:5]}...{key[-5:]}" if len(key) > 10 else key
                        print(f"  {service.upper():<15}: {masked_key}")
                else:
                    print("❌ No API keys configured. Use 'aegis config set <service> <key>' to add keys.")
    
    def run_recon(self):
        """Run reconnaissance operations"""
        if self.args.command == 'recon':
            target = Target(self.args.target)
            
            if self.args.recon_module == 'osint':
                self.run_osint(target)
    
    def run_osint(self, target: Target):
        """Run OSINT gathering"""
        osint_module = OSINTModule()
        
        print(f"🔍 Starting OSINT gathering for {target.host}...")
        
        results = osint_module.run(target)
        
        if results.get('success'):
            self.display_results(results, self.args.format)
            
            # Generate HTML report if requested
            if self.args.html_report:
                report_file = f"aegis_report_{target.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                self.formatter.generate_html_report(results, report_file)
                print(f"\n📊 HTML report generated: {report_file}")
        else:
            print(f"❌ OSINT gathering failed: {results.get('error', 'Unknown error')}")
    
    def display_results(self, results: Dict, format: str = "rich"):
        """Display results with enhanced formatting"""
        if format == "json":
            self.formatter.print_results(results, "json")
        elif format == "csv":
            self.formatter.print_results(results, "csv")
        elif format == "text":
            self.formatter.print_results(results, "text")
        else:
            self.formatter.print_results(results, "rich")
    
    def run(self):
        """Main entry point"""
        if not self.args.command:
            self.parser.print_help()
            return
        
        try:
            if self.args.command == 'config':
                self.handle_config()
            elif self.args.command == 'recon':
                self.run_recon()
            else:
                self.parser.print_help()
                
        except KeyboardInterrupt:
            print("\n⏹️  Operation cancelled by user")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            sys.exit(1)

def main():
    """Main function"""
    cli = AegisCLI()
    cli.run()

if __name__ == "__main__":
    main()