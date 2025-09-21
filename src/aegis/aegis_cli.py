#!/usr/bin/env python3
"""
Project Aegis - Main CLI Interface
Next-Generation Ethical Penetration Testing Framework
"""

import argparse
import sys
import os
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add the src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from aegis.core.framework import AegisFramework, Target
from aegis.modules import SubdomainEnumModule, OSINTModule, PortScanModule

class AegisCLI:
    """Main CLI handler for Project Aegis"""
    
    def __init__(self):
        self.framework = AegisFramework()
        self.results = []
        self.current_target = None
        
    def print_banner(self):
        """Print the tool banner"""
        banner = r"""
    ╔═══════════════════════════════════════════════════╗
    ║                  PROJECT AEGIS                   ║
    ║           Next-Gen Penetration Testing           ║
    ╚═══════════════════════════════════════════════════╝
    """
        print(banner)
        print("    Ethical Penetration Testing Framework")
        print("    Version: 0.1.0 | Phase 1: Reconnaissance")
        print("    " + "="*47)
        print()
    
    def setup_parser(self) -> argparse.ArgumentParser:
        """Setup command line argument parser"""
        parser = argparse.ArgumentParser(
            description="Project Aegis - Ethical Penetration Testing Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  aegis recon example.com --all              # Full reconnaissance
  aegis recon example.com -sp                # Subdomains and ports only
  aegis scan 192.168.1.1 -p 1-1000           # Custom port range
  aegis osint example.com --shodan-key KEY   # OSINT with Shodan
  aegis test --full                          # Run complete test suite
            """
        )
        
        # Main commands
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # Recon command
        recon_parser = subparsers.add_parser("recon", help="Comprehensive reconnaissance")
        recon_parser.add_argument("target", help="Target domain or IP address")
        recon_parser.add_argument("-s", "--subdomains", action="store_true", 
                                 help="Perform subdomain enumeration")
        recon_parser.add_argument("-p", "--ports", action="store_true", 
                                 help="Perform port scanning")
        recon_parser.add_argument("-o", "--osint", action="store_true", 
                                 help="Gather OSINT information")
        recon_parser.add_argument("-a", "--all", action="store_true", 
                                 help="Run all reconnaissance modules")
        recon_parser.add_argument("--output", default="json", 
                                 choices=["json", "text", "csv"], 
                                 help="Output format")
        recon_parser.add_argument("--save", action="store_true", 
                                 help="Save results to file")
        
        # Scan command (focused scanning)
        scan_parser = subparsers.add_parser("scan", help="Focused scanning operations")
        scan_parser.add_argument("target", help="Target domain or IP address")
        scan_parser.add_argument("-p", "--ports", default="1-1000", 
                                help="Port range (e.g., 1-1000, 80,443,22)")
        scan_parser.add_argument("-t", "--timeout", type=float, default=1.0,
                                help="Timeout per port (seconds)")
        scan_parser.add_argument("-w", "--workers", type=int, default=50,
                                help="Number of concurrent workers")
        
        # OSINT command
        osint_parser = subparsers.add_parser("osint", help="OSINT gathering")
        osint_parser.add_argument("target", help="Target domain")
        osint_parser.add_argument("--shodan-key", help="Shodan API key")
        osint_parser.add_argument("--full", action="store_true", 
                                 help="Comprehensive OSINT collection")
        
        # Test command
        test_parser = subparsers.add_parser("test", help="Framework testing")
        test_parser.add_argument("--quick", action="store_true", 
                                help="Run quick functionality tests")
        test_parser.add_argument("--full", action="store_true", 
                                help="Run complete test suite")
        test_parser.add_argument("--target", default="example.com",
                                help="Test target")
        
        # Info command
        subparsers.add_parser("info", help="Framework information")
        
        # Module command
        module_parser = subparsers.add_parser("modules", help="Module management")
        module_parser.add_argument("--list", action="store_true", 
                                  help="List available modules")
        module_parser.add_argument("--info", help="Show module information")
        
        return parser
    
    def parse_port_range(self, port_spec: str) -> List[int]:
        """Parse port range specification"""
        ports = []
        for part in port_spec.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports
    
    async def run_recon(self, args):
        """Run comprehensive reconnaissance"""
        print(f"[*] Starting reconnaissance on: {args.target}")
        print("[*] Loading modules...")
        
        self.framework.discover_modules()
        self.current_target = Target(host=args.target)
        self.framework.set_target(self.current_target)
        
        results = {}
        modules_to_run = []
        
        # Determine which modules to run
        if args.all:
            modules_to_run = ["subdomain_enum", "port_scan", "osint"]
        else:
            if args.subdomains:
                modules_to_run.append("subdomain_enum")
            if args.ports:
                modules_to_run.append("port_scan")
            if args.osint:
                modules_to_run.append("osint")
        
        if not modules_to_run:
            print("[!] No modules selected. Use --all or specify modules.")
            return
        
        # Run modules
        for module_name in modules_to_run:
            print(f"[*] Running {module_name}...")
            
            module_args = {}
            if module_name == "osint" and hasattr(args, 'shodan_key') and args.shodan_key:
                module_args["shodan_key"] = args.shodan_key
            
            result = self.framework.run_module(module_name, **module_args)
            results[module_name] = result
            
            if result.get("success"):
                print(f"    ✓ {module_name} completed successfully")
            else:
                print(f"    ✗ {module_name} failed: {result.get('error', 'Unknown error')}")
        
        # Display results
        print("\n" + "="*60)
        print("RECONNAISSANCE RESULTS")
        print("="*60)
        print(f"Target: {args.target}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        self.display_results(results, args.output)
        
        # Save results if requested
        if args.save:
            filename = f"aegis_recon_{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(self.framework.export_results())
            print(f"\n[*] Results saved to: {filename}")
    
    def display_results(self, results: Dict, format: str = "text"):
        """Display results in specified format"""
        if format == "json":
            print(json.dumps(results, indent=2))
            return
        
        for module_name, result in results.items():
            if not result.get("success"):
                continue
                
            print(f"\n[{module_name.upper()}]")
            print("-" * 40)
            
            if module_name == "subdomain_enum":
                subdomains = result.get("subdomains_found", [])
                print(f"Subdomains found: {len(subdomains)}")
                for subdomain in subdomains:
                    print(f"  • {subdomain}")
            
            elif module_name == "port_scan":
                open_ports = result.get("open_ports", [])
                print(f"Open ports: {len(open_ports)}")
                for port_info in open_ports:
                    banner = port_info.get("banner", "").replace('\n', ' ').replace('\r', '')[:50]
                    print(f"  • Port {port_info['port']}: {banner}...")
            
            elif module_name == "osint":
                print("OSINT Information:")
                for key, value in result.items():
                    if key not in ['success', 'error']:
                        if isinstance(value, list):
                            print(f"  • {key}:")
                            for item in value:
                                print(f"    - {item}")
                        else:
                            print(f"  • {key}: {value}")
    
    async def run_scan(self, args):
        """Run focused port scanning"""
        print(f"[*] Starting port scan on: {args.target}")
        
        # Parse port range
        try:
            ports = self.parse_port_range(args.ports)
            print(f"[*] Scanning {len(ports)} ports with {args.workers} workers")
        except ValueError:
            print("[!] Invalid port specification. Use format: 1-1000 or 80,443,22")
            return
        
        # Initialize and run port scan
        port_module = PortScanModule()
        target = Target(host=args.target)
        
        result = port_module.run(target, ports=ports, timeout=args.timeout, max_workers=args.workers)
        
        if result.get("success"):
            print("\n[PORT SCAN RESULTS]")
            print("=" * 40)
            print(f"Target: {args.target}")
            print(f"IP: {result.get('target_ip', 'Unknown')}")
            print(f"Open ports: {len(result.get('open_ports', []))}")
            print(f"Ports scanned: {result.get('ports_scanned', 0)}")
            print()
            
            for port_info in result.get("open_ports", []):
                banner = port_info.get("banner", "No banner").replace('\n', ' ').replace('\r', '')
                print(f"  {port_info['port']}/tcp - {banner[:60]}...")
        else:
            print(f"[!] Scan failed: {result.get('error', 'Unknown error')}")
    
    async def run_osint(self, args):
        """Run OSINT gathering"""
        print(f"[*] Gathering OSINT for: {args.target}")
        
        osint_module = OSINTModule()
        target = Target(host=args.target)
        
        module_args = {}
        if args.shodan_key:
            module_args["shodan_key"] = args.shodan_key
        
        result = osint_module.run(target, **module_args)
        
        if result.get("success"):
            print("\n[OSINT RESULTS]")
            print("=" * 40)
            
            # Display certificate transparency results
            if "ct_log_subdomains" in result:
                subdomains = result["ct_log_subdomains"]
                print(f"Subdomains from Certificate Transparency logs: {len(subdomains)}")
                for subdomain in subdomains[:10]:  # Show first 10
                    print(f"  • {subdomain}")
                if len(subdomains) > 10:
                    print(f"  • ... and {len(subdomains) - 10} more")
            
            # Display other OSINT findings
            for key, value in result.items():
                if key not in ['success', 'error', 'ct_log_subdomains'] and value:
                    print(f"\n{key.replace('_', ' ').title()}:")
                    if isinstance(value, list):
                        for item in value:
                            print(f"  • {item}")
                    else:
                        print(f"  {value}")
        else:
            print(f"[!] OSINT gathering failed: {result.get('error', 'Unknown error')}")
    
    async def run_test(self, args):
        """Run framework tests"""
        print("[*] Running framework tests...")
        
        if args.quick:
            print("[*] Running quick functionality tests...")
            # Basic functionality tests
            try:
                # Test framework initialization
                framework = AegisFramework()
                print("✓ Framework initialization")
                
                # Test target creation
                target = Target(host=args.target)
                print("✓ Target creation")
                
                # Test module discovery
                modules = framework.discover_modules()
                print(f"✓ Module discovery ({len(modules)} modules found)")
                
                print("\n✓ All quick tests passed!")
                
            except Exception as e:
                print(f"✗ Test failed: {e}")
                return False
        
        elif args.full:
            print("[*] Running complete test suite...")
            # This would run the full pytest suite
            try:
                import subprocess
                result = subprocess.run([
                    sys.executable, "-m", "pytest", 
                    "tests/", "-v", "--tb=short"
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    print("✓ All tests passed!")
                    print(result.stdout)
                else:
                    print("✗ Some tests failed")
                    print(result.stdout)
                    if result.stderr:
                        print("Errors:", result.stderr)
                    return False
            except Exception as e:
                print(f"✗ Test execution failed: {e}")
                return False
        
        else:
            print("[!] Please specify --quick or --full for testing")
            return False
        
        return True
    
    def show_info(self):
        """Show framework information"""
        self.print_banner()
        
        # Discover available modules
        self.framework.discover_modules()
        
        print("Available Modules:")
        print("-" * 40)
        for module_name, module_info in self.framework.modules.items():
            print(f"  • {module_name}: {module_info.get('description', 'No description')}")
        
        print("\nUsage Examples:")
        print("  aegis recon example.com --all")
        print("  aegis scan 192.168.1.1 -p 1-1000 -w 100")
        print("  aegis osint example.com --shodan-key YOUR_KEY")
        print("  aegis test --full")
        print("\nFor detailed help: aegis <command> --help")
    
    def list_modules(self):
        """List available modules"""
        self.framework.discover_modules()
        
        print("Available Modules:")
        print("=" * 60)
        for module_name, module_info in self.framework.modules.items():
            print(f"\nModule: {module_name}")
            print(f"Description: {module_info.get('description', 'No description')}")
            print(f"Category: {module_info.get('category', 'Unknown')}")
            print(f"Safe: {'Yes' if module_info.get('safe', True) else 'No'}")
    
    async def run(self):
        """Main CLI execution"""
        self.print_banner()
        
        parser = self.setup_parser()
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            if args.command == "recon":
                await self.run_recon(args)
            elif args.command == "scan":
                await self.run_scan(args)
            elif args.command == "osint":
                await self.run_osint(args)
            elif args.command == "test":
                await self.run_test(args)
            elif args.command == "info":
                self.show_info()
            elif args.command == "modules":
                if args.list:
                    self.list_modules()
                elif args.info:
                    # Show specific module info
                    pass
                else:
                    parser.print_help()
        
        except KeyboardInterrupt:
            print("\n\n[!] Operation cancelled by user")
        except Exception as e:
            print(f"\n[!] Error: {e}")
            if hasattr(args, 'debug') and args.debug:
                import traceback
                traceback.print_exc()

def main():
    """Main entry point"""
    try:
        cli = AegisCLI()
        asyncio.run(cli.run())
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()