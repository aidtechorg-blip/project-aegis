#!/usr/bin/env python3
"""
Example usage of Project Aegis reconnaissance modules
"""

import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.aegis.core.framework import AegisFramework, Target
from modules.recon import SubdomainEnumModule, OSINTModule, PortScanModule

async def main():
    """Demo the reconnaissance modules"""
    print("Project Aegis - Reconnaissance Demo")
    print("=" * 50)
    
    # Initialize framework
    framework = AegisFramework()
    framework.discover_modules()
    
    # Create target
    target = Target(host="example.com")
    framework.set_target(target)
    
    # Run subdomain enumeration
    print("\n1. Running subdomain enumeration...")
    subdomain_result = framework.run_module("subdomain_enum", subdomains=["www", "mail", "ftp"])
    print(f"Found {len(subdomain_result.get('subdomains_found', []))} subdomains")
    
    # Run OSINT gathering
    print("\n2. Running OSINT gathering...")
    osint_result = framework.run_module("osint")
    print("OSINT gathering complete")
    
    # Run port scanning
    print("\n3. Running port scanning...")
    port_scan_result = framework.run_module("port_scan", ports=[80, 443, 22, 21])
    print(f"Found {len(port_scan_result.get('open_ports', []))} open ports")
    
    # Display results
    print("\n4. Results Summary:")
    print(f"Target: {target.host}")
    print(f"IP: {target.ip or 'Not resolved'}")
    print(f"Subdomains found: {getattr(target, 'subdomains', [])}")
    print(f"Open ports: {getattr(target, 'ports', [])}")
    
    # Export results
    print("\n5. Exporting results...")
    results = framework.export_results()
    print(results[:500] + "..." if len(results) > 500 else results)

if __name__ == "__main__":
    asyncio.run(main())