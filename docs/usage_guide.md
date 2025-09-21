# Project Aegis - Usage Guide

## Installation

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/your-username/project-aegis.git
cd project-aegis

# Install using pip
pip install .

# Or for development
pip install -e .

## Using Virtual Environment
# Create virtual environment
python3 -m venv aegis-env
source aegis-env/bin/activate  # Linux/Mac
# or
aegis-env\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -e .

## Basic Usage
# Getting Help
# Show main help
aegis --help

# Show command-specific help
aegis recon --help
aegis scan --help
aegis osint --help

# Framework Information
# Show framework info and available modules
aegis info

# List all available modules
aegis modules --list

## Reconnaissance Commands
# Comprehensive Reconnaissance
# Run all reconnaissance modules on a target
aegis recon example.com --all

# Run specific modules
aegis recon example.com --subdomains --ports

# Save results to file
aegis recon example.com --all --save

# Specify output format
aegis recon example.com --all --output json

# Focused Port Scanning
# Scan specific port range
aegis scan 192.168.1.1 -p 1-1000

# Custom port list
aegis scan 192.168.1.1 -p 80,443,22,21

# Adjust timeout and workers
aegis scan 192.168.1.1 -p 1-1000 -t 0.5 -w 100

# OSINT Gathering
# Basic OSINT collection
aegis osint example.com

# With Shodan API key
aegis osint example.com --shodan-key YOUR_API_KEY

# Comprehensive OSINT
aegis osint example.com --full

## Testing
# Framework Testing
# Quick functionality test
aegis test --quick

# Complete test suite
aegis test --full

# Test with specific target
aegis test --target test.example.com

## Module Configuration
# Custom Wordlists
# Create a wordlists/ directory and add your custom wordlists:
mkdir wordlists
# Add your subdomain wordlists here

## Configuration File

# Create a config.json file for persistent settings:
{
    "max_threads": 20,
    "default_timeout": 2.0,
    "output_format": "text",
    "safe_mode": true
}

## Output Formats
# JSON Output
aegis recon example.com --output json

# Ideal for automated processing and integration with other tools.

# Text Output
aegis recon example.com --output text

# Human-readable format with clear section headers.

# CSV Output
aegis recon example.com --output csv

# Spreadsheet-friendly format (coming soon).

## Examples
# Basic Assessment
# Quick assessment of a web server
aegis recon example.com --subdomains --ports
aegis osint example.com

# Comprehensive Assessment
# Full assessment with all modules
aegis recon target-company.com --all --save
aegis osint target-company.com --full

# Network Scanning
# Scan entire network range
for ip in 192.168.1.{1..254}; do
    aegis scan $ip -p 1-1000 --save
done

## Best Practices 

# 1. Always Get Authorization
# Verify authorization before scanning
echo "Checking authorization for: example.com"
# Proceed only after confirmation

# 2. Use Safe Mode
# Safe mode is enabled by default
# Disable only when absolutely necessary and authorized

# 3. Monitor Resource Usage
# Adjust worker count based on system resources
aegis scan target.com -w 50  # Moderate
aegis scan target.com -w 10  # Conservative

# 4. Save Results
# Always save results for documentation
aegis recon target.com --all --save

## Troubleshooting
# Common Issues

    # Import Errors: Make sure all dependencies are installed

    # Network Issues: Check firewall settings and network connectivity

    # Permission Issues: Run with appropriate permissions for network operations

# Getting Help

    # Check the --help for any command

    # Review the ethical charter before reporting issues

    # Open issues on GitHub for bugs and feature requests

# Advanced Usage
# Custom Modules

# Create custom modules in the modules/ directory following the base module structure.

# Integration

# Use the JSON output format to integrate with other security tools and workflows.

# Automation

# Create scripts that chain multiple Aegis commands for automated assessment workflows.


## 28. Example Scripts (examples/recon_demo.py)

```python
#!/usr/bin/env python3
"""
Project Aegis - Reconnaissance Demo Script
Example usage of reconnaissance modules
"""

import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.aegis.core.framework import AegisFramework, Target

async def demo_basic_recon():
    """Demo basic reconnaissance functionality"""
    print("Project Aegis - Reconnaissance Demo")
    print("=" * 50)
    
    # Initialize framework
    framework = AegisFramework()
    framework.discover_modules()
    
    # Create target
    target = Target(host="example.com")
    framework.set_target(target)
    
    print(f"Target: {target.host}")
    print()
    
    # Run subdomain enumeration
    print("1. Running subdomain enumeration...")
    subdomain_result = framework.run_module("subdomain_enum")
    if subdomain_result.get("success"):
        subdomains = subdomain_result.get("subdomains_found", [])
        print(f"   Found {len(subdomains)} subdomains")
        for subdomain in subdomains[:5]:  # Show first 5
            print(f"   • {subdomain}")
        if len(subdomains) > 5:
            print(f"   • ... and {len(subdomains) - 5} more")
    else:
        print(f"   Failed: {subdomain_result.get('error')}")
    
    print()
    
    # Run port scanning
    print("2. Running port scanning...")
    port_scan_result = framework.run_module("port_scan", ports=[80, 443, 22, 21, 8080])
    if port_scan_result.get("success"):
        open_ports = port_scan_result.get("open_ports", [])
        print(f"   Found {len(open_ports)} open ports")
        for port_info in open_ports:
            print(f"   • Port {port_info['port']}: {port_info.get('banner', 'No banner')[:50]}...")
    else:
        print(f"   Failed: {port_scan_result.get('error')}")
    
    print()
    
    # Run OSINT gathering
    print("3. Gathering OSINT information...")
    osint_result = framework.run_module("osint")
    if osint_result.get("success"):
        results = osint_result.get("results", {})
        print(f"   Gathered {len(results)} OSINT data points")
        for key in results.keys():
            if key != "shodan_info":
                print(f"   • {key}")
    else:
        print(f"   Failed: {osint_result.get('error')}")
    
    print()
    print("Demo completed successfully!")
    print("Use 'aegis recon --all' for comprehensive scanning")

async def demo_advanced_usage():
    """Demo advanced usage patterns"""
    print("\nAdvanced Usage Demo")
    print("=" * 50)
    
    framework = AegisFramework()
    framework.discover_modules()
    
    # Multiple targets
    targets = ["example.com", "test.example.com"]
    
    for target_host in targets:
        print(f"\nScanning: {target_host}")
        target = Target(host=target_host)
        framework.set_target(target)
        
        # Quick scan
        result = framework.run_module("port_scan", ports=[80, 443])
        if result.get("success"):
            open_ports = result.get("open_ports", [])
            print(f"   Open ports: {[p['port'] for p in open_ports]}")
        else:
            print(f"   Scan failed: {result.get('error')}")

if __name__ == "__main__":
    print("Project Aegis Demonstration")
    print("This demo shows basic usage of the reconnaissance modules.")
    print("Note: This uses example.com for demonstration purposes.")
    print()
    
    asyncio.run(demo_basic_recon())
    # Uncomment for advanced demo
    # asyncio.run(demo_advanced_usage())

