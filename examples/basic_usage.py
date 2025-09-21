#!/usr/bin/env python3
"""
Project Aegis - Basic Usage Example
Simple examples of how to use the framework
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.aegis.core.framework import AegisFramework, Target

def simple_usage():
    """Simple usage example"""
    print("Project Aegis - Simple Usage Example")
    print("=" * 40)
    
    # Initialize the framework
    framework = AegisFramework()
    framework.discover_modules()
    
    # Create a target
    target = Target(host="example.com")
    framework.set_target(target)
    
    print(f"Target: {target.host}")
    print(f"Available modules: {list(framework.modules.keys())}")
    print()
    
    # Run a single module
    print("Running port scan...")
    result = framework.run_module("port_scan", ports=[80, 443, 22])
    
    if result.get("success"):
        print("✓ Port scan successful")
        open_ports = result.get("open_ports", [])
        print(f"Open ports found: {len(open_ports)}")
        for port in open_ports:
            print(f"  • Port {port['port']}")
    else:
        print(f"✗ Port scan failed: {result.get('error')}")
    
    print()
    print("Results exported:")
    print(framework.export_results()[:200] + "...")  # Show first 200 chars

def module_chain_example():
    """Example of chaining multiple modules"""
    print("\nModule Chaining Example")
    print("=" * 40)
    
    framework = AegisFramework()
    framework.discover_modules()
    target = Target(host="example.com")
    framework.set_target(target)
    
    modules_to_run = ["subdomain_enum", "port_scan", "osint"]
    
    for module_name in modules_to_run:
        print(f"Running {module_name}...")
        result = framework.run_module(module_name)
        
        if result.get("success"):
            print(f"  ✓ {module_name} completed")
        else:
            print(f"  ✗ {module_name} failed: {result.get('error')}")
    
    print("\nFinal target state:")
    print(f"Subdomains found: {len(target.subdomains)}")
    print(f"Open ports: {len(target.ports)}")
    print(f"OSINT data points: {len(target.osint_data)}")

if __name__ == "__main__":
    simple_usage()
    module_chain_example()