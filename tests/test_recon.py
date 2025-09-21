"""
Tests for reconnaissance modules
"""

import pytest
import asyncio
from src.aegis.core.framework import Target
from modules.recon.subdomain_enum.subdomain_enum import SubdomainEnumModule
from modules.recon.osint.osint import OSINTModule
from modules.recon.port_scan.port_scan import PortScanModule

def test_subdomain_module_initialization():
    """Test subdomain enumeration module initialization"""
    module = SubdomainEnumModule()
    assert module.name == "subdomain_enum"
    assert module.description == "Discover subdomains using multiple techniques"
    assert module.safe is True

def test_osint_module_initialization():
    """Test OSINT module initialization"""
    module = OSINTModule()
    assert module.name == "osint"
    assert module.description == "Collect open source intelligence about targets"
    assert module.safe is True

def test_port_scan_module_initialization():
    """Test port scan module initialization"""
    module = PortScanModule()
    assert module.name == "port_scan"
    assert module.description == "Scan for open ports on target systems"
    assert module.safe is True

def test_subdomain_enumeration():
    """Test subdomain enumeration with a test domain"""
    module = SubdomainEnumModule()
    target = Target(host="example.com")
    
    # Test with a small subset of subdomains
    result = module.run(target, subdomains=["www", "mail", "nonexistent12345"])
    
    assert "success" in result
    # www.example.com should exist
    assert "www.example.com" in result.get("subdomains_found", [])

def test_port_scanning_localhost():
    """Test port scanning with localhost (basic test)"""
    module = PortScanModule()
    target = Target(host="127.0.0.1")
    
    # Test with a small set of ports
    result = module.run(target, ports=[80, 443, 9999])
    
    assert "success" in result
    assert "open_ports" in result
    # Just verify the structure, not specific results

def test_osint_gathering():
    """Test OSINT gathering (basic functionality)"""
    module = OSINTModule()
    target = Target(host="example.com")
    
    result = module.run(target)
    
    assert "success" in result
    assert "results" in result
    # Should contain some OSINT data
    assert len(result["results"]) > 0

def test_module_safety():
    """Test that all recon modules are marked as safe"""
    modules = [SubdomainEnumModule(), OSINTModule(), PortScanModule()]
    
    for module in modules:
        assert module.safe is True, f"{module.name} should be safe for reconnaissance"

def test_target_validation_in_modules():
    """Test target validation in all modules"""
    modules = [SubdomainEnumModule(), OSINTModule(), PortScanModule()]
    invalid_target = Target(host="localhost")
    
    for module in modules:
        result = module.run(invalid_target)
        # Should handle invalid target gracefully
        assert "success" in result

if __name__ == "__main__":
    pytest.main([__file__, "-v"])