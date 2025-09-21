"""
Aegis Modules Package
All penetration testing modules for Project Aegis
"""

# Import recon modules for easy access
from modules.recon.subdomain_enum.subdomain_enum import SubdomainEnumModule
from modules.recon.osint.osint import OSINTModule
from modules.recon.port_scan.port_scan import PortScanModule

__all__ = ['SubdomainEnumModule', 'OSINTModule', 'PortScanModule']