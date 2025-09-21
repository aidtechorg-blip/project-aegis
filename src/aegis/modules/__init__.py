"""
Aegis Modules Package
All penetration testing modules for Project Aegis
"""

# Import recon modules for easy access
from .recon.subdomain_enum.subdomain_enum import SubdomainEnumModule
from .recon.osint.osint import OSINTModule
from .recon.port_scan.port_scan import PortScanModule

__all__ = ['SubdomainEnumModule', 'OSINTModule', 'PortScanModule']