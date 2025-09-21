"""
Aegis Modules Package
All penetration testing modules for Project Aegis
"""

# Import recon modules for easy access
from aegis.modules.recon.subdomain_enum.subdomain_enum import SubdomainEnumModule
from aegis.modules.recon.osint.osint import OSINTModule
from aegis.modules.recon.port_scan.port_scan import PortScanModule

__all__ = ['SubdomainEnumModule', 'OSINTModule', 'PortScanModule']