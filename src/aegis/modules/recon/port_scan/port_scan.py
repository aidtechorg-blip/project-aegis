"""
Port scanning module for Project Aegis
Scans for open ports on target systems
"""

import socket
import concurrent.futures
from typing import Dict, List, Any
from aegis.modules.base_recon import BaseReconModule
from aegis.core.framework import Target

class PortScanModule(BaseReconModule):
    """Port scanning module"""
    name = "port_scan"
    description = "Scan for open ports on target systems"
    safe = True
    
    def __init__(self):
        super().__init__()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
    
    def scan_port(self, target_ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Enhanced port scanning with advanced banner grabbing"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            
            if result == 0:
                # Enhanced banner grabbing based on port
                banner = self._grab_advanced_banner(s, port)
                
                # Service fingerprinting
                service_info = self._identify_service(port, banner)
                
                return {
                    "port": port,
                    "status": "open",
                    "banner": banner,
                    "service": service_info.get('service', 'unknown'),
                    "version": service_info.get('version', 'unknown'),
                    "vulnerability_hints": service_info.get('vulnerabilities', [])
                }
            else:
                return {
                    "port": port,
                    "status": "closed"
                }
    except:
        return {
            "port": port,
            "status": "error"
        }

def _grab_advanced_banner(self, sock, port: int) -> str:
    """Advanced banner grabbing with protocol-specific probes"""
    try:
        if port == 80 or port == 443:
            # HTTP/S banner
            sock.send(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        elif port == 21:
            # FTP banner
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        elif port == 22:
            # SSH banner
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        elif port == 25:
            # SMTP banner
            sock.send(b"EHLO example.com\r\n")
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        else:
            # Generic banner
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
    except:
        return "Could not retrieve banner"

def _identify_service(self, port: int, banner: str) -> Dict[str, Any]:
    """Identify service and version from banner"""
    service_info = {
        "service": "unknown",
        "version": "unknown",
        "vulnerabilities": []
    }
    
    # Common service patterns
    patterns = {
        'ssh': r'SSH-([\d.]+)',
        'apache': r'Apache/([\d.]+)',
        'nginx': r'nginx/([\d.]+)',
        'iis': r'Microsoft-IIS/([\d.]+)',
        'openssh': r'OpenSSH_([\d.]+)'
    }
    
    for service, pattern in patterns.items():
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            service_info["service"] = service
            service_info["version"] = match.group(1)
            break
    
    # Add vulnerability hints based on version
    service_info["vulnerabilities"] = self._check_vulnerabilities(
        service_info["service"], service_info["version"]
    )
    
    return service_info