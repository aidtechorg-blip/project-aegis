"""
Port scanning module for Project Aegis
Scans for open ports on target systems
"""

import socket
import concurrent.futures
from typing import Dict, List, Any
from modules.recon.base_recon import BaseReconModule
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
    
    def scan_port(self, target_ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target_ip, port))
                
                if result == 0:
                    # Try to get service banner
                    try:
                        s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    except:
                        banner = "Could not retrieve banner"
                    
                    return {
                        "port": port,
                        "status": "open",
                        "banner": banner
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
    
    def run(self, target: Target, **kwargs) -> Dict[str, Any]:
        """Execute port scanning"""
        if not self.validate_target(target):
            return {"error": "Invalid target", "success": False}
        
        # Get parameters
        ports = kwargs.get('ports', self.common_ports)
        timeout = kwargs.get('timeout', 1.0)
        max_workers = kwargs.get('max_workers', 10)
        
        # Resolve target IP if not already set
        if not target.ip:
            try:
                # Try multiple resolution methods
                try:
                    target.ip = socket.gethostbyname(target.host)
                except socket.gaierror:
                    # Try with getaddrinfo as fallback
                    addr_info = socket.getaddrinfo(target.host, None)
                    if addr_info:
                        target.ip = addr_info[0][4][0]
                    else:
                        return {"error": f"Could not resolve hostname: {target.host}", "success": False}
            except Exception as e:
                return {"error": f"Resolution failed: {str(e)}", "success": False}
        
        open_ports = []
        
        # Scan ports using thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(self.scan_port, target.ip, port, timeout): port 
                for port in ports
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result["status"] == "open":
                        open_ports.append(result)
                        
                        # Add to target services
                        target.services[result["port"]] = result.get("banner", "unknown")
                except Exception as e:
                    print(f"Port {port} generated an exception: {e}")
        
        # Update target with open ports
        target.ports.extend([port["port"] for port in open_ports])
        
        return {
            "success": True,
            "target_ip": target.ip,
            "ports_scanned": len(ports),
            "open_ports": open_ports
        }