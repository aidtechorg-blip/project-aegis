"""
OSINT gathering module for Project Aegis
Collects open source intelligence about targets
"""

import requests
import json
from typing import Dict, List, Any
from aegis.modules.base_recon import BaseReconModule
from aegis.core.framework import Target

class OSINTModule(BaseReconModule):
    """OSINT gathering module"""
    name = "osint"
    description = "Collect open source intelligence about targets"
    safe = True
    
    def __init__(self):
        super().__init__()
    
    def query_shodan(self, target: Target, api_key: str) -> Dict[str, Any]:
        """Query Shodan for information about the target"""
        if not api_key:
            return {"shodan_info": "No API key provided"}
        
        try:
            # This would be implemented with actual Shodan API calls
            # For now, return placeholder data
            return {
                "shodan_data": {
                    "ports": [80, 443],
                    "services": ["http", "https"],
                    "vulnerabilities": [],
                    "geolocation": "Unknown"
                }
            }
        except Exception as e:
            return {"shodan_error": f"Shodan query failed: {str(e)}"}
    
    def query_wayback(self, target: Target) -> Dict[str, Any]:
        """Query Wayback Machine for historical data"""
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{target.host}/*&output=json&collapse=urlkey"
            response = requests.get(url, headers={"User-Agent": self.get_random_user_agent()}, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {"wayback_results": len(data) if data else 0}
            return {"wayback_results": 0}
        except:
            return {"wayback_error": "Failed to query Wayback Machine"}
    
    def query_certificate_transparency(self, target: Target) -> Dict[str, Any]:
        """Query certificate transparency logs for subdomains"""
        try:
            url = f"https://crt.sh/?q=%.{target.host}&output=json"
            response = requests.get(url, headers={"User-Agent": self.get_random_user_agent()}, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle multiple domains in one entry
                        for domain in name.split('\n'):
                            if target.host in domain:
                                subdomains.add(domain.strip())
                return {"ct_log_subdomains": list(subdomains)}
            return {"ct_log_subdomains": []}
        except:
            return {"ct_log_error": "Failed to query certificate transparency logs"}
    
    def search_public_records(self, target: Target) -> Dict[str, Any]:
        """Search for public records and information"""
        # Placeholder for various OSINT sources
        return {
            "public_records": [
                "WHOIS data available",
                "DNS records accessible",
                "Social media mentions possible"
            ]
        }
    
    def run(self, target: Target, **kwargs) -> Dict[str, Any]:
        """Execute OSINT gathering"""
        if not self.validate_target(target):
            return {"error": "Invalid target", "success": False}
        
        results = {}
        
        # Perform various OSINT queries
        results.update(self.query_wayback(target))
        results.update(self.query_certificate_transparency(target))
        results.update(self.search_public_records(target))
        
        # Query Shodan if API key is provided
        shodan_key = kwargs.get('shodan_key', None)
        if shodan_key:
            results.update(self.query_shodan(target, shodan_key))
        else:
            results["shodan_info"] = "No API key provided"
        
        # Update target with OSINT findings
        target.osint_data.update(results)
        
        return {
            "success": True,
            "results": results
        }