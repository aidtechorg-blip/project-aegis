"""
Enhanced OSINT gathering module for Project Aegis
Multiple intelligence sources with advanced correlation
"""

import requests
import json
import dns.resolver
import whois
import re
import socket
from typing import Dict, List, Any
from datetime import datetime
from modules.recon.base_recon import BaseReconModule
from aegis.core.framework import Target

class OSINTModule(BaseReconModule):
    """Enhanced OSINT gathering module with multiple intelligence sources"""
    name = "osint"
    description = "Collect open source intelligence from multiple sources"
    safe = True
    
    def __init__(self):
        super().__init__()
        self.intelligence_sources = {
            'shodan': False,
            'virustotal': False,
            'securitytrails': False,
            'hunterio': False
        }
    
    def query_shodan(self, target: Target, api_key: str) -> Dict[str, Any]:
        """Real Shodan query with comprehensive data"""
        if not api_key:
            return {"shodan_status": "no_api_key"}
        
        try:
            from shodan import Shodan
            api = Shodan(api_key)
            
            # Try to query by IP if the target is an IP, otherwise by domain
            try:
                if target.is_ip:
                    host_info = api.host(target.host)
                else:
                    # Shodan's REST API for domain search
                    results = api.search(f"hostname:{target.host}")
                    host_info = results['matches'][0] if results['matches'] else None
            except Exception as ip_error:
                # Fallback to domain search if IP lookup fails
                try:
                    results = api.search(f"hostname:{target.host}")
                    host_info = results['matches'][0] if results['matches'] else None
                except Exception as domain_error:
                    return {"shodan_error": f"Shodan query failed: {str(domain_error)}"}

            if not host_info:
                return {"shodan_status": "no_data_found"}

            # Parse the rich Shodan data into our format
            shodan_data = {
                "ports": host_info.get('ports', []),
                "services": [],
                "vulnerabilities": host_info.get('vulns', []),
                "geolocation": {
                    "city": host_info.get('city', 'N/A'),
                    "country": host_info.get('country_name', 'N/A')
                },
                "last_update": host_info.get('last_update', 'N/A'),
                "tags": host_info.get('tags', []),
                "domains": host_info.get('domains', []),
                "hostnames": host_info.get('hostnames', []),
                "cves": list(host_info.get('vulns', {}).keys()) if isinstance(host_info.get('vulns'), dict) else host_info.get('vulns', []),
                "org": host_info.get('org', 'N/A'),
                "isp": host_info.get('isp', 'N/A'),
                "asn": host_info.get('asn', 'N/A')
            }

            # Build services list from ports and data
            for port in host_info.get('ports', []):
                service_info = {
                    "port": port,
                    "service": "unknown",
                    "version": "unknown",
                    "info": ""
                }
                
                # Check if there's more specific data for this port
                for item in host_info.get('data', []):
                    if item.get('port') == port:
                        service_info.update({
                            "service": item.get('product', service_info['service']),
                            "version": item.get('version', service_info['version']),
                            "info": item.get('data', service_info['info'])
                        })
                        break
                
                shodan_data["services"].append(service_info)

            return {"shodan_data": shodan_data}
            
        except Exception as e:
            return {"shodan_error": f"Shodan query failed: {str(e)}"}
    
    def query_virustotal(self, target: Target, api_key: str) -> Dict[str, Any]:
        """Query VirusTotal for domain and IP reputation"""
        if not api_key:
            return {"virustotal_status": "no_api_key"}
        
        try:
            # Basic implementation - will need vt-py library for full functionality
            headers = {
                "x-apikey": api_key,
                "User-Agent": self.get_random_user_agent()
            }
            
            url = f"https://www.virustotal.com/api/v3/domains/{target.host}"
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                return {
                    "virustotal_data": {
                        "reputation_score": attributes.get('reputation', 0),
                        "last_analysis_stats": attributes.get('last_analysis_stats', {}),
                        "categories": attributes.get('categories', []),
                        "last_analysis_results": attributes.get('last_analysis_results', {})
                    }
                }
            else:
                return {"virustotal_error": f"API returned status {response.status_code}"}
                
        except Exception as e:
            return {"virustotal_error": f"VirusTotal query failed: {str(e)}"}
    
    def query_whois(self, target: Target) -> Dict[str, Any]:
        """Comprehensive WHOIS lookup"""
        try:
            domain_info = whois.whois(target.host)
            return {
                "whois_data": {
                    "registrar": str(domain_info.registrar),
                    "creation_date": str(domain_info.creation_date),
                    "expiration_date": str(domain_info.expiration_date),
                    "name_servers": list(domain_info.name_servers) if domain_info.name_servers else [],
                    "emails": list(domain_info.emails) if domain_info.emails else [],
                    "status": list(domain_info.status) if domain_info.status else []
                }
            }
        except Exception as e:
            return {"whois_error": f"WHOIS query failed: {str(e)}"}
    
    def query_dns_records(self, target: Target) -> Dict[str, Any]:
        """Comprehensive DNS record enumeration"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        dns_results = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(target.host, record_type)
                dns_results[record_type.lower()] = [str(r) for r in answers]
            except:
                dns_results[record_type.lower()] = []
        
        return {"dns_records": dns_results}
    
    def query_wayback_machine(self, target: Target) -> Dict[str, Any]:
        """Advanced Wayback Machine query with historical analysis"""
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{target.host}/*&output=json&collapse=urlkey&limit=50"
            response = requests.get(url, headers={"User-Agent": self.get_random_user_agent()}, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                historical_data = {
                    "total_snapshots": len(data) - 1 if data else 0,  # Subtract header row
                    "first_capture": data[1][1] if len(data) > 1 else "unknown",
                    "last_capture": data[-1][1] if data and len(data) > 1 else "unknown",
                    "sample_urls": [entry[2] for entry in data[1:6]] if data and len(data) > 1 else []
                }
                return {"wayback_data": historical_data}
            return {"wayback_data": {"total_snapshots": 0}}
        except Exception as e:
            return {"wayback_error": f"Failed to query Wayback Machine: {str(e)}"}
    
    def query_certificate_transparency(self, target: Target) -> Dict[str, Any]:
        """Advanced Certificate Transparency log analysis"""
        try:
            url = f"https://crt.sh/?q=%.{target.host}&output=json"
            response = requests.get(url, headers={"User-Agent": self.get_random_user_agent()}, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                certificates = []
                
                for entry in data[:20]:  # Limit to first 20 entries
                    name = entry.get('name_value', '')
                    if name:
                        for domain in name.split('\n'):
                            if target.host in domain:
                                subdomains.add(domain.strip())
                    
                    certificates.append({
                        "id": entry.get('id'),
                        "issuer": entry.get('issuer_name'),
                        "not_before": entry.get('not_before'),
                        "not_after": entry.get('not_after')
                    })
                
                return {
                    "ct_logs": {
                        "subdomains": list(subdomains),
                        "certificates_found": len(data),
                        "recent_certificates": certificates[:5]
                    }
                }
            return {"ct_logs": {"subdomains": [], "certificates_found": 0}}
        except Exception as e:
            return {"ct_log_error": f"Failed to query certificate transparency logs: {str(e)}"}
    
    def analyze_domain_age(self, creation_date) -> Dict[str, Any]:
        """Analyze domain age and reputation factors"""
        if not creation_date:
            return {"domain_age": "unknown"}
        
        try:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            created = datetime.strptime(str(creation_date).split()[0], '%Y-%m-%d')
            age_days = (datetime.now() - created).days
            
            reputation = "established" if age_days > 365 else "new"
            return {
                "domain_age": {
                    "days": age_days,
                    "years": round(age_days / 365, 1),
                    "reputation": reputation,
                    "creation_date": str(creation_date)
                }
            }
        except:
            return {"domain_age": "unknown"}
    
    def run(self, target: Target, **kwargs) -> Dict[str, Any]:
        """Execute comprehensive OSINT gathering"""
        if not self.validate_target(target):
            return {"error": "Invalid target", "success": False}
        
        results = {}
        
        # Get API keys from config system
        from aegis.core.config import config
        shodan_key = config.get_api_key('shodan') or kwargs.get('shodan_key')
        virustotal_key = config.get_api_key('virustotal') or kwargs.get('virustotal_key')
        
        # Perform comprehensive OSINT queries
        results.update(self.query_whois(target))
        results.update(self.query_dns_records(target))
        results.update(self.query_wayback_machine(target))
        results.update(self.query_certificate_transparency(target))
        
        # Query external services if API keys provided
        if shodan_key:
            results.update(self.query_shodan(target, shodan_key))
        else:
            results["shodan_status"] = "no_api_key"
        
        if virustotal_key:
            results.update(self.query_virustotal(target, virustotal_key))
        else:
            results["virustotal_status"] = "no_api_key"
        
        # Analyze domain age from WHOIS data
        if 'whois_data' in results and results['whois_data']:
            creation_date = results['whois_data'].get('creation_date')
            results.update(self.analyze_domain_age(creation_date))
        
        # Threat intelligence assessment
        threat_level = self.assess_threat_level(results)
        results["threat_assessment"] = threat_level
        
        # Update target with OSINT findings
        target.osint_data.update(results)
        
        return {
            "success": True,
            "results": results,
            "summary": self.generate_summary(results)
        }
    
    def assess_threat_level(self, results: Dict) -> Dict[str, Any]:
        """Assess threat level based on OSINT findings"""
        score = 0
        warnings = []
        
        # Basic scoring logic
        if results.get('shodan_data', {}).get('vulnerabilities'):
            score += 30
            warnings.append("Vulnerabilities detected in Shodan")
        
        vt_data = results.get('virustotal_data', {})
        if vt_data.get('last_analysis_stats', {}).get('malicious', 0) > 0:
            score += 40
            warnings.append("Malicious detections in VirusTotal")
        
        if vt_data.get('last_analysis_stats', {}).get('suspicious', 0) > 0:
            score += 20
            warnings.append("Suspicious detections in VirusTotal")
        
        # Determine threat level
        if score >= 50:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"
        
        return {
            "threat_score": score,
            "threat_level": level,
            "warnings": warnings,
            "recommendations": self.generate_recommendations(level)
        }
    
    def generate_recommendations(self, threat_level: str) -> List[str]:
        """Generate security recommendations based on threat level"""
        if threat_level == "HIGH":
            return [
                "Immediate security assessment recommended",
                "Consider implementing WAF and IDS/IPS",
                "Monitor for suspicious activity",
                "Conduct penetration testing"
            ]
        elif threat_level == "MEDIUM":
            return [
                "Security review recommended",
                "Ensure regular vulnerability scanning",
                "Keep systems updated and patched"
            ]
        else:
            return [
                "Maintain current security practices",
                "Continue regular monitoring",
                "Keep systems updated"
            ]
    
    def generate_summary(self, results: Dict) -> Dict[str, Any]:
        """Generate executive summary of OSINT findings"""
        return {
            "domain_age": results.get('domain_age', {}).get('domain_age', {}),
            "threat_level": results.get('threat_assessment', {}).get('threat_level', 'UNKNOWN'),
            "open_ports": len(results.get('shodan_data', {}).get('ports', [])),
            "subdomains_found": len(results.get('ct_logs', {}).get('subdomains', [])),
            "dns_records": sum(len(v) for k, v in results.get('dns_records', {}).items() if k != 'dns_records')
        }