"""
Subdomain enumeration module for Project Aegis
Uses multiple techniques to discover subdomains
"""

import asyncio
import aiohttp
import dns.resolver
from typing import Dict, List, Any
from modules.recon.base_recon import BaseReconModule
from aegis.core.framework import Target

class SubdomainEnumModule(BaseReconModule):
    """Subdomain enumeration module"""
    name = "subdomain_enum"
    description = "Discover subdomains using multiple techniques"
    safe = True
    
    def __init__(self):
        super().__init__()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video'
        ]
    
    async def check_subdomain_async(self, session: aiohttp.ClientSession, subdomain: str, base_domain: str) -> str:
        """Asynchronously check if a subdomain exists"""
        full_domain = f"{subdomain}.{base_domain}"
        try:
            async with session.get(f"http://{full_domain}", timeout=5, ssl=False) as response:
                if response.status < 400:
                    return full_domain
        except aiohttp.ClientConnectorError:
            # Connection error, try HTTPS
            pass
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None
        
        try:
            async with session.get(f"https://{full_domain}", timeout=5, ssl=False) as response:
                if response.status < 400:
                    return full_domain
        except (aiohttp.ClientConnectorError, asyncio.TimeoutError, Exception):
            return None
        
        return None
    
    async def check_subdomains_async(self, base_domain: str, subdomains: List[str]) -> List[str]:
        """Check multiple subdomains asynchronously"""
        connector = aiohttp.TCPConnector(limit=10)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for subdomain in subdomains:
                tasks.append(self.check_subdomain_async(session, subdomain, base_domain))
                self.delay_request(0.1, 0.3)  # Small delay between task creation
            
            results = await asyncio.gather(*tasks)
            return [result for result in results if result is not None]
    
    def check_subdomain_dns(self, subdomain: str, base_domain: str) -> str:
        """Check subdomain using DNS resolution"""
        full_domain = f"{subdomain}.{base_domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            return full_domain
        except:
            return None
    
    def check_subdomains_dns(self, base_domain: str, subdomains: List[str]) -> List[str]:
        """Check multiple subdomains using DNS"""
        found_subdomains = []
        for subdomain in subdomains:
            result = self.check_subdomain_dns(subdomain, base_domain)
            if result:
                found_subdomains.append(result)
            self.delay_request(0.1, 0.3)
        return found_subdomains
    
    def run(self, target: Target, **kwargs) -> Dict[str, Any]:
        """Execute subdomain enumeration"""
        if not self.validate_target(target):
            return {"error": "Invalid target", "success": False}
        
        # Get parameters
        wordlist = kwargs.get('wordlist', None)
        method = kwargs.get('method', 'async')  # 'async' or 'dns'
        max_workers = kwargs.get('max_workers', 10)
        
        # Use provided wordlist or default
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    subdomains_to_check = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                subdomains_to_check = self.common_subdomains
        else:
            subdomains_to_check = self.common_subdomains
        
        found_subdomains = []
        
        # Choose enumeration method
        if method == 'async':
            # Asynchronous HTTP checking
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            found_subdomains = loop.run_until_complete(
                self.check_subdomains_async(target.host, subdomains_to_check)
            )
        elif method == 'dns':
            # DNS resolution
            found_subdomains = self.check_subdomains_dns(target.host, subdomains_to_check)
        else:
            return {"error": "Invalid method", "success": False}
        
        # Update target with found subdomains
        target.subdomains.extend(found_subdomains)
        
        return {
            "success": True,
            "subdomains_found": found_subdomains,
            "subdomains_checked": len(subdomains_to_check),
            "method_used": method
        }