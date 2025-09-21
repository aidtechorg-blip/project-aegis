"""
Aegis Core Framework - Module loader and data management system
"""

import importlib
import inspect
import json
import os
import time
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('aegis_core')

@dataclass
class Target:
    """Representation of a target system"""
    host: str
    ip: Optional[str] = None
    ports: List[int] = None
    services: Dict[int, str] = None
    os: Optional[str] = None
    vulnerabilities: List[Dict] = None
    subdomains: List[str] = None
    osint_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.services is None:
            self.services = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.subdomains is None:
            self.subdomains = []
        if self.osint_data is None:
            self.osint_data = {}

@dataclass
class ScanResult:
    """Container for scan results"""
    target: Target
    module: str
    data: Dict[str, Any]
    timestamp: float
    success: bool
    error: Optional[str] = None

class BaseModule:
    """Base class that all Aegis modules should inherit from"""
    name = "base_module"
    description = "Base module for all Aegis modules"
    category = "utility"
    safe = True  # Whether this module is safe to run in safe mode
    
    def run(self, target: Target, **kwargs) -> Dict[str, Any]:
        """Main method that modules should override"""
        raise NotImplementedError("Modules must implement the run method")

class AegisFramework:
    """Core framework class for module management and data flow"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.modules = {}
        self.results = []
        self.config = self.load_config(config_path)
        self.current_target = None
        
    def load_config(self, config_path: Optional[str]) -> Dict:
        """Load framework configuration"""
        default_config = {
            "module_paths": ["modules"],
            "max_threads": 10,
            "default_timeout": 30,
            "output_format": "json",
            "safe_mode": True  # Prevents potentially dangerous operations
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                
        return default_config
    
    def discover_modules(self) -> Dict[str, Any]:
        """Discover and load available modules - Manual registration"""
        self.modules = {}
    
        # Manually register all known modules
        modules_to_register = [
            {
                "name": "subdomain_enum",
                "class": None,  # We'll import this dynamically
                "import_path": "aegis.modules.recon.subdomain_enum.subdomain_enum.SubdomainEnumModule"
             },
            {
                "name": "osint", 
                "class": None,
                "import_path": "aegis.modules.recon.osint.osint.OSINTModule"
            },
            {
                "name": "port_scan",
                "class": None, 
                "import_path": "aegis.modules.recon.port_scan.port_scan.PortScanModule"
            }
        ]
    
        for module_info in modules_to_register:
            try:
                # Dynamically import the module class
                module_path, class_name = module_info["import_path"].rsplit('.', 1)
                module = importlib.import_module(module_path)
                module_class = getattr(module, class_name)
            
                # Create instance and register
                module_instance = module_class()
                self.modules[module_info["name"]] = {
                    "class": module_class,
                    "description": getattr(module_class, "description", ""),
                    "category": getattr(module_class, "category", "unknown"),
                    "safe": getattr(module_class, "safe", True)
                }
                logger.info(f"Loaded module: {module_info['name']}")
            
            except ImportError as e:
                logger.error(f"Failed to import module {module_info['name']}: {e}")
            except Exception as e:
                logger.error(f"Error loading module {module_info['name']}: {e}")
    
        return self.modules
    
    def export_results(self, format: str = None) -> str:
        """Export results in specified format"""
        export_format = format or self.config.get("output_format", "json")
        
        if export_format == "json":
            return json.dumps(self.results, indent=2, default=str)
        else:
            # Simple text format
            output = []
            for result in self.results:
                output.append(f"Module: {result['module']}")
                output.append(f"Success: {result['success']}")
                if 'error' in result:
                    output.append(f"Error: {result['error']}")
                output.append("Data:")
                for key, value in result.get('data', {}).items():
                    if isinstance(value, list):
                        output.append(f"  {key}:")
                        for item in value:
                            output.append(f"    • {item}")
                    else:
                        output.append(f"  {key}: {value}")
                output.append("─" * 40)
            return "\n".join(output)