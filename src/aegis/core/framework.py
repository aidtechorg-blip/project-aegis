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
        """Discover and load available modules"""
        module_paths = self.config.get("module_paths", ["modules"])
        self.modules = {}
        
        for base_path in module_paths:
            full_module_path = os.path.join(os.path.dirname(__file__), '..', '..', base_path)
            if not os.path.exists(full_module_path):
                logger.warning(f"Module path {full_module_path} does not exist")
                continue
                
            for module_file in Path(full_module_path).rglob("*.py"):
                if module_file.name == "__init__.py":
                    continue
                    
                module_name = module_file.stem
                module_relative_path = str(module_file.relative_to(full_module_path).parent).replace(os.sep, '.')
                
                try:
                    # Import module using proper package structure
                    full_module_import = f"modules.{module_relative_path}.{module_name}"
                    if module_relative_path == '.':
                        full_module_import = f"modules.{module_name}"
                    
                    module = importlib.import_module(full_module_import)
                    
                    # Check if it's a valid Aegis module
                    if hasattr(module, "Module") and inspect.isclass(module.Module):
                        module_class = module.Module
                        if hasattr(module_class, "name") and hasattr(module_class, "run"):
                            self.modules[module_class.name] = {
                                "class": module_class,
                                "description": getattr(module_class, "description", ""),
                                "category": getattr(module_class, "category", "unknown"),
                                "safe": getattr(module_class, "safe", True)
                            }
                            logger.info(f"Loaded module: {module_class.name}")
                except ImportError as e:
                    logger.error(f"Failed to import module {module_name}: {e}")
                except Exception as e:
                    logger.error(f"Error loading module {module_name}: {e}")
                    
        return self.modules
    
    def set_target(self, target: Target):
        """Set the current target for operations"""
        self.current_target = target
        logger.info(f"Target set to: {target.host}")
    
    def run_module(self, module_name: str, **kwargs) -> ScanResult:
        """Execute a specific module"""
        if module_name not in self.modules:
            return {
                "success": False,
                "error": f"Module {module_name} not found",
                "module": module_name
            }
            
        module_info = self.modules[module_name]
        
        # Safety check
        if self.config.get("safe_mode", True) and not module_info.get("safe", True):
            return {
                "success": False,
                "error": f"Module {module_name} is not allowed in safe mode",
                "module": module_name
            }
        
        try:
            module_instance = module_info["class"]()
            result_data = module_instance.run(self.current_target, **kwargs)
            
            result = {
                "success": True,
                "module": module_name,
                "data": result_data,
                "timestamp": time.time()
            }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Error running module {module_name}: {e}")
            result = {
                "success": False,
                "error": str(e),
                "module": module_name,
                "timestamp": time.time()
            }
            self.results.append(result)
            return result
    
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