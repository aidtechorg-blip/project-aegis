class AegisFramework:
    """Core framework class for module management and data flow"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.modules = {}
        self.results = []
        self.config = self.load_config(config_path)
        self.current_target = None
        
    def set_target(self, target: Target):
        """Set the current target for operations"""
        self.current_target = target
        logger.info(f"Target set to: {target.host}")
    
    def load_config(self, config_path: Optional[str]) -> Dict:
        """Load framework configuration"""
        default_config = {
            "module_paths": ["src/aegis/modules"],
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
                "class": None,
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
    
    def run_module(self, module_name: str, **kwargs) -> Dict[str, Any]:
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