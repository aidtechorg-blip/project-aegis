"""
Configuration management for Project Aegis
Handles API keys and settings
"""

import json
import os
from pathlib import Path
from typing import Dict, Any

class Config:
    """Manage Aegis configuration and API keys"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".aegis"
        self.config_file = self.config_dir / "config.json"
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def save_config(self):
        """Save configuration to file"""
        self.config_dir.mkdir(exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get_api_key(self, service: str) -> str:
        """Get API key for a service"""
        return self.config.get('api_keys', {}).get(service, '')
    
    def set_api_key(self, service: str, key: str):
        """Set API key for a service"""
        if 'api_keys' not in self.config:
            self.config['api_keys'] = {}
        self.config['api_keys'][service] = key
        self.save_config()
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a configuration setting"""
        return self.config.get('settings', {}).get(key, default)
    
    def list_api_keys(self) -> Dict[str, str]:
        """List all configured API keys"""
        return self.config.get('api_keys', {})

# Global config instance
config = Config()