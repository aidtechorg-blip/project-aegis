"""
Base reconnaissance module for Project Aegis
Provides common functionality for all reconnaissance modules
"""

import time
import random
from typing import Dict, List, Any
from aegis.core.framework import BaseModule, Target

class BaseReconModule(BaseModule):
    """Base class for all reconnaissance modules"""
    category = "reconnaissance"
    
    def __init__(self):
        super().__init__()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]
    
    def get_random_user_agent(self) -> str:
        """Return a random user agent"""
        return random.choice(self.user_agents)
    
    def delay_request(self, min_delay: float = 1.0, max_delay: float = 3.0) -> None:
        """Add a random delay between requests to avoid detection"""
        time.sleep(random.uniform(min_delay, max_delay))
    
    def validate_target(self, target: Target) -> bool:
        """Validate that the target is appropriate for reconnaissance"""
        if not target.host:
            return False
        
        # Basic validation - could be expanded
        forbidden_targets = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if target.host.lower() in forbidden_targets:
            return False
            
        return True