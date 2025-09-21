"""
Tests for Aegis framework core functionality
"""

import pytest
from src.aegis.core.framework import AegisFramework, Target, BaseModule

def test_target_creation():
    """Test creating a target"""
    target = Target(host="example.com", ip="93.184.216.34")
    assert target.host == "example.com"
    assert target.ip == "93.184.216.34"
    assert target.ports == []
    assert target.services == {}
    assert target.vulnerabilities == []

def test_framework_initialization():
    """Test framework initialization"""
    framework = AegisFramework()
    assert framework.modules == {}
    assert framework.results == []
    assert framework.current_target is None
    assert framework.config is not None

def test_base_module():
    """Test base module interface"""
    class TestModule(BaseModule):
        name = "test_module"
        description = "Test module"
        
        def run(self, target, **kwargs):
            return {"success": True, "data": "test"}
    
    module = TestModule()
    assert module.name == "test_module"
    assert module.description == "Test module"
    assert module.safe is True
    
    target = Target(host="test.com")
    result = module.run(target)
    assert result["success"] is True
    assert result["data"] == "test"

def test_module_discovery():
    """Test module discovery functionality"""
    framework = AegisFramework()
    modules = framework.discover_modules()
    
    # Should discover our recon modules
    assert isinstance(modules, dict)
    # At least our three main modules should be found
    assert len(modules) >= 3

def test_target_validation():
    """Test target validation"""
    framework = AegisFramework()
    
    # Valid target
    valid_target = Target(host="example.com")
    framework.set_target(valid_target)
    assert framework.current_target == valid_target
    
    # Invalid target (should not raise error but framework should handle it)
    invalid_target = Target(host="localhost")
    framework.set_target(invalid_target)
    assert framework.current_target == invalid_target

if __name__ == "__main__":
    pytest.main([__file__, "-v"])