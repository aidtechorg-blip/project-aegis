"""
Basic functionality tests for Project Aegis
"""

import sys
import os
import subprocess

def test_python_version():
    """Test that Python version is sufficient"""
    version = sys.version_info
    assert version.major == 3
    assert version.minor >= 8
    print("✓ Python version check passed")

def test_imports():
    """Test that all required modules can be imported"""
    try:
        from src.aegis.core.framework import AegisFramework, Target
        from modules.recon.subdomain_enum.subdomain_enum import SubdomainEnumModule
        from modules.recon.osint.osint import OSINTModule
        from modules.recon.port_scan.port_scan import PortScanModule
        print("✓ All imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_cli_help():
    """Test that CLI help works"""
    try:
        result = subprocess.run([
            sys.executable, "aegis.py", "--help"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and "usage" in result.stdout.lower():
            print("✓ CLI help command works")
            return True
        else:
            print("✗ CLI help failed")
            return False
    except subprocess.TimeoutExpired:
        print("✗ CLI help timed out")
        return False
    except Exception as e:
        print(f"✗ CLI help error: {e}")
        return False

def test_info_command():
    """Test that info command works"""
    try:
        result = subprocess.run([
            sys.executable, "aegis.py", "info"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and "project aegis" in result.stdout.lower():
            print("✓ Info command works")
            return True
        else:
            print("✗ Info command failed")
            return False
    except subprocess.TimeoutExpired:
        print("✗ Info command timed out")
        return False
    except Exception as e:
        print(f"✗ Info command error: {e}")
        return False

def run_all_tests():
    """Run all basic tests"""
    print("Running basic functionality tests...")
    print("=" * 50)
    
    tests = [
        test_python_version,
        test_imports,
        test_cli_help,
        test_info_command
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("✓ All basic tests passed!")
        return True
    else:
        print("✗ Some tests failed")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)