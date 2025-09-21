#!/usr/bin/env python3
"""
Project Aegis Debug Script
Checks for common issues and validates the project structure
"""

import os
import sys
import importlib
import subprocess
from pathlib import Path

def check_project_structure():
    """Check if all required files and directories exist"""
    print("Checking project structure...")
    
    required_files = [
        "pyproject.toml",
        "requirements.txt",
        "README.md",
        "LICENSE",
        ".gitignore",
        "src/aegis/__init__.py",
        "src/aegis/core/__init__.py",
        "src/aegis/core/framework.py",
        "src/aegis/modules/__init__.py",
        "src/aegis/modules/base_recon.py",
        "src/aegis/modules/recon/__init__.py",
        "src/aegis/modules/recon/subdomain_enum/__init__.py",
        "src/aegis/modules/recon/subdomain_enum/subdomain_enum.py",
        "src/aegis/modules/recon/osint/__init__.py",
        "src/aegis/modules/recon/osint/osint.py",
        "src/aegis/modules/recon/port_scan/__init__.py",
        "src/aegis/modules/recon/port_scan/port_scan.py",
        "src/aegis/aegis_cli.py",
        "tests/__init__.py",
        "tests/test_framework.py",
        "tests/test_recon.py",
        "tests/test_basic.py",
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print("❌ Missing files:")
        for file in missing_files:
            print(f"  - {file}")
        return False
    else:
        print("✅ All required files present")
        return True

def check_imports():
    """Test if all modules can be imported successfully"""
    print("\nTesting imports...")
    
    # Add src to Python path
    src_path = os.path.join(os.path.dirname(__file__), 'src')
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    
    modules_to_test = [
        "aegis.core.framework",
        "aegis.modules.recon.subdomain_enum.subdomain_enum",
        "aegis.modules.recon.osint.osint", 
        "aegis.modules.recon.port_scan.port_scan",
        "aegis.aegis_cli"
    ]
    
    failed_imports = []
    for module_name in modules_to_test:
        try:
            importlib.import_module(module_name)
            print(f"✅ {module_name}")
        except ImportError as e:
            print(f"❌ {module_name}: {e}")
            failed_imports.append(module_name)
    
    return len(failed_imports) == 0

def check_pyproject_toml():
    """Validate pyproject.toml syntax"""
    print("\nChecking pyproject.toml...")
    
    try:
        import tomllib
        with open('pyproject.toml', 'rb') as f:
            tomllib.load(f)
        print("✅ pyproject.toml syntax is valid")
        return True
    except Exception as e:
        print(f"❌ pyproject.toml error: {e}")
        return False

def check_entry_point():
    """Test if the entry point works"""
    print("\nTesting entry point...")
    
    try:
        # Test the entry point directly
        from aegis.aegis_cli import main
        print("✅ Entry point import successful")
        return True
    except Exception as e:
        print(f"❌ Entry point error: {e}")
        return False

def run_basic_tests():
    """Run basic functionality tests"""
    print("\nRunning basic tests...")
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            "tests/test_basic.py", "-v"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Basic tests passed")
            return True
        else:
            print(f"❌ Basic tests failed: {result.stdout}")
            return False
    except Exception as e:
        print(f"❌ Test execution error: {e}")
        return False

def main():
    """Run all debug checks"""
    print("Project Aegis Debug Utility")
    print("=" * 50)
    
    checks = [
        check_project_structure,
        check_pyproject_toml,
        check_imports,
        check_entry_point,
        run_basic_tests
    ]
    
    passed = 0
    total = len(checks)
    
    for check in checks:
        try:
            if check():
                passed += 1
        except Exception as e:
            print(f"❌ Check failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Debug Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("🎉 Project is ready to use!")
        print("\nNext steps:")
        print("1. Run: aegis --help")
        print("2. Test: aegis test --quick")
        print("3. Try: aegis recon example.com --subdomains")
    else:
        print("⚠️  Some issues need to be fixed")
        
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)