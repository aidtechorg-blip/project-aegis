#!/bin/bash
# Project Aegis Installation Script

echo "Installing Project Aegis..."
echo "============================"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ $(echo "$PYTHON_VERSION < 3.8" | bc -l) -eq 1 ]]; then
    echo "Error: Python 3.8 or higher is required. Found Python $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv aegis-env

# Activate virtual environment
echo "[*] Activating virtual environment..."
source aegis-env/bin/activate

# Install the package using modern packaging
echo "[*] Installing Project Aegis..."
pip install --upgrade pip
pip install .

# Make main script executable (for direct execution)
chmod +x aegis.py

echo ""
echo "✅ Installation complete!"
echo ""
echo "To use Project Aegis:"
echo "  source aegis-env/bin/activate"
echo "  aegis --help"
echo ""
echo "Or run directly: ./aegis.py --help"
echo ""
echo "For ethical use guidelines, see docs/ethical_charter.md"