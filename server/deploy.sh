#!/bin/bash
# ICMP UDC2 Server Deployment Script

set -e

INSTALL_DIR="/opt/icmp-udc2-server"
SERVICE_NAME="icmp-udc2-server"
USER="root"

echo "ICMP UDC2 Server Deployment"
echo "=================================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)" 
   exit 1
fi

# Check Python version
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)" 2>/dev/null; then
    echo "Error: Python 3.7 or higher is required"
    exit 1
fi

echo "✓ Python version check passed"

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy files
echo "Copying server files..."
cp icmp_udc2_server.py "$INSTALL_DIR/"
cp config.json "$INSTALL_DIR/"
cp README.md "$INSTALL_DIR/"

# Set permissions
echo "Setting permissions..."
chown -R $USER:$USER "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/icmp_udc2_server.py"

# Install systemd service (if systemd is available)
if command -v systemctl >/dev/null 2>&1; then
    echo "Installing systemd service..."
    cp icmp-udc2-server.service /etc/systemd/system/
    systemctl daemon-reload
    
    echo "Service installed. To start the service:"
    echo "  sudo systemctl start $SERVICE_NAME"
    echo "  sudo systemctl enable $SERVICE_NAME  # To start on boot"
    echo ""
    echo "To check service status:"
    echo "  sudo systemctl status $SERVICE_NAME"
    echo ""
    echo "To view logs:"
    echo "  sudo journalctl -u $SERVICE_NAME -f"
else
    echo "Systemd not available. Manual startup required."
fi

echo ""
echo "Installation complete!"
echo ""
echo "Configuration file: $INSTALL_DIR/config.json"
echo "Server executable: $INSTALL_DIR/icmp_udc2_server.py"
echo ""
echo "To start manually:"
echo "  cd $INSTALL_DIR"
echo "  sudo python3 icmp_udc2_server.py --config config.json"
echo ""
echo "To generate a custom config:"
echo "  python3 icmp_udc2_server.py --generate-config my_config.json"
echo ""
echo "For more information, see: $INSTALL_DIR/README.md"
