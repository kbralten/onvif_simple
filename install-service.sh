#!/bin/bash
#
# ONVIF Camera Emulator Service Installer
# Installs or removes the ONVIF camera emulator as a systemd service
#

set -e

# Configuration
SERVICE_NAME="onvif-camera"
SERVICE_USER="onvif"
INSTALL_DIR="/opt/onvif-camera"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_FILE="/etc/default/${SERVICE_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Create service user
create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        print_status "Creating service user '$SERVICE_USER'..."
        useradd --system --no-create-home --shell /bin/false --group video "$SERVICE_USER"
        usermod -a -G video "$SERVICE_USER"
    else
        print_status "Service user '$SERVICE_USER' already exists"
    fi
}

# Install the service
install_service() {
    print_status "Installing ONVIF Camera Emulator as systemd service..."
    
    # Check if we're in the right directory
    if [[ ! -f "onvif_server.py" ]] || [[ ! -f "rtsp_server_gst.py" ]] || [[ ! -f "start_camera.sh" ]]; then
        print_error "Required files not found. Please run this script from the ONVIF project directory."
        exit 1
    fi
    
    # Create service user
    create_user
    
    # Create installation directory
    print_status "Creating installation directory..."
    mkdir -p "$INSTALL_DIR"
    
    # Copy files
    print_status "Copying project files..."
    cp -r * "$INSTALL_DIR/"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/start_camera.sh"
    chmod +x "$INSTALL_DIR/start_camera_service.sh"
    chmod +x "$INSTALL_DIR"/*.py
    
    # Install Python dependencies
    print_status "Installing Python dependencies..."

    # Choose dependency installation method: pip or apt
    DEP_METHOD="${DEP_METHOD:-pip}"  # Default to pip, can override with DEP_METHOD=apt

    if [[ "$DEP_METHOD" == "apt" ]]; then
        print_status "Installing Python dependencies via apt..."
        if [[ -f "$INSTALL_DIR/requirements.txt" ]]; then
            # Extract package names from requirements.txt and try to install python3-<package>
            while IFS= read -r pkg; do
                pkg_name=$(echo "$pkg" | cut -d'=' -f1 | tr '[:upper:]' '[:lower:]' | tr '_' '-')
                apt_pkg="python3-${pkg_name}"
                print_status "Attempting to install $apt_pkg"
                apt-get install -y "$apt_pkg" || print_warning "Could not install $apt_pkg via apt"
            done < "$INSTALL_DIR/requirements.txt"
        fi
    else
        print_status "Installing Python dependencies via pip..."
        if [[ -f "$INSTALL_DIR/requirements.txt" ]]; then
            pip3 install -r "$INSTALL_DIR/requirements.txt"
        fi
    fi
    
    # Create configuration file
    print_status "Creating configuration file..."
    cat > "$CONFIG_FILE" << 'EOF'
# ONVIF Camera Emulator Configuration
# Edit these values to customize your camera setup

# Video device (usually /dev/video0, /dev/video1, etc.)
VIDEO_DEVICE=/dev/video1

# Network configuration
RTSP_PORT=8554
ONVIF_PORT=8000
LOCAL_IP=

# Video settings
VIDEO_WIDTH=640
VIDEO_HEIGHT=480
VIDEO_FRAMERATE=25

# Additional options
# PYTHONPATH=/opt/onvif-camera
EOF
    
    # Create systemd service file
    print_status "Creating systemd service file..."
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=ONVIF Camera Emulator
Documentation=https://github.com/your-username/onvif-camera-emulator
After=network.target
Wants=network.target

[Service]
Type=exec
User=$SERVICE_USER
Group=video
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONFIG_FILE
ExecStart=$INSTALL_DIR/start_camera_service.sh
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=30
TimeoutStartSec=30

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR /run /tmp /var/log
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Device access
DevicePolicy=closed
DeviceAllow=char-video4linux

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    print_status "Enabling systemd service..."
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_status "Installation completed successfully!"
    echo
    print_status "Configuration file: $CONFIG_FILE"
    print_status "Service file: $SERVICE_FILE"
    print_status "Installation directory: $INSTALL_DIR"
    echo
    print_status "To configure your camera, edit: $CONFIG_FILE"
    print_status "To start the service: sudo systemctl start $SERVICE_NAME"
    print_status "To check status: sudo systemctl status $SERVICE_NAME"
    print_status "To view logs: sudo journalctl -u $SERVICE_NAME -f"
}

# Remove the service
remove_service() {
    print_status "Removing ONVIF Camera Emulator service..."
    
    # Stop and disable service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_status "Disabling service..."
        systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove service file
    if [[ -f "$SERVICE_FILE" ]]; then
        print_status "Removing service file..."
        rm -f "$SERVICE_FILE"
    fi
    
    # Remove configuration file
    if [[ -f "$CONFIG_FILE" ]]; then
        print_warning "Keeping configuration file: $CONFIG_FILE"
        print_warning "Remove manually if desired: sudo rm $CONFIG_FILE"
    fi
    
    # Remove installation directory
    if [[ -d "$INSTALL_DIR" ]]; then
        read -p "Remove installation directory $INSTALL_DIR? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Removing installation directory..."
            rm -rf "$INSTALL_DIR"
        else
            print_warning "Keeping installation directory: $INSTALL_DIR"
        fi
    fi
    
    # Remove service user
    if id "$SERVICE_USER" &>/dev/null; then
        read -p "Remove service user '$SERVICE_USER'? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Removing service user..."
            userdel "$SERVICE_USER" 2>/dev/null || true
        else
            print_warning "Keeping service user: $SERVICE_USER"
        fi
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
    print_status "Service removal completed!"
}

# Show service status
show_status() {
    echo "=== ONVIF Camera Emulator Service Status ==="
    echo
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service is running"
    else
        print_warning "Service is not running"
    fi
    
    echo
    echo "Service status:"
    systemctl status "$SERVICE_NAME" --no-pager -l
    
    echo
    echo "Recent logs:"
    journalctl -u "$SERVICE_NAME" --no-pager -l -n 20
}

# Show configuration
show_config() {
    echo "=== ONVIF Camera Emulator Configuration ==="
    echo
    
    if [[ -f "$CONFIG_FILE" ]]; then
        print_status "Configuration file: $CONFIG_FILE"
        echo
        cat "$CONFIG_FILE"
    else
        print_warning "Configuration file not found: $CONFIG_FILE"
    fi
    
    echo
    print_status "Available video devices:"
    ls -la /dev/video* 2>/dev/null || echo "No video devices found"
}

# Show usage
show_usage() {
    echo "ONVIF Camera Emulator Service Installer"
    echo
    echo "Usage: $0 {install|remove|status|config|logs}"
    echo
    echo "Commands:"
    echo "  install  - Install as systemd service"
    echo "  remove   - Remove systemd service"
    echo "  status   - Show service status"
    echo "  config   - Show configuration"
    echo "  logs     - Show service logs"
    echo "  start    - Start the service"
    echo "  stop     - Stop the service"
    echo "  restart  - Restart the service"
    echo
    echo "Examples:"
    echo "  sudo $0 install    # Install the service"
    echo "  sudo $0 status     # Check if running"
    echo "  sudo $0 logs       # View recent logs"
}

# Main script logic
case "${1:-}" in
    install)
        check_root
        install_service
        ;;
    remove|uninstall)
        check_root
        remove_service
        ;;
    status)
        show_status
        ;;
    config)
        show_config
        ;;
    logs)
        journalctl -u "$SERVICE_NAME" -f
        ;;
    start)
        check_root
        systemctl start "$SERVICE_NAME"
        print_status "Service started"
        ;;
    stop)
        check_root
        systemctl stop "$SERVICE_NAME"
        print_status "Service stopped"
        ;;
    restart)
        check_root
        systemctl restart "$SERVICE_NAME"
        print_status "Service restarted"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
