# ONVIF Camera Emulator

Turn any USB camera into an ONVIF-compatible IP camera. This project creates an ONVIF device server with RTSP streaming using GStreamer for your USB video device.

## Quick Start

1. **Install dependencies:** (Select one install option)
   - With pip
      ```bash
      #update
      sudo apt update
      #install dependencies
      sudo apt install python3 python3-pip python3-venv gstreamer1.0-* gir1.2-gstreamer-1.0 gir1.2-gst-rtsp-server-1.0 netcat-traditional
      #setup a python virtual environment
      python3 -m venv .venv
      source .venv/bin/activate
      pip install -r requirements.txt
      ```
   - or with apt packages
      ```bash
      #update
      sudo apt update
      #install dependencies and python requirements
      sudo apt install python3 python3-pip python3-venv gstreamer1.0-* gir1.2-gstreamer-1.0 gir1.2-gst-rtsp-server-1.0 netcat-traditional
      sudo apt install python3-gi python3-gi-cairo python3-aiohttp python3-netifaces
      ```

2. **Install ustreamer if desired**
   ```bash
   #install ustreamer
   sudo apt install ustreamer
   ```

2. **Run the camera emulator:**
   ```bash
   ./start_camera.sh
   ```

Your USB camera is now available as an ONVIF device!

## Configuration
Customize the setup using environment variables:

```bash
# Basic configuration
VIDEO_DEVICE=/dev/video0 \
RTSP_PORT=8554 \
ONVIF_PORT=8000 \
LOCAL_IP=192.168.1.100 \
./start_camera.sh
```

### Available Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_DEVICE` | `/dev/video1` | USB camera device path |
| `VIDEO_SOURCE` | `v4l2` | Video source: `v4l2` (direct) or `ustreamer` (HTTP MJPEG) |
| `RTSP_PORT` | `8554` | RTSP streaming port |
| `ONVIF_PORT` | `8000` | ONVIF web service port |
| `LOCAL_IP` | _as detected_ | IP address for ONVIF responses |
| `VIDEO_WIDTH` | `640` | Video stream width |
| `VIDEO_HEIGHT` | `480` | Video stream height |
| `VIDEO_FRAMERATE` | `25` | Video stream frame rate |
| `USTREAMER_HOST` | `127.0.0.1` | ustreamer host (when using ustreamer source) |
| `USTREAMER_PORT` | `8080` | ustreamer port (when using ustreamer source) |
| `CAMERA_NAME` | _(system hostname)_ | Hostname reported by ONVIF GetHostname response. If set, overrides the system hostname. |

### Video Source Options

**V4L2 Direct Access (Default):**
Direct access to the video device using GStreamer's v4l2src. This is the default and most efficient option.

```bash
VIDEO_SOURCE=v4l2 ./start_camera.sh
```

**ustreamer Source:**
Uses ustreamer to provide an HTTP MJPEG stream, which is then consumed by GStreamer. Useful for compatibility or when multiple applications need access to the same camera.

```bash
VIDEO_SOURCE=ustreamer ./start_camera.sh
```

The script will automatically start ustreamer if it's not already running.

### Example Configurations

**Custom Camera Name:**
```bash
CAMERA_NAME="MyCustomCamera" ./start_camera.sh
```
This will cause the ONVIF GetHostname response to return `MyCustomCamera` as the device hostname.
**High Resolution Setup:**
```bash
VIDEO_WIDTH=1920 VIDEO_HEIGHT=1080 VIDEO_FRAMERATE=30 ./start_camera.sh
```

**Using ustreamer Source:**
```bash
VIDEO_SOURCE=ustreamer ./start_camera.sh
```

**Multiple Camera Setup:**
```bash
# Camera 1 (V4L2 direct)
VIDEO_DEVICE=/dev/video0 RTSP_PORT=8554 ONVIF_PORT=8000 ./start_camera.sh &

# Camera 2 (ustreamer)
VIDEO_DEVICE=/dev/video1 VIDEO_SOURCE=ustreamer USTREAMER_PORT=8081 RTSP_PORT=8555 ONVIF_PORT=8001 ./start_camera.sh &
```

## Usage
Once running, your camera will be available as:

- **ONVIF Device:** `http://YOUR_IP:8000`
- **RTSP Stream:** `rtsp://YOUR_IP:8554/stream`
- **Discovery:** Automatically discoverable via WS-Discovery on your network

### Connect with ONVIF Clients
Your camera will work with any ONVIF-compatible software:
- VLC Media Player: Open `rtsp://YOUR_IP:8554/stream`
- Security camera software (Blue Iris, Frigate, etc.)
- ONVIF device managers
- Mobile apps that support ONVIF cameras

## Troubleshooting

### Camera Not Found
```bash
# Check available video devices
ls -la /dev/video*

# Test your camera works
ffplay /dev/video0
```

### Permission Issues
```bash
# Add user to video group
sudo usermod -a -G video $USER
# Log out and back in, or run:
newgrp video
```

### RTSP Stream Issues
```bash
# Test RTSP stream directly
ffplay rtsp://localhost:8554/stream

# Check if GStreamer can access camera
gst-launch-1.0 v4l2src device=/dev/video0 ! videoconvert ! xvimagesink
```

### Network Discovery Problems
```bash
# Check if ONVIF server is running
curl -s http://localhost:8000/onvif/device_service | head

# Test from another machine
curl -s http://YOUR_IP:8000/onvif/device_service | head
```

### Port Conflicts
```bash
# Check what's using the ports
sudo netstat -tlnp | grep -E ':(8000|8554)'

# Use different ports
RTSP_PORT=8555 ONVIF_PORT=8001 ./start_camera.sh
```

### GStreamer Dependencies Missing
```bash
# Install all GStreamer packages (Ubuntu/Debian)
sudo apt install gstreamer1.0-* python3-gi python3-gi-cairo \
  gir1.2-gstreamer-1.0 gir1.2-gst-rtsp-server-1.0 \
  gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly

# For older systems, you might need:
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev
```

### Video Format Issues
Some cameras output formats that need conversion. Try:
```bash
# Force a specific format
VIDEO_WIDTH=640 VIDEO_HEIGHT=480 ./start_camera.sh
```

### Debug Mode
Run with verbose logging:
```bash
# Enable debug logging
export PYTHONPATH=.
python3 -c "
import logging
logging.basicConfig(level=logging.DEBUG)
exec(open('onvif_server.py').read())
"
```

### Video pipeline issues
Use GStreamer Debug to spot issues with the video pipeline like missing modules, incompatible formats, or device access errors.
```bash
#set GST_DEBUG=2 to see GStreamer debug messages
GST_DEBUG=2 ./start_camera.sh
```

## Service management commands
```bash
# Install the service
sudo ./install-service.sh install

# Check status
./install-service.sh status

# Start/stop/restart
sudo ./install-service.sh start
sudo ./install-service.sh stop
sudo ./install-service.sh restart

# View configuration
./install-service.sh config

# View live logs
sudo ./install-service.sh logs

# Remove the service
sudo ./install-service.sh remove
```

## How It Works

This emulator consists of two main components:

1. **RTSP Server** (`rtsp_server_gst.py`): Uses GStreamer to capture video from your USB camera and serve it as an RTSP stream.
   - By default, the v4l2 source is used to create a pipeline entirely in gstreamer.
   - Optionally this wraps a stream from `ustreamer` to make a USB camera to HTTP to RTSP pipeline. 
2. **ONVIF Server** (`onvif_server.py`): Implements the ONVIF SOAP web services and WS-Discovery for multicast network discovery.

The `start_camera.sh` script coordinates both services and handles cleanup when stopped.