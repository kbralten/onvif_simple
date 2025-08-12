# ONVIF Camera Emulator

Turn any USB camera into an ONVIF-compatible IP camera. This project creates an ONVIF device server with RTSP streaming using GStreamer for your USB video device.

## Quick Start

1. **Install dependencies:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv gstreamer1.0-* python3-gi python3-gi-cairo gir1.2-gstreamer-1.0 gir1.2-gst-rtsp-server-1.0
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
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
| `RTSP_PORT` | `8554` | RTSP streaming port |
| `ONVIF_PORT` | `8000` | ONVIF web service port |
| `LOCAL_IP` | `192.168.1.155` | IP address for ONVIF responses |
| `VIDEO_WIDTH` | `1280` | Video stream width |
| `VIDEO_HEIGHT` | `720` | Video stream height |
| `VIDEO_FRAMERATE` | `25` | Video stream frame rate |

### Example Configurations

**High Resolution Setup:**
```bash
VIDEO_WIDTH=1920 VIDEO_HEIGHT=1080 VIDEO_FRAMERATE=30 ./start_camera.sh
```

**Multiple Camera Setup:**
```bash
# Camera 1
VIDEO_DEVICE=/dev/video0 RTSP_PORT=8554 ONVIF_PORT=8000 ./start_camera.sh &

# Camera 2  
VIDEO_DEVICE=/dev/video1 RTSP_PORT=8555 ONVIF_PORT=8001 ./start_camera.sh &
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

## How It Works

This emulator consists of two main components:

1. **RTSP Server** (`rtsp_server_gst.py`): Uses GStreamer to capture video from your USB camera and serve it as an RTSP stream
2. **ONVIF Server** (`onvif_server.py`): Implements the ONVIF SOAP web services and WS-Discovery for network discovery

The `start_camera.sh` script coordinates both services and handles cleanup when stopped.
