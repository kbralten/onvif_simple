#!/bin/bash
#
# Startup script for ONVIF camera emulator with RTSP server
#
# Configuration can be overridden with environment variables:
#   VIDEO_DEVICE=/dev/video0 ./start_camera.sh
#   MJPEG_PORT=8081 RTSP_PORT=8555 ./start_camera.sh
#   LOCAL_IP=192.168.1.100 ./start_camera.sh
#

# Configuration variables
VIDEO_DEVICE=${VIDEO_DEVICE:-/dev/video1}
RTSP_PORT=${RTSP_PORT:-8554}
ONVIF_PORT=${ONVIF_PORT:-8000}
LOCAL_IP=${LOCAL_IP:-192.168.1.155}
VIDEO_WIDTH=${VIDEO_WIDTH:-640}
VIDEO_HEIGHT=${VIDEO_HEIGHT:-480}
VIDEO_FRAMERATE=${VIDEO_FRAMERATE:-25}

# Function to cleanup background processes
cleanup() {
    echo "Cleaning up processes..."
    if [ ! -z "$USTREAMER_PID" ]; then
        kill $USTREAMER_PID 2>/dev/null
        echo "Stopped ustreamer (PID: $USTREAMER_PID)"
    fi
    if [ ! -z "$RTSP_PID" ]; then
        kill $RTSP_PID 2>/dev/null
        echo "Stopped RTSP server (PID: $RTSP_PID)"
    fi
    if [ ! -z "$ONVIF_PID" ]; then
        kill $ONVIF_PID 2>/dev/null
        echo "Stopped ONVIF server (PID: $ONVIF_PID)"
    fi
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

echo "Starting ONVIF Camera Emulator with RTSP support..."
echo "Video device: $VIDEO_DEVICE"
echo "Video resolution: ${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps"
echo "RTSP port: $RTSP_PORT"
echo "ONVIF port: $ONVIF_PORT"
echo "Local IP: $LOCAL_IP"
echo ""

# Check if video device exists
if [ ! -e "$VIDEO_DEVICE" ]; then
    echo "Warning: Video device $VIDEO_DEVICE not found"
    echo "Available video devices:"
    ls -la /dev/video* 2>/dev/null || echo "No video devices found"
    echo ""
fi

# Start RTSP server in background
echo "Starting RTSP server..."
VIDEO_DEVICE="$VIDEO_DEVICE" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" python3 rtsp_server_gst.py &
RTSP_PID=$!
echo "RTSP server started (PID: $RTSP_PID)"

# Give RTSP server time to start
sleep 3

# Start ONVIF server in background
echo "Starting ONVIF server..."
ONVIF_PORT="$ONVIF_PORT" LOCAL_IP="$LOCAL_IP" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" python3 onvif_server.py &
ONVIF_PID=$!
echo "ONVIF server started (PID: $ONVIF_PID)"

echo ""
echo "=== ONVIF Camera Emulator Started ==="
echo "Video Source: $VIDEO_DEVICE (${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps)"
echo "RTSP Stream:  rtsp://$LOCAL_IP:$RTSP_PORT/stream"
echo "ONVIF Device: http://$LOCAL_IP:$ONVIF_PORT"
echo "Discovery:    Multicast on 239.255.255.250:3702"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for any process to finish
wait $USTREAMER_PID $RTSP_PID $ONVIF_PID
cleanup
