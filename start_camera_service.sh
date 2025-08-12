#!/bin/bash
#
# Service-friendly wrapper for start_camera.sh
# This version is designed to work with systemd
#

# Configuration from environment or defaults
VIDEO_DEVICE=${VIDEO_DEVICE:-/dev/video1}
RTSP_PORT=${RTSP_PORT:-8554}
ONVIF_PORT=${ONVIF_PORT:-8000}
LOCAL_IP=${LOCAL_IP:-}
VIDEO_WIDTH=${VIDEO_WIDTH:-640}
VIDEO_HEIGHT=${VIDEO_HEIGHT:-480}
VIDEO_FRAMERATE=${VIDEO_FRAMERATE:-25}

# Service configuration
SERVICE_NAME="onvif-camera"
PID_FILE="/run/${SERVICE_NAME}.pid"
LOG_FILE="/var/log/${SERVICE_NAME}.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to cleanup background processes
cleanup() {
    log_message "Cleaning up processes..."
    if [ ! -z "$RTSP_PID" ]; then
        kill $RTSP_PID 2>/dev/null
        log_message "Stopped RTSP server (PID: $RTSP_PID)"
    fi
    if [ ! -z "$ONVIF_PID" ]; then
        kill $ONVIF_PID 2>/dev/null
        log_message "Stopped ONVIF server (PID: $ONVIF_PID)"
    fi
    rm -f "$PID_FILE"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Create log file
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

log_message "Starting ONVIF Camera Emulator as service..."
log_message "Video device: $VIDEO_DEVICE"
log_message "Video resolution: ${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps"
log_message "RTSP port: $RTSP_PORT"
log_message "ONVIF port: $ONVIF_PORT"
log_message "Local IP: $LOCAL_IP"

# Check if video device exists
if [ ! -e "$VIDEO_DEVICE" ]; then
    log_message "ERROR: Video device $VIDEO_DEVICE not found"
    log_message "Available video devices:"
    ls -la /dev/video* 2>/dev/null | tee -a "$LOG_FILE" || log_message "No video devices found"
    exit 1
fi

# Start RTSP server in background
log_message "Starting RTSP server..."
VIDEO_DEVICE="$VIDEO_DEVICE" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" python3 rtsp_server_gst.py >> "$LOG_FILE" 2>&1 &
RTSP_PID=$!
log_message "RTSP server started (PID: $RTSP_PID)"

# Give RTSP server time to start
sleep 3

# Start ONVIF server in background
log_message "Starting ONVIF server..."
ONVIF_PORT="$ONVIF_PORT" LOCAL_IP="$LOCAL_IP" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" python3 onvif_server.py >> "$LOG_FILE" 2>&1 &
ONVIF_PID=$!
log_message "ONVIF server started (PID: $ONVIF_PID)"

# Write main PID file
echo $$ > "$PID_FILE"

log_message "=== ONVIF Camera Emulator Started ==="
log_message "Video Source: $VIDEO_DEVICE (${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps)"
log_message "RTSP Stream:  rtsp://${LOCAL_IP:-localhost}:$RTSP_PORT/stream"
log_message "ONVIF Device: http://${LOCAL_IP:-localhost}:$ONVIF_PORT"
log_message "Discovery:    Multicast on 239.255.255.250:3702"

# Wait for any process to finish
wait $RTSP_PID $ONVIF_PID
cleanup
