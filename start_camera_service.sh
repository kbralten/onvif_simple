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
CAMERA_NAME=${CAMERA_NAME:-}
VIDEO_WIDTH=${VIDEO_WIDTH:-640}
VIDEO_HEIGHT=${VIDEO_HEIGHT:-480}
VIDEO_FRAMERATE=${VIDEO_FRAMERATE:-25}
VIDEO_SOURCE=${VIDEO_SOURCE:-v4l2}  # 'v4l2' or 'ustreamer'
USTREAMER_HOST=${USTREAMER_HOST:-localhost}
USTREAMER_PORT=${USTREAMER_PORT:-8080}

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
    if [ ! -z "$USTREAMER_PID" ]; then
        kill $USTREAMER_PID 2>/dev/null
        log_message "Stopped ustreamer (PID: $USTREAMER_PID)"
    fi
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
log_message "Video source: $VIDEO_SOURCE"
log_message "Video device: $VIDEO_DEVICE"
log_message "Video resolution: ${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps"
log_message "RTSP port: $RTSP_PORT"
log_message "ONVIF port: $ONVIF_PORT"
log_message "Local IP: $LOCAL_IP"

# Validate video source availability
if [ "$VIDEO_SOURCE" = "v4l2" ]; then
    # Check if video device exists for v4l2 source
    if [ ! -e "$VIDEO_DEVICE" ]; then
        log_message "ERROR: Video device $VIDEO_DEVICE not found"
        log_message "Available video devices:"
        ls -la /dev/video* 2>/dev/null | tee -a "$LOG_FILE" || log_message "No video devices found"
        exit 1
    fi
    log_message "Using V4L2 source: $VIDEO_DEVICE"
elif [ "$VIDEO_SOURCE" = "ustreamer" ]; then
    # Check if ustreamer is needed and start it
    if ! nc -z "$USTREAMER_HOST" "$USTREAMER_PORT" 2>/dev/null; then
        log_message "Starting ustreamer on port $USTREAMER_PORT..."
        # Check if video device exists for ustreamer
        if [ ! -e "$VIDEO_DEVICE" ]; then
            log_message "ERROR: Video device $VIDEO_DEVICE not found for ustreamer"
            log_message "Available video devices:"
            ls -la /dev/video* 2>/dev/null | tee -a "$LOG_FILE" || log_message "No video devices found"
            exit 1
        fi
        
        # Start ustreamer in background
        ustreamer --device="$VIDEO_DEVICE" --host="$USTREAMER_HOST" --port="$USTREAMER_PORT" \
                 --resolution="${VIDEO_WIDTH}x${VIDEO_HEIGHT}" --desired-fps="$VIDEO_FRAMERATE" \
                 --format=MJPEG >> "$LOG_FILE" 2>&1 &
        USTREAMER_PID=$!
        log_message "ustreamer started (PID: $USTREAMER_PID)"
        
        # Give ustreamer time to start
        sleep 5
        
        # Verify ustreamer is running
        if ! nc -z "$USTREAMER_HOST" "$USTREAMER_PORT" 2>/dev/null; then
            log_message "ERROR: ustreamer failed to start on $USTREAMER_HOST:$USTREAMER_PORT"
            exit 1
        fi
    else
        log_message "ustreamer already running on $USTREAMER_HOST:$USTREAMER_PORT"
    fi
    log_message "Using ustreamer source: http://$USTREAMER_HOST:$USTREAMER_PORT/stream"
else
    log_message "ERROR: Unknown video source: $VIDEO_SOURCE (must be 'v4l2' or 'ustreamer')"
    exit 1
fi

# Start RTSP server in background
log_message "Starting RTSP server..."
VIDEO_SOURCE="$VIDEO_SOURCE" VIDEO_DEVICE="$VIDEO_DEVICE" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" USTREAMER_HOST="$USTREAMER_HOST" USTREAMER_PORT="$USTREAMER_PORT" python3 rtsp_server_gst.py >> "$LOG_FILE" 2>&1 &
RTSP_PID=$!
log_message "RTSP server started (PID: $RTSP_PID)"

# Give RTSP server time to start
sleep 3

# Start ONVIF server in background
log_message "Starting ONVIF server..."
ONVIF_PORT="$ONVIF_PORT" LOCAL_IP="$LOCAL_IP" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" CAMERA_NAME="$CAMERA_NAME" python3 onvif_server.py >> "$LOG_FILE" 2>&1 &
ONVIF_PID=$!
log_message "ONVIF server started (PID: $ONVIF_PID)"

# Write main PID file
echo $$ > "$PID_FILE"

log_message "=== ONVIF Camera Emulator Started ==="
log_message "Video Source: $VIDEO_SOURCE"
if [ "$VIDEO_SOURCE" = "v4l2" ]; then
    log_message "Video Device: $VIDEO_DEVICE (${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps)"
else
    log_message "ustreamer: http://$USTREAMER_HOST:$USTREAMER_PORT/stream (${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps)"
fi
log_message "RTSP Stream:  rtsp://${LOCAL_IP:-localhost}:$RTSP_PORT/stream"
log_message "ONVIF Device: http://${LOCAL_IP:-localhost}:$ONVIF_PORT"
log_message "Discovery:    Multicast on 239.255.255.250:3702"

# Wait for any process to finish
wait $RTSP_PID $ONVIF_PID
cleanup
