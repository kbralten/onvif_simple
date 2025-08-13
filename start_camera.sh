#!/bin/bash
#
# Start the ONVIF camera emulator
# Supports both interactive and service use
#

# Configuration from environment or defaults
VIDEO_DEVICE=${VIDEO_DEVICE:-/dev/video1}
RTSP_PORT=${RTSP_PORT:-8554}
ONVIF_PORT=${ONVIF_PORT:-8000}
# CAMERA_NAME can be set via env or argument
CAMERA_NAME=${CAMERA_NAME:-}
# Get the first non-loopback IPv4 address if LOCAL_IP is not set
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
fi
VIDEO_WIDTH=${VIDEO_WIDTH:-640}
VIDEO_HEIGHT=${VIDEO_HEIGHT:-480}
VIDEO_FRAMERATE=${VIDEO_FRAMERATE:-25}
VIDEO_SOURCE=${VIDEO_SOURCE:-v4l2}  # 'v4l2' or 'ustreamer'
USTREAMER_HOST=${USTREAMER_HOST:-127.0.0.1}
USTREAMER_PORT=${USTREAMER_PORT:-8080}

# Determine if running as a service
if [ -t 1 ]; then
    # Interactive mode (terminal attached)
    IS_SERVICE=false
    LOG_FUNC() { echo "$1"; }
else
    # Service mode (no terminal)
    IS_SERVICE=true
    LOG_FUNC() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >&2; }
fi

# Function to cleanup background processes
cleanup() {
    LOG_FUNC "Cleaning up..."
    if [ ! -z "$USTREAMER_PID" ]; then
        kill $USTREAMER_PID 2>/dev/null
        LOG_FUNC "Stopped ustreamer (PID: $USTREAMER_PID)"
    fi
    if [ ! -z "$RTSP_PID" ]; then
        kill $RTSP_PID 2>/dev/null
        LOG_FUNC "Stopped RTSP server (PID: $RTSP_PID)"
    fi
    if [ ! -z "$ONVIF_PID" ]; then
        kill $ONVIF_PID 2>/dev/null
        LOG_FUNC "Stopped ONVIF server (PID: $ONVIF_PID)"
    fi
    exit 0
}

# Set up signal handler
trap cleanup SIGINT SIGTERM

LOG_FUNC "Starting ONVIF Camera Emulator..."
LOG_FUNC "Video source: $VIDEO_SOURCE"
LOG_FUNC "Video device: $VIDEO_DEVICE"
LOG_FUNC "Video resolution: ${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps"
LOG_FUNC "RTSP port: $RTSP_PORT"
LOG_FUNC "ONVIF port: $ONVIF_PORT"
LOG_FUNC "Local IP: $LOCAL_IP"

if [ "$IS_SERVICE" = false ]; then
    echo ""
fi

# Validate video source availability
if [ "$VIDEO_SOURCE" = "v4l2" ]; then
    # Check if video device exists for v4l2 source
    if [ ! -e "$VIDEO_DEVICE" ]; then
        LOG_FUNC "ERROR: Video device $VIDEO_DEVICE not found"
        LOG_FUNC "Available video devices:"
        ls -la /dev/video* 2>/dev/null || LOG_FUNC "No video devices found"
        exit 1
    fi
    LOG_FUNC "Using V4L2 source: $VIDEO_DEVICE"
elif [ "$VIDEO_SOURCE" = "ustreamer" ]; then
    # Check if ustreamer is needed and start it
    if ! nc -z "$USTREAMER_HOST" "$USTREAMER_PORT" 2>/dev/null; then
        LOG_FUNC "Starting ustreamer on port $USTREAMER_PORT..."
        # Check if video device exists for ustreamer
        if [ ! -e "$VIDEO_DEVICE" ]; then
            LOG_FUNC "ERROR: Video device $VIDEO_DEVICE not found for ustreamer"
            LOG_FUNC "Available video devices:"
            ls -la /dev/video* 2>/dev/null || LOG_FUNC "No video devices found"
            exit 1
        fi
        
        # Start ustreamer in background
        if [ "$IS_SERVICE" = true ]; then
            ustreamer --device="$VIDEO_DEVICE" --host="$USTREAMER_HOST" --port="$USTREAMER_PORT" \
                     --resolution="${VIDEO_WIDTH}x${VIDEO_HEIGHT}" --desired-fps="$VIDEO_FRAMERATE" \
                     --format=MJPEG >&2 &
        else
            ustreamer --device="$VIDEO_DEVICE" --host="$USTREAMER_HOST" --port="$USTREAMER_PORT" \
                     --resolution="${VIDEO_WIDTH}x${VIDEO_HEIGHT}" --desired-fps="$VIDEO_FRAMERATE" \
                     --format=MJPEG &
        fi
        USTREAMER_PID=$!
        LOG_FUNC "ustreamer started (PID: $USTREAMER_PID)"
        
        # Give ustreamer time to start
        sleep 5
        
        # Verify ustreamer is running
        if ! nc -z "$USTREAMER_HOST" "$USTREAMER_PORT" 2>/dev/null; then
            LOG_FUNC "ERROR: ustreamer failed to start on $USTREAMER_HOST:$USTREAMER_PORT"
            exit 1
        fi
    else
        LOG_FUNC "ustreamer already running on $USTREAMER_HOST:$USTREAMER_PORT"
    fi
    LOG_FUNC "Using ustreamer source: http://$USTREAMER_HOST:$USTREAMER_PORT/stream"
else
    LOG_FUNC "ERROR: Unknown video source: $VIDEO_SOURCE (must be 'v4l2' or 'ustreamer')"
    exit 1
fi

# Start RTSP server in background
LOG_FUNC "Starting RTSP server..."
if [ "$IS_SERVICE" = true ]; then
    # Service mode: redirect output to stderr for systemd logging
    VIDEO_SOURCE="$VIDEO_SOURCE" VIDEO_DEVICE="$VIDEO_DEVICE" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" USTREAMER_HOST="$USTREAMER_HOST" USTREAMER_PORT="$USTREAMER_PORT" python3 rtsp_server_gst.py >&2 &
else
    # Interactive mode: normal output
    VIDEO_SOURCE="$VIDEO_SOURCE" VIDEO_DEVICE="$VIDEO_DEVICE" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" USTREAMER_HOST="$USTREAMER_HOST" USTREAMER_PORT="$USTREAMER_PORT" python3 rtsp_server_gst.py &
fi
RTSP_PID=$!
LOG_FUNC "RTSP server started (PID: $RTSP_PID)"

# Give RTSP server time to start
sleep 3

# Start ONVIF server in background
LOG_FUNC "Starting ONVIF server..."
if [ "$IS_SERVICE" = true ]; then
    # Service mode: redirect output to stderr for systemd logging
    ONVIF_PORT="$ONVIF_PORT" LOCAL_IP="$LOCAL_IP" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" CAMERA_NAME="$CAMERA_NAME" python3 onvif_server.py >&2 &
else
    # Interactive mode: normal output
    ONVIF_PORT="$ONVIF_PORT" LOCAL_IP="$LOCAL_IP" RTSP_PORT="$RTSP_PORT" VIDEO_WIDTH="$VIDEO_WIDTH" VIDEO_HEIGHT="$VIDEO_HEIGHT" VIDEO_FRAMERATE="$VIDEO_FRAMERATE" CAMERA_NAME="$CAMERA_NAME" python3 onvif_server.py &
fi
ONVIF_PID=$!
LOG_FUNC "ONVIF server started (PID: $ONVIF_PID)"

if [ "$IS_SERVICE" = false ]; then
    echo ""
fi

LOG_FUNC "=== ONVIF Camera Emulator Started ==="
LOG_FUNC "Video Source: $VIDEO_SOURCE"
if [ "$VIDEO_SOURCE" = "v4l2" ]; then
    LOG_FUNC "Video Device: $VIDEO_DEVICE (${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps)"
else
    LOG_FUNC "ustreamer: http://$USTREAMER_HOST:$USTREAMER_PORT/stream (${VIDEO_WIDTH}x${VIDEO_HEIGHT} @ ${VIDEO_FRAMERATE}fps)"
fi
LOG_FUNC "RTSP Stream:  rtsp://${LOCAL_IP:-localhost}:$RTSP_PORT/stream"
LOG_FUNC "ONVIF Device: http://${LOCAL_IP:-localhost}:$ONVIF_PORT"
LOG_FUNC "Discovery:    Multicast on 239.255.255.250:3702"

if [ "$IS_SERVICE" = false ]; then
    echo ""
    echo "Press Ctrl+C to stop..."
fi

# Wait for any process to finish
wait $RTSP_PID $ONVIF_PID
