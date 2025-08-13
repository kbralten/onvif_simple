#!/usr/bin/env python3
"""
RTSP server that wraps a V4L2 device or connects to ustreamer using GStreamer RTSP Server
"""

import gi
gi.require_version('Gst', '1.0')
gi.require_version('GstRtspServer', '1.0')
from gi.repository import Gst, GstRtspServer, GLib
import logging
import sys
import signal
import argparse
import os
import urllib.request
import socket

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Video Configuration
VIDEO_WIDTH = int(os.environ.get('VIDEO_WIDTH', 640))
VIDEO_HEIGHT = int(os.environ.get('VIDEO_HEIGHT', 480))
VIDEO_FRAMERATE = int(os.environ.get('VIDEO_FRAMERATE', 30))
VIDEO_SOURCE = os.environ.get('VIDEO_SOURCE', 'v4l2')  # 'v4l2' or 'ustreamer'
USTREAMER_HOST = os.environ.get('USTREAMER_HOST', 'localhost')
USTREAMER_PORT = int(os.environ.get('USTREAMER_PORT', 8080))

class MyRTSPMediaFactory(GstRtspServer.RTSPMediaFactory):
    def __init__(self, **properties):
        super(MyRTSPMediaFactory, self).__init__(**properties)
        self.connect("media-configure", self.on_media_configure)

    def on_media_configure(self, factory, media):
        """Callback to connect to the 'prepared' signal of the media object."""
        media.connect("prepared", self.on_media_prepared)

    def on_media_prepared(self, media):
        """Callback to add custom attributes to the SDP once the media is prepared."""


class RTSPServer:
    def __init__(self, video_device="/dev/video1", rtsp_port=8554, video_source="v4l2", ustreamer_host="localhost", ustreamer_port=8080):
        self.video_device = video_device
        self.rtsp_port = rtsp_port
        self.video_source = video_source
        self.ustreamer_host = ustreamer_host
        self.ustreamer_port = ustreamer_port
        self.server = None
        self.loop = None
        
        # Initialize GStreamer
        Gst.init(None)
        
    def check_video_source(self):
        """Check if the video source is available"""
        if self.video_source == "v4l2":
            if not os.path.exists(self.video_device):
                logger.error(f"Video device not found at {self.video_device}")
                return False
            logger.info(f"Video device is available at {self.video_device}")
            return True
        elif self.video_source == "ustreamer":
            # Check if ustreamer is reachable
            try:
                sock = socket.create_connection((self.ustreamer_host, self.ustreamer_port), timeout=5)
                sock.close()
                logger.info(f"ustreamer is available at {self.ustreamer_host}:{self.ustreamer_port}")
                return True
            except (socket.error, ConnectionRefusedError, socket.timeout) as e:
                logger.error(f"ustreamer not reachable at {self.ustreamer_host}:{self.ustreamer_port}: {e}")
                return False
        else:
            logger.error(f"Unknown video source: {self.video_source}")
            return False
        
    def start(self):
        """Start the RTSP server"""
        try:
            if not self.check_video_source():
                return False
                
            # Create the RTSP server
            self.server = GstRtspServer.RTSPServer()
            self.server.props.service = str(self.rtsp_port)
            
            # Create our custom media factory
            factory = MyRTSPMediaFactory()
            
            # Set the pipeline based on video source
            if self.video_source == "v4l2":
                # Pipeline for direct V4L2 device access
                pipeline = (
                    f'v4l2src device={self.video_device} '
                    '! videoconvertscale '
                    '! videorate '
                    f'! video/x-raw,width={VIDEO_WIDTH},height={VIDEO_HEIGHT},framerate={VIDEO_FRAMERATE}/1 '
                    '! openh264enc bitrate=2000000 '
                    '! rtph264pay name=pay0 pt=96'
                )
                logger.info(f"Using V4L2 source: {self.video_device}")
            elif self.video_source == "ustreamer":
                # Pipeline for ustreamer MJPEG source
                pipeline = (
                    f'souphttpsrc location=http://{self.ustreamer_host}:{self.ustreamer_port}/stream '
                    '! multipartdemux '
                    '! jpegdec '
                    '! videoconvertscale '
                    f'! video/x-raw,width={VIDEO_WIDTH},height={VIDEO_HEIGHT} '
                    '! openh264enc bitrate=2000000 '
                    '! rtph264pay name=pay0 pt=96'
                )
                logger.info(f"Using ustreamer source: http://{self.ustreamer_host}:{self.ustreamer_port}/stream")
            
            factory.set_launch(pipeline)
            factory.set_shared(True)
            
            # Get the mount points for this server
            mounts = self.server.get_mount_points()
            
            # Attach the media factory to the "/stream" URL
            mounts.add_factory("/stream", factory)
            
            # Attach the server to the default maincontext
            self.server.attach(None)
            
            # Create main loop
            self.loop = GLib.MainLoop()
            
            logger.info(f"RTSP server started on port {self.rtsp_port}")
            logger.info(f"Stream available at: rtsp://<your-ip>:{self.rtsp_port}/stream")
            logger.info(f"Video source: {self.video_source}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start RTSP server: {e}")
            return False
    
    def run(self):
        """Run the server (blocking)"""
        if self.loop:
            try:
                self.loop.run()
            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt")
            finally:
                self.stop()
    
    def stop(self):
        """Stop the RTSP server"""
        if self.loop:
            logger.info("Stopping RTSP server...")
            self.loop.quit()
            self.loop = None
        
        if self.server:
            self.server = None
            
        logger.info("RTSP server stopped")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    logger.info("Received interrupt signal")
    if 'server' in globals():
        server.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description="RTSP Server for V4L2 device or ustreamer")
    parser.add_argument('--device', type=str, default=os.environ.get('VIDEO_DEVICE', '/dev/video1'),
                        help='Video device path (e.g., /dev/video1) - used with v4l2 source')
    parser.add_argument('--port', type=int, default=int(os.environ.get('RTSP_PORT', 8554)),
                        help='RTSP server port')
    parser.add_argument('--source', type=str, default=VIDEO_SOURCE, choices=['v4l2', 'ustreamer'],
                        help='Video source: v4l2 (direct device) or ustreamer (HTTP MJPEG)')
    parser.add_argument('--ustreamer-host', type=str, default=USTREAMER_HOST,
                        help='ustreamer host (default: localhost)')
    parser.add_argument('--ustreamer-port', type=int, default=USTREAMER_PORT,
                        help='ustreamer port (default: 8080)')
    args = parser.parse_args()

    # Create and start RTSP server
    server = RTSPServer(
        video_device=args.device, 
        rtsp_port=args.port, 
        video_source=args.source,
        ustreamer_host=args.ustreamer_host,
        ustreamer_port=args.ustreamer_port
    )
    
    if server.start():
        server.run()
    else:
        logger.error("Failed to start server")
        sys.exit(1)
