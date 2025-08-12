#!/usr/bin/env python3
"""
RTSP server that wraps a V4L2 device using GStreamer RTSP Server
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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Video Configuration
VIDEO_WIDTH = int(os.environ.get('VIDEO_WIDTH', 640))
VIDEO_HEIGHT = int(os.environ.get('VIDEO_HEIGHT', 480))
VIDEO_FRAMERATE = int(os.environ.get('VIDEO_FRAMERATE', 30))

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
    def __init__(self, video_device="/dev/video1", rtsp_port=8554):
        self.video_device = video_device
        self.rtsp_port = rtsp_port
        self.server = None
        self.loop = None
        
        # Initialize GStreamer
        Gst.init(None)
        
    def check_video_device(self):
        """Check if the video device is available"""
        if not os.path.exists(self.video_device):
            logger.error(f"Video device not found at {self.video_device}")
            return False
        logger.info(f"Video device is available at {self.video_device}")
        return True
        
    def start(self):
        """Start the RTSP server"""
        try:
            if not self.check_video_device():
                return False
                
            # Create the RTSP server
            self.server = GstRtspServer.RTSPServer()
            self.server.props.service = str(self.rtsp_port)
            
            # Create our custom media factory
            factory = MyRTSPMediaFactory()
            
            # Set the pipeline for the media factory
            # This pipeline reads from the V4L2 device and converts to H.264 for RTSP
            pipeline = (
                f'v4l2src device={self.video_device} '
                '! videoconvertscale '
                '! videorate '
                f'! video/x-raw,width={VIDEO_WIDTH},height={VIDEO_HEIGHT},framerate={VIDEO_FRAMERATE}/1 '
                '! openh264enc bitrate=2000000 '
                '! rtph264pay name=pay0 pt=96'
            )
            
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
            # Assuming the server is reachable at the host's IP.
            # For a more robust solution, you might want to determine the local IP dynamically.
            logger.info(f"Stream available at: rtsp://<your-ip>:{self.rtsp_port}/stream")
            logger.info(f"Using video device: {self.video_device}")
            
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
    
    parser = argparse.ArgumentParser(description="RTSP Server for V4L2 device")
    parser.add_argument('--device', type=str, default=os.environ.get('VIDEO_DEVICE', '/dev/video1'),
                        help='Video device path (e.g., /dev/video1)')
    parser.add_argument('--port', type=int, default=int(os.environ.get('RTSP_PORT', 8554)),
                        help='RTSP server port')
    args = parser.parse_args()

    # Create and start RTSP server
    server = RTSPServer(video_device=args.device, rtsp_port=args.port)
    
    if server.start():
        server.run()
    else:
        logger.error("Failed to start server")
        sys.exit(1)
