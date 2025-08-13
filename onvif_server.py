# onvif_camera_emulator.py
# This script emulates a basic ONVIF camera. It exposes a Device and Media
# service that points to a local MJPEG stream, typically from ustreamer.

import asyncio
import logging
from aiohttp import web
from datetime import datetime
import xml.etree.ElementTree as ET
from aiohttp.web_response import Response
import socket
import struct
import uuid
import time
import array
import fcntl
import base64
import hashlib
import random
import netifaces
import os
import argparse

# --- Configuration ---
MJPEG_STREAM_HOST = '127.0.0.1'
MJPEG_STREAM_PORT = 8080
MJPEG_STREAM_PATH = '/?action=stream'
ONVIF_SERVER_PORT = int(os.environ.get('ONVIF_PORT', 8000))
ONVIF_SERVER_HOST = '0.0.0.0'
LOCAL_IP = os.environ.get('LOCAL_IP', '192.168.1.155')
RTSP_PORT = int(os.environ.get('RTSP_PORT', 8554))

# Video Configuration
VIDEO_WIDTH = int(os.environ.get('VIDEO_WIDTH', 640))
VIDEO_HEIGHT = int(os.environ.get('VIDEO_HEIGHT', 480))
VIDEO_FRAMERATE = int(os.environ.get('VIDEO_FRAMERATE', 30))

# WS-Discovery multicast settings
MULTICAST_GROUP = '239.255.255.250'
MULTICAST_PORT = 3702

# Generate a unique device UUID for this session
def get_mac_address():
    """Get the MAC address of the first non-loopback interface."""
    for iface in netifaces.interfaces():
        if iface == 'lo':
            continue
        addrs = netifaces.ifaddresses(iface)
        mac = addrs.get(netifaces.AF_LINK)
        if mac and mac[0].get('addr'):
            return mac[0]['addr']
    return None

mac = get_mac_address()
if mac:
    DEVICE_UUID = str(uuid.uuid5(uuid.NAMESPACE_DNS, mac))
else:
    DEVICE_UUID = str(uuid.uuid4())
DEVICE_URN = f"uuid:{DEVICE_UUID}"

# --- Logging setup ---
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def log_curl_commands(request, request_text, endpoint):
    # """Log curl commands to test both this server and the real camera"""
     # Get the local IP for our server
    local_ip = get_local_ip()
    
    # # Extract headers we need to replicate
    # headers = []
    # for header_name, header_value in request.headers.items():
    #     if header_name.lower() in ['content-type', 'soapaction', 'authorization']:
    #         headers.append(f'-H "{header_name}: {header_value}"')
    
    # headers_str = ' '.join(headers)
    
    # # Escape single quotes in the request body for shell safety
    # escaped_body = request_text.replace("'", "'\"'\"'")
    
    # # Generate curl commands
    # our_server_curl = f"curl -X POST {headers_str} -d '{escaped_body}' http://{local_ip}:{ONVIF_SERVER_PORT}{endpoint}"
    # real_camera_curl = f"curl -X POST {headers_str} -d '{escaped_body}' http://192.168.1.202{endpoint}"
    
    # logger.info("=" * 80)
    # logger.info(f"CURL COMMANDS FOR {endpoint}:")
    # logger.info("Our Server:")
    # logger.info(our_server_curl)
    # logger.info("Real Camera:")
    # logger.info(real_camera_curl)
    # logger.info("=" * 80)

# SOAP namespaces
SOAP_ENV = "http://www.w3.org/2003/05/soap-envelope"
ONVIF_DEVICE = "http://www.onvif.org/ver10/device/wsdl"
ONVIF_MEDIA = "http://www.onvif.org/ver10/media/wsdl"
WS_DISCOVERY = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
WS_ADDRESSING = "http://www.w3.org/2005/08/addressing"

def get_local_ip():
    """Get the local IP address of the machine or use configured LOCAL_IP"""
    # If LOCAL_IP is explicitly set and not the default, use it
    global LOCAL_IP
    if LOCAL_IP and LOCAL_IP != "192.168.1.155":
        return LOCAL_IP
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return LOCAL_IP if LOCAL_IP else "127.0.0.1"

def create_ws_discovery_probe_match():
    """Create a WS-Discovery ProbeMatches response"""
    local_ip = get_local_ip()
    device_service_url = f"http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/device_service"

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Header><wsa:MessageID>{{message_id}}</wsa:MessageID><wsa:RelatesTo>{{relation_id}}</wsa:RelatesTo><wsa:To SOAP-ENV:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To><wsa:Action SOAP-ENV:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><wsdd:ProbeMatches><wsdd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:{DEVICE_URN}</wsa:Address></wsa:EndpointReference><wsdd:Types>tdn:NetworkVideoTransmitter</wsdd:Types><wsdd:Scopes>onvif://www.onvif.org/type/Network_Video_Transmitter onvif://www.onvif.org/type/ptz onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/type/video_analytics onvif://www.onvif.org/name/ONVIF_ICAMERA onvif://www.onvif.org/hardware/PG2345I onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/location/China onvif://www.onvif.org/location/Shenzhen </wsdd:Scopes><wsdd:XAddrs>{device_service_url}</wsdd:XAddrs><wsdd:MetadataVersion>1</wsdd:MetadataVersion></wsdd:ProbeMatch></wsdd:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>""" + "\n"

class WSDiscoveryHandler:
    """Handles WS-Discovery multicast probe requests"""
    
    def __init__(self):
        self.listen_socket = None
        self.response_socket = None
        self.running = False
        self.local_ip = get_local_ip()
    
    def _get_actual_local_ip(self):
        """Get the actual local IP for socket binding"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    async def start(self):
        """Start the WS-Discovery multicast listener"""
        self.running = True

        # Create and configure the multicast socket
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        
        # Set socket options for reuse
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
            
        # Configure multicast options
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        
        # Important: SO_BROADCAST might be needed for some networks
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Bind to all interfaces to receive multicast
        logger.info(f"Binding listen socket to 0.0.0.0:{MULTICAST_PORT}")
        self.listen_socket.bind(('0.0.0.0', MULTICAST_PORT))

        # Join multicast group on all interfaces
        mreq = struct.pack('4s4s', socket.inet_aton(MULTICAST_GROUP), socket.inet_aton('0.0.0.0'))
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        logger.info(f"Joined multicast group {MULTICAST_GROUP} on all interfaces")

        # Set socket to non-blocking mode
        self.listen_socket.setblocking(False)

        # Create response socket
        self.response_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.response_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Use actual local IP for socket binding, but configured IP for content
        actual_local_ip = self._get_actual_local_ip()
        self.response_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(actual_local_ip))
        
        try:
            self.response_socket.bind((actual_local_ip, 3702))
            logger.info(f"Response socket bound to {actual_local_ip}:3702")
        except Exception as e:
            logger.warning(f"Could not bind response socket to {actual_local_ip}:3702: {e}")
            self.response_socket.bind(('', 3702))

        # Start listening loop
        logger.info("Starting WS-Discovery listener loop")
        asyncio.create_task(self._listen_loop())

    async def _listen_loop(self):
        """Listen for multicast probe requests"""
        while self.running:
            try:
                # Use asyncio to avoid blocking
                data, addr = await asyncio.get_event_loop().sock_recvfrom(self.listen_socket, 4096)
                logger.debug(f"Received UDP packet from {addr}, {len(data)} bytes")
                
                # Ignore messages from the server's own IP address
                if addr[0] == self.local_ip:
                    logger.debug(f"Ignoring multicast message from self ({addr[0]})")
                    continue
                
                try:
                    message = data.decode('utf-8', errors='replace')
                    logger.debug(f"Received multicast message from {addr}: {message[:200]}...")
                    
                    if 'Probe' in message:
                        logger.info(f"Received WS-Discovery Probe from {addr[0]}:{addr[1]}")
                        await self._handle_probe(message, addr)
                        
                except UnicodeDecodeError:
                    logger.debug(f"Received non-UTF8 multicast data from {addr}")
                    
            except socket.error as e:
                if e.errno == socket.EAGAIN or e.errno == socket.EWOULDBLOCK:
                    # No data available, wait a bit
                    await asyncio.sleep(0.01)
                else:
                    logger.error(f"Socket error in WS-Discovery listener: {e}")
                    break
            except Exception as e:
                logger.error(f"Error in WS-Discovery listener: {e}")
                await asyncio.sleep(0.1)
    
    async def _handle_probe(self, message, sender_addr):
        """Handle a WS-Discovery probe request"""
        try:
            # Extract MessageID for response correlation
            message_id = None
            
            if 'MessageID' in message:
                import re
                match = re.search(r'<.*?MessageID.*?>(.*?)</.*?MessageID.*?>', message)
                if match:
                    message_id = match.group(1).strip()
                    logger.debug(f"Extracted MessageID: {message_id}")
                    #Extracted MessageID: urn:uuid:a60bacd1-b775-4110-ac50-e17000df992d
                    #uuid:0b8e8053-a83d-4913-9b53-da9e31a1dcac
            if not message_id:
                message_id = f"uuid:{uuid.uuid4()}"

            our_message_id = f"uuid:{uuid.uuid4()}"
            
            # Create response
            response = create_ws_discovery_probe_match().replace("{relation_id}", message_id).replace("{message_id}", our_message_id)
            response_data = response.encode('utf-8')
            
            # Random delay to avoid network flooding (0-500ms)
            delay = random.uniform(0, 0.5)
            await asyncio.sleep(delay)
            
            # Log detailed information about the response destination
            logger.debug(f"Response destination: IP={sender_addr[0]}, Port={sender_addr[1]}")

            # Send unicast response only to the originating IP address
            self.response_socket.sendto(response_data, sender_addr)
            logger.info(f"Sent WS-Discovery ProbeMatch response to {sender_addr[0]}:{sender_addr[1]}")

            # Removed multicast response to avoid unnecessary traffic
            # logger.debug("Also sent response to multicast group")
            
        except Exception as e:
            logger.error(f"Error handling WS-Discovery probe: {e}")
            import traceback
            traceback.print_exc()
    
    def stop(self):
        """Stop the WS-Discovery service"""
        self.running = False
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except:
                pass
        if self.response_socket:
            try:
                self.response_socket.close()
            except:
                pass

def create_soap_response(body_content):
    """Create a SOAP envelope response"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="{SOAP_ENV}" xmlns:tds="{ONVIF_DEVICE}" xmlns:trt="{ONVIF_MEDIA}" xmlns:tt="http://www.onvif.org/ver10/schema"><soap:Body>{body_content}</soap:Body></soap:Envelope>"""

class ONVIFDeviceService:
    """Implements a basic ONVIF Device service."""
    def get_device_information(self):
        """Returns mock information about the camera device."""
        return f"""<tds:Manufacturer>VIRTUAL_ONVIF</tds:Manufacturer><tds:Model>ONVIF_SIMPLE</tds:Model><tds:FirmwareVersion>V0.1.1.0</tds:FirmwareVersion><tds:SerialNumber>A4EDS</tds:SerialNumber><tds:HardwareId>DEADBEEFUIAS</tds:HardwareId></tds:GetDeviceInformationResponse>"""

    def get_capabilities(self):
        """Returns device capabilities."""
        local_ip = get_local_ip()
        return f"""
        <tds:GetCapabilitiesResponse>
            <tds:Capabilities>
                <tt:Device>
                    <tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/device_service</tt:XAddr>
                </tt:Device>
                <tt:Media>
                    <tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/media_service</tt:XAddr>
                </tt:Media>
            </tds:Capabilities>
        </tds:GetCapabilitiesResponse>"""

class ONVIFMediaService:
    """Implements a basic ONVIF Media service."""
    def get_profiles(self):
        """Returns media profile information."""
        return f"""
        <trt:GetProfilesResponse>
            <trt:Profiles fixed="true" token="profile1">
                <tt:Name>Default</tt:Name>
                <tt:VideoSourceConfiguration token="video1">
                    <tt:Name>VideoSource1</tt:Name>
                    <tt:UseCount>1</tt:UseCount>
                    <tt:SourceToken>video1</tt:SourceToken>
                    <tt:Bounds height="{VIDEO_HEIGHT}" width="{VIDEO_WIDTH}" y="0" x="0"/>
                </tt:VideoSourceConfiguration>
                <tt:VideoEncoderConfiguration token="encoder1">
                    <tt:Name>Encoder1</tt:Name>
                    <tt:UseCount>1</tt:UseCount>
                    <tt:Encoding>JPEG</tt:Encoding>
                    <tt:Resolution>
                        <tt:Width>{VIDEO_WIDTH}</tt:Width>
                        <tt:Height>{VIDEO_HEIGHT}</tt:Height>
                    </tt:Resolution>
                    <tt:Quality>100</tt:Quality>
                    <tt:RateControl>
                        <tt:FrameRateLimit>{VIDEO_FRAMERATE}</tt:FrameRateLimit>
                        <tt:EncodingInterval>1</tt:EncodingInterval>
                        <tt:BitrateLimit>3000</tt:BitrateLimit>
                    </tt:RateControl>
                </tt:VideoEncoderConfiguration>
            </trt:Profiles>
        </trt:GetProfilesResponse>"""

    def get_stream_uri(self, profile_token):
        """Returns the MJPEG stream URI."""
        stream_uri = f'http://{MJPEG_STREAM_HOST}:{MJPEG_STREAM_PORT}{MJPEG_STREAM_PATH}'
        return f"""
        <trt:GetStreamUriResponse>
            <trt:MediaUri>
                <tt:Uri>{stream_uri}</tt:Uri>
                <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
                <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
                <tt:Timeout>PT0S</tt:Timeout>
            </trt:MediaUri>
        </trt:GetStreamUriResponse>"""

def extract_soap_action(request_text):
    """Extract the SOAP action from the request to include in response Content-Type"""
    # Try to find the SOAP action in the XML body
    try:
        # Parse the XML to find the first child of the Body element
        import xml.etree.ElementTree as ET
        root = ET.fromstring(request_text)
        
        # Find the Body element in any namespace
        body = None
        for elem in root.iter():
            if elem.tag.endswith('}Body') or elem.tag == 'Body':
                body = elem
                break
        
        if body is not None and len(body) > 0:
            # Get the first child of Body, which contains the operation
            operation = body[0]
            tag = operation.tag
            
            # Extract namespace and operation name
            if '}' in tag:
                namespace, op_name = tag.rsplit('}', 1)
                namespace = namespace[1:]  # Remove the leading '{'
            else:
                # Fallback to the default ONVIF device namespace
                namespace = "http://www.onvif.org/ver10/device/wsdl"
                op_name = tag
            
            return f"{namespace}/{op_name}"
    except Exception as e:
        logger.debug(f"Failed to extract SOAP action: {e}")
    
    # Fallback - return a generic action
    return "http://www.onvif.org/ver10/device/wsdl/Action"

def create_onvif_response(response_body, soap_action=None):
    """Create an ONVIF response with proper headers matching real cameras"""
    headers = {
        'Server': 'gSOAP/2.8',
        'Access-Control-Allow-Origin': '*',
        'Content-Type': f'application/soap+xml; charset=utf-8',
        'Connection': 'close'
    }
    
    # Add the action to Content-Type if provided
    if soap_action:
        headers['Content-Type'] += f'; action="{soap_action}"'
    
    return web.Response(text=response_body, headers=headers)

async def handle_device_service(request):
    """Handle requests to the /onvif/device_service endpoint"""
    request_text = await request.text()
    logger.info("Received POST request to /onvif/device_service")
    logger.debug(f"Request content preview: {request_text[:200]}...")
    
    # Log curl commands for debugging
    log_curl_commands(request, request_text, "/onvif/device_service")

    if "GetServiceCapabilities" in request_text:
        logger.info("Handling GetServiceCapabilities request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><tds:GetServiceCapabilitiesResponse><tds:Capabilities><tds:Network IPFilter="false" ZeroConfiguration="false" IPVersion6="false" DynDNS="false" Dot11Configuration="false" HostnameFromDHCP="false" NTP="1"></tds:Network><tds:Security TLS1.0="false" TLS1.1="false" TLS1.2="false" OnboardKeyGeneration="false" AccessPolicyConfig="false" Dot1X="false" RemoteUserHandling="false" X.509Token="false" SAMLToken="false" KerberosToken="false" UsernameToken="false" HttpDigest="false" RELToken="false"></tds:Security><tds:System DiscoveryResolve="false" DiscoveryBye="false" RemoteDiscovery="false" SystemBackup="false" SystemLogging="true" FirmwareUpgrade="true" HttpFirmwareUpgrade="true" HttpSystemBackup="false" HttpSystemLogging="true" HttpSupportInformation="true"></tds:System></tds:Capabilities></tds:GetServiceCapabilitiesResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    elif "GetCapabilities" in request_text:
        logger.info("Handling GetCapabilities request")
        local_ip = get_local_ip()
        response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><tds:GetCapabilitiesResponse><tds:Capabilities><tt:Analytics><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/analytics</tt:XAddr><tt:RuleSupport>true</tt:RuleSupport><tt:AnalyticsModuleSupport>true</tt:AnalyticsModuleSupport></tt:Analytics><tt:Device><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/device</tt:XAddr><tt:Network><tt:IPFilter>false</tt:IPFilter><tt:ZeroConfiguration>false</tt:ZeroConfiguration><tt:IPVersion6>false</tt:IPVersion6><tt:DynDNS>false</tt:DynDNS><tt:Extension><tt:Dot11Configuration>false</tt:Dot11Configuration></tt:Extension></tt:Network><tt:System><tt:DiscoveryResolve>false</tt:DiscoveryResolve><tt:DiscoveryBye>false</tt:DiscoveryBye><tt:RemoteDiscovery>false</tt:RemoteDiscovery><tt:SystemBackup>false</tt:SystemBackup><tt:SystemLogging>true</tt:SystemLogging><tt:FirmwareUpgrade>true</tt:FirmwareUpgrade><tt:SupportedVersions><tt:Major>17</tt:Major><tt:Minor>6</tt:Minor></tt:SupportedVersions><tt:Extension><tt:HttpFirmwareUpgrade>true</tt:HttpFirmwareUpgrade><tt:HttpSystemBackup>false</tt:HttpSystemBackup><tt:HttpSystemLogging>true</tt:HttpSystemLogging><tt:HttpSupportInformation>true</tt:HttpSupportInformation></tt:Extension></tt:System><tt:IO><tt:InputConnectors>1</tt:InputConnectors><tt:RelayOutputs>1</tt:RelayOutputs></tt:IO><tt:Security><tt:TLS1.1>false</tt:TLS1.1><tt:TLS1.2>false</tt:TLS1.2><tt:OnboardKeyGeneration>false</tt:OnboardKeyGeneration><tt:AccessPolicyConfig>false</tt:AccessPolicyConfig><tt:X.509Token>false</tt:X.509Token><tt:SAMLToken>false</tt:SAMLToken><tt:KerberosToken>false</tt:KerberosToken><tt:RELToken>false</tt:RELToken></tt:Security></tt:Device><tt:Events><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/events</tt:XAddr><tt:WSSubscriptionPolicySupport>true</tt:WSSubscriptionPolicySupport><tt:WSPullPointSupport>true</tt:WSPullPointSupport><tt:WSPausableSubscriptionManagerInterfaceSupport>true</tt:WSPausableSubscriptionManagerInterfaceSupport></tt:Events><tt:Imaging><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/imaging</tt:XAddr></tt:Imaging><tt:Media><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/media</tt:XAddr><tt:StreamingCapabilities><tt:RTPMulticast>true</tt:RTPMulticast><tt:RTP_TCP>true</tt:RTP_TCP><tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP></tt:StreamingCapabilities></tt:Media><tt:PTZ><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/ptz</tt:XAddr></tt:PTZ><tt:Extension><tt:DeviceIO><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/deviceIO</tt:XAddr><tt:VideoSources>1</tt:VideoSources><tt:VideoOutputs>0</tt:VideoOutputs><tt:AudioSources>1</tt:AudioSources><tt:AudioOutputs>1</tt:AudioOutputs><tt:RelayOutputs>1</tt:RelayOutputs></tt:DeviceIO><tt:Extensions><tt:TelexCapabilities><tt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/telecom_service</tt:XAddr><tt:TimeOSDSupport>true</tt:TimeOSDSupport><tt:TitleOSDSupport>true</tt:TitleOSDSupport><tt:PTZ3DZoomSupport>true</tt:PTZ3DZoomSupport><tt:PTZAuxSwitchSupport>true</tt:PTZAuxSwitchSupport><tt:MotionDetectorSupport>true</tt:MotionDetectorSupport><tt:TamperDetectorSupport>true</tt:TamperDetectorSupport></tt:TelexCapabilities></tt:Extensions><ewsd:hbCapabilities><exsd:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/hbgk_ext</exsd:XAddr><exsd:H265Support>true</exsd:H265Support><exsd:PrivacyMaskSupport>true</exsd:PrivacyMaskSupport><exsd:CameraNum>1</exsd:CameraNum><exsd:MaxMaskAreaNum>4</exsd:MaxMaskAreaNum></ewsd:hbCapabilities><tplt:Plus><tplt:XAddr>http://{local_ip}:{ONVIF_SERVER_PORT}/onvif/hbgk_ext</tplt:XAddr><tplt:H265>true</tplt:H265><tplt:PrivacyMask>true</tplt:PrivacyMask><tplt:CameraNum>1</tplt:CameraNum><tplt:MaxMaskAreaNum>4</tplt:MaxMaskAreaNum></tplt:Plus></tt:Extension></tds:Capabilities></tds:GetCapabilitiesResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    elif "GetSystemDateAndTime" in request_text:
        logger.info("Handling GetSystemDateAndTime request")
        # Dynamically generate current UTC and local time
        now_utc = datetime.utcnow()
        now_local = datetime.now()
        response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>Manual</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:TimeZone><tt:TZ>EST5EDT,M3.2.0,M11.1.0</tt:TZ></tt:TimeZone><tt:UTCDateTime><tt:Time><tt:Hour>{now_utc.hour}</tt:Hour><tt:Minute>{now_utc.minute}</tt:Minute><tt:Second>{now_utc.second}</tt:Second></tt:Time><tt:Date><tt:Year>{now_utc.year}</tt:Year><tt:Month>{now_utc.month}</tt:Month><tt:Day>{now_utc.day}</tt:Day></tt:Date></tt:UTCDateTime><tt:LocalDateTime><tt:Time><tt:Hour>{now_local.hour}</tt:Hour><tt:Minute>{now_local.minute}</tt:Minute><tt:Second>{now_local.second}</tt:Second></tt:Time><tt:Date><tt:Year>{now_local.year}</tt:Year><tt:Month>{now_local.month}</tt:Month><tt:Day>{now_local.day}</tt:Day></tt:Date></tt:LocalDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    elif "GetDeviceInformation" in request_text:
        logger.info("Handling GetDeviceInformation request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><tds:GetDeviceInformationResponse><tds:Manufacturer>VIRTUAL_ONVIF</tds:Manufacturer><tds:Model>ONVIF_SIMPLE</tds:Model><tds:FirmwareVersion>V0.1.1.0</tds:FirmwareVersion><tds:SerialNumber>A4EDS</tds:SerialNumber><tds:HardwareId>DEADBEEFUIAS</tds:HardwareId></tds:GetDeviceInformationResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    elif "GetHostname" in request_text:
        logger.info("Handling GetHostname request")
        camera_name = os.environ.get('CAMERA_NAME')
        if not camera_name:
            camera_name = socket.gethostname()
        response_body = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsdd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:chan=\"http://schemas.microsoft.com/ws/2005/02/duplex\" xmlns:wsa5=\"http://www.w3.org/2005/08/addressing\" xmlns:xmime=\"http://www.w3.org/2005/05/xmlmime\" xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" xmlns:wsrfbf=\"http://docs.oasis-open.org/wsrf/bf-2\" xmlns:tt=\"http://www.onvif.org/ver10/schema\" xmlns:wstop=\"http://docs.oasis-open.org/wsn/t-1\" xmlns:wsrfr=\"http://docs.oasis-open.org/wsrf/r-2\" xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\" xmlns:tdn=\"http://www.onvif.org/ver10/network/wsdl\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" xmlns:c14n=\"http://www.w3.org/2001/10/xml-exc-c14n#\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:wsc=\"http://schemas.xmlsoap.org/ws/2005/02/sc\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:timg=\"http://www.onvif.org/ver20/imaging/wsdl\" xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\" xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:ter=\"http://www.onvif.org/ver10/error\" xmlns:tns1=\"http://www.onvif.org/ver10/topics\" xmlns:trt2=\"http://www.onvif.org/ver20/media/wsdl\" xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\" xmlns:tplt=\"http://www.onvif.org/ver10/plus/schema\" xmlns:tpl=\"http://www.onvif.org/ver10/plus/wsdl\" xmlns:ewsd=\"http://www.onvifext.com/onvif/ext/ver10/wsdl\" xmlns:exsd=\"http://www.onvifext.com/onvif/ext/ver10/schema\" xmlns:tnshik=\"http://www.hikvision.com/2011/event/topics\"><SOAP-ENV:Body><tds:GetHostnameResponse><tds:HostnameInformation><tt:FromDHCP>false</tt:FromDHCP><tt:Name>{camera_name}</tt:Name></tds:HostnameInformation></tds:GetHostnameResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    elif "GetScopes" in request_text:
        logger.info("Handling GetScopes request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<tds:GetScopesResponse>
<tds:Scopes>
<tt:ScopeDef>Fixed</tt:ScopeDef>
<tt:ScopeItem>onvif://www.onvif.org/type/Network_Video_Transmitter</tt:ScopeItem>
</tds:Scopes>
<tds:Scopes>
<tt:ScopeDef>Fixed</tt:ScopeDef>
<tt:ScopeItem>onvif://www.onvif.org/Profile/Streaming</tt:ScopeItem>
</tds:Scopes>
<tds:Scopes>
<tt:ScopeDef>Fixed</tt:ScopeDef>
<tt:ScopeItem>onvif://www.onvif.org/name/ONVIF_VIRTUAL</tt:ScopeItem>
</tds:Scopes>
<tds:Scopes>
<tt:ScopeDef>Fixed</tt:ScopeDef>
<tt:ScopeItem>onvif://www.onvif.org/hardware/VIRTUAL</tt:ScopeItem>
</tds:Scopes>
</tds:GetScopesResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetDNS" in request_text:
        logger.info("Handling GetDNS request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<tds:GetDNSResponse>
<tds:DNSInformation>
<tt:FromDHCP>false</tt:FromDHCP>
<tt:DNSFromDHCP>false</tt:DNSFromDHCP>
</tds:DNSInformation>
</tds:GetDNSResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetNetworkInterfaces" in request_text:
        logger.info("Handling GetNetworkInterfaces request")
        response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<tds:GetNetworkInterfacesResponse>
<tds:NetworkInterfaces token="eth0">
<tt:Enabled>true</tt:Enabled>
<tt:Info>
<tt:Name>eth0</tt:Name>
<tt:HwAddress>00:11:22:33:44:55</tt:HwAddress>
<tt:MTU>1500</tt:MTU>
</tt:Info>
<tt:IPv4>
<tt:Enabled>true</tt:Enabled>
<tt:Config>
<tt:DHCP>false</tt:DHCP>
<tt:Manual>
<tt:Address>{LOCAL_IP}</tt:Address>
<tt:PrefixLength>24</tt:PrefixLength>
</tt:Manual>
</tt:Config>
</tt:IPv4>
</tds:NetworkInterfaces>
</tds:GetNetworkInterfacesResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetNetworkProtocols" in request_text:
        logger.info("Handling GetNetworkProtocols request")
        response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<tds:GetNetworkProtocolsResponse>
<tds:NetworkProtocols>
<tt:Name>HTTP</tt:Name>
<tt:Enabled>true</tt:Enabled>
<tt:Port>80</tt:Port>
</tds:NetworkProtocols>
<tds:NetworkProtocols>
<tt:Name>RTSP</tt:Name>
<tt:Enabled>true</tt:Enabled>
<tt:Port>{RTSP_PORT}</tt:Port>
</tds:NetworkProtocols>
</tds:GetNetworkProtocolsResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetUsers" in request_text:
        logger.info("Handling GetUsers request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<tds:GetUsersResponse>
<tds:User>
<tt:Username>anonymous</tt:Username>
<tt:Password></tt:Password>
<tt:UserLevel>User</tt:UserLevel>
</tds:User>
</tds:GetUsersResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetWsdlUrl" in request_text:
        logger.info("Handling GetWsdlUrl request")
        response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<tds:GetWsdlUrlResponse>
<tds:WsdlUrl>http://{LOCAL_IP}:{ONVIF_SERVER_PORT}/onvif/device_service?wsdl</tds:WsdlUrl>
</tds:GetWsdlUrlResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    else:
        logger.warning("Received unsupported SOAP request")
        logger.warning(f"Checked for: GetServiceCapabilities, GetCapabilities, GetSystemDateAndTime, GetDeviceInformation, GetHostname")
        logger.debug(f"Full request content: {request_text}")
        response_body = """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
            <SOAP-ENV:Body>
                <SOAP-ENV:Fault>
                    <faultcode>SOAP-ENV:Client</faultcode>
                    <faultstring>Unknown request</faultstring>
                </SOAP-ENV:Fault>
            </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>"""

    # Extract SOAP action from request for proper Content-Type header
    soap_action = extract_soap_action(request_text)
    return create_onvif_response(response_body, soap_action)

async def handle_unsupported_route(request):
    """Handle unsupported routes"""
    logger.warning(f"Received {request.method} request to unsupported route: {request.path}")
    
    # Log curl commands for any unexpected requests
    if request.method == 'POST':
        request_text = await request.text()
        log_curl_commands(request, request_text, request.path)
    else:
        log_curl_commands(request, "", request.path)
    
    return web.Response(status=404, text="Not Found")

async def handle_media_service(request):
    """Handle requests to the /onvif/media_service endpoint"""
    request_text = await request.text()
    logger.info("Received POST request to /onvif/media_service")
    logger.debug(f"Request content preview: {request_text[:200]}...")
    
    # Log curl commands for debugging
    log_curl_commands(request, request_text, "/onvif/media_service")
    
    # Check for HTTP Basic Authentication in headers
    auth_header = request.headers.get('Authorization', '')
    if auth_header:
        logger.info(f"Received Authorization header: {auth_header[:50]}...")
    
    # Accept any authentication or no authentication

    # Parse different ONVIF media service requests
    if "GetProfiles" in request_text:
        logger.info("Handling GetProfiles request")
        response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetProfilesResponse>
<trt:Profiles token="MainStream" fixed="false">
<tt:Name>MainStream</tt:Name>
<tt:VideoSourceConfiguration token="VideoSourceMain">
<tt:Name>VideoSourceMain</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:SourceToken>VideoSourceMain</tt:SourceToken>
<tt:Bounds x="0" y="0" width="{VIDEO_WIDTH}" height="{VIDEO_HEIGHT}"></tt:Bounds>
</tt:VideoSourceConfiguration>
<tt:AudioSourceConfiguration token="AudioMainToken">
<tt:Name>AudioMainName</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:SourceToken>AudioMainSrcToken</tt:SourceToken>
</tt:AudioSourceConfiguration>
<tt:VideoEncoderConfiguration token="VideoEncodeMain">
<tt:Name>VideoEncodeMain</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:Encoding>H264</tt:Encoding>
<tt:Resolution>
<tt:Width>{VIDEO_WIDTH}</tt:Width>
<tt:Height>{VIDEO_HEIGHT}</tt:Height>
</tt:Resolution>
<tt:Quality>50</tt:Quality>
<tt:RateControl>
<tt:FrameRateLimit>{VIDEO_FRAMERATE}</tt:FrameRateLimit>
<tt:EncodingInterval>1</tt:EncodingInterval>
<tt:BitrateLimit>4900</tt:BitrateLimit>
</tt:RateControl>
<tt:MPEG4>
<tt:GovLength>0</tt:GovLength>
<tt:Mpeg4Profile>SP</tt:Mpeg4Profile>
</tt:MPEG4>
<tt:H264>
<tt:GovLength>40</tt:GovLength>
<tt:H264Profile>High</tt:H264Profile>
</tt:H264>
<tt:Multicast>
<tt:Address>
<tt:Type>IPv4</tt:Type>
<tt:IPv4Address>192.168.1.202</tt:IPv4Address>
</tt:Address>
<tt:Port>0</tt:Port>
<tt:TTL>0</tt:TTL>
<tt:AutoStart>false</tt:AutoStart>
</tt:Multicast>
<tt:SessionTimeout>PT00H12M00S</tt:SessionTimeout>
</tt:VideoEncoderConfiguration>
<tt:AudioEncoderConfiguration token="G711">
<tt:Name>AudioMain</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:Encoding>G711</tt:Encoding>
<tt:Bitrate>64000</tt:Bitrate>
<tt:SampleRate>8000</tt:SampleRate>
<tt:Multicast>
<tt:Address>
<tt:Type>IPv4</tt:Type>
<tt:IPv4Address>192.168.1.202</tt:IPv4Address>
</tt:Address>
<tt:Port>80</tt:Port>
<tt:TTL>1</tt:TTL>
<tt:AutoStart>false</tt:AutoStart>
</tt:Multicast>
<tt:SessionTimeout>PT00H00M00.060S</tt:SessionTimeout>
</tt:AudioEncoderConfiguration>
</trt:Profiles>
</trt:GetProfilesResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetStreamUri" in request_text:
        logger.info("Handling GetStreamUri request")
        response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetStreamUriResponse>
<trt:MediaUri>
<tt:Uri>rtsp://{LOCAL_IP}:{RTSP_PORT}/stream</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
<tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
<tt:Timeout>PT60S</tt:Timeout>
</trt:MediaUri>
</trt:GetStreamUriResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetVideoSources" in request_text:
        logger.info("Handling GetVideoSources request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><trt:GetVideoSourcesResponse><trt:VideoSources token="VideoSourceMain"><tt:Framerate>25</tt:Framerate><tt:Resolution><tt:Width>640</tt:Width><tt:Height>480</tt:Height></tt:Resolution><tt:Imaging><tt:BacklightCompensation><tt:Mode>OFF</tt:Mode><tt:Level>0</tt:Level></tt:BacklightCompensation><tt:Brightness>69.0196075</tt:Brightness><tt:ColorSaturation>50.1960793</tt:ColorSaturation><tt:Contrast>50.1960793</tt:Contrast><tt:Focus><tt:AutoFocusMode>MANUAL</tt:AutoFocusMode><tt:DefaultSpeed>1</tt:DefaultSpeed><tt:NearLimit>1</tt:NearLimit><tt:FarLimit>10</tt:FarLimit></tt:Focus><tt:IrCutFilter>AUTO</tt:IrCutFilter><tt:Sharpness>50.1960793</tt:Sharpness><tt:WideDynamicRange><tt:Mode>OFF</tt:Mode><tt:Level>0</tt:Level></tt:WideDynamicRange><tt:WhiteBalance><tt:Mode>AUTO</tt:Mode><tt:CrGain>128</tt:CrGain><tt:CbGain>128</tt:CbGain></tt:WhiteBalance></tt:Imaging></trt:VideoSources></trt:GetVideoSourcesResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    elif "GetProfile" in request_text:
        logger.info("Handling GetProfile request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetProfileResponse>
<trt:Profile fixed="true" token="MainStream">
<tt:Name>MainStream</tt:Name>
<tt:VideoSourceConfiguration token="VideoSourceToken">
<tt:Name>VideoSourceConfig</tt:Name>
<tt:UseCount>2</tt:UseCount>
<tt:SourceToken>VideoSourceToken</tt:SourceToken>
<tt:Bounds height="1080" width="1920" y="0" x="0"/>
</tt:VideoSourceConfiguration>
<tt:AudioSourceConfiguration token="AudioSourceConfigToken">
<tt:Name>AudioSourceConfig</tt:Name>
<tt:UseCount>2</tt:UseCount>
<tt:SourceToken>AudioSourceToken</tt:SourceToken>
</tt:AudioSourceConfiguration>
<tt:VideoEncoderConfiguration token="VideoEncoderToken">
<tt:Name>VideoEncoderConfig</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:Encoding>H264</tt:Encoding>
<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>
<tt:Quality>4.000000</tt:Quality>
<tt:RateControl><tt:FrameRateLimit>25</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>4096</tt:BitrateLimit></tt:RateControl>
<tt:H264><tt:GovLength>50</tt:GovLength><tt:H264Profile>Main</tt:H264Profile></tt:H264>
<tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast>
<tt:SessionTimeout>PT60S</tt:SessionTimeout>
</tt:VideoEncoderConfiguration>
<tt:AudioEncoderConfiguration token="AudioEncoderConfigToken">
<tt:Name>AudioEncoderConfig</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:Encoding>G711</tt:Encoding>
<tt:Bitrate>64</tt:Bitrate>
<tt:SampleRate>8</tt:SampleRate>
<tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast>
<tt:SessionTimeout>PT60S</tt:SessionTimeout>
</tt:AudioEncoderConfiguration>
<tt:PTZConfiguration token="PTZConfigurationToken">
<tt:Name>PTZConfiguration</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:NodeToken>PTZNodeToken</tt:NodeToken>
<tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
<tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
<tt:DefaultRelativePanTiltTranslationSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:DefaultRelativePanTiltTranslationSpace>
<tt:DefaultRelativeZoomTranslationSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:DefaultRelativeZoomTranslationSpace>
<tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
<tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
<tt:DefaultPTZSpeed><tt:PanTilt space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace" y="1.000000" x="1.000000"/><tt:Zoom space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace" x="1.000000"/></tt:DefaultPTZSpeed>
<tt:DefaultPTZTimeout>PT5S</tt:DefaultPTZTimeout>
<tt:PanTiltLimits><tt:Range><tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:URI><tt:XRange><tt:Min>-1.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:XRange><tt:YRange><tt:Min>-1.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits>
<tt:ZoomLimits><tt:Range><tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:URI><tt:XRange><tt:Min>0.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:XRange></tt:Range></tt:ZoomLimits>
</tt:PTZConfiguration>
</trt:Profile>
</trt:GetProfileResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetVideoSourceConfiguration" in request_text:
        logger.info("Handling GetVideoSourceConfiguration request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetVideoSourceConfigurationResponse>
<trt:Configuration token="VideoSourceToken">
<tt:Name>VideoSourceConfig</tt:Name>
<tt:UseCount>2</tt:UseCount>
<tt:SourceToken>VideoSourceToken</tt:SourceToken>
<tt:Bounds height="1080" width="1920" y="0" x="0"/>
</trt:Configuration>
</trt:GetVideoSourceConfigurationResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    elif "GetVideoEncoderConfigurationOptions" in request_text:
        logger.info("Handling GetVideoEncoderConfigurationOptions request")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><trt:GetVideoEncoderConfigurationOptionsResponse><trt:Options><tt:QualityRange><tt:Min>10</tt:Min><tt:Max>100</tt:Max></tt:QualityRange><tt:H264><tt:ResolutionsAvailable><tt:Width>640</tt:Width><tt:Height>480</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>2304</tt:Width><tt:Height>1296</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1280</tt:Width><tt:Height>720</tt:Height></tt:ResolutionsAvailable><tt:GovLengthRange><tt:Min>1</tt:Min><tt:Max>200</tt:Max></tt:GovLengthRange><tt:FrameRateRange><tt:Min>1</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:EncodingIntervalRange><tt:Min>1</tt:Min><tt:Max>1</tt:Max></tt:EncodingIntervalRange><tt:H264ProfilesSupported>Baseline</tt:H264ProfilesSupported><tt:H264ProfilesSupported>Main</tt:H264ProfilesSupported><tt:H264ProfilesSupported>High</tt:H264ProfilesSupported></tt:H264><tt:Extension><tt:H264><tt:GovLengthRange xsi:nil="true"/><tt:FrameRateRange xsi:nil="true"/><tt:EncodingIntervalRange xsi:nil="true"/><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>9216</tt:Max></tt:BitrateRange><tt:ResolutionsAvailable><tt:Width>640</tt:Width><tt:Height>480</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>25</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>8192</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>2304</tt:Width><tt:Height>1296</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>8192</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>9216</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1280</tt:Width><tt:Height>720</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>6144</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable></tt:H264></tt:Extension></trt:Options></trt:GetVideoEncoderConfigurationOptionsResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    else:
        logger.warning(f"Unsupported media service request. Request contains: {[op for op in ['GetProfiles', 'GetProfile', 'GetStreamUri', 'GetVideoSources', 'GetVideoSourceConfiguration', 'GetVideoEncoderConfigurationOptions'] if op in request_text]}")
        logger.warning(f"Checked for: GetProfiles, GetProfile, GetStreamUri, GetVideoSources, GetVideoSourceConfiguration, GetVideoEncoderConfigurationOptions")
        response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
<SOAP-ENV:Body>
<SOAP-ENV:Fault>
<SOAP-ENV:Code><SOAP-ENV:Value>SOAP-ENV:Receiver</SOAP-ENV:Value></SOAP-ENV:Code>
<SOAP-ENV:Reason><SOAP-ENV:Text>Action not supported</SOAP-ENV:Text></SOAP-ENV:Reason>
</SOAP-ENV:Fault>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    # Extract SOAP action from request for proper Content-Type header
    soap_action = extract_soap_action(request_text)
    return create_onvif_response(response_body, soap_action)

async def handle_media(request):
    """Handle requests to the /onvif/media endpoint"""
    try:
        request_text = await request.text()
        logger.info("Received POST request to /onvif/media")
        logger.debug(f"Request content preview: {request_text[:200]}...")
        
        # Extract SOAP action for proper response headers
        soap_action = extract_soap_action(request_text)
        
        if "GetVideoSources" in request_text:
            logger.info("Handling GetVideoSources request on /onvif/media")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetVideoSourcesResponse>
<trt:VideoSources token="VideoSourceToken">
<tt:Framerate>25</tt:Framerate>
<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>
</trt:VideoSources>
</trt:GetVideoSourcesResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetProfiles" in request_text:
            logger.info("Handling GetProfiles request on /onvif/media")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetProfilesResponse>
<trt:Profiles fixed="true" token="MainStream">
<tt:Name>MainStream</tt:Name>
<tt:VideoSourceConfiguration token="VideoSourceToken">
<tt:Name>VideoSourceConfig</tt:Name>
<tt:UseCount>2</tt:UseCount>
<tt:SourceToken>VideoSourceToken</tt:SourceToken>
<tt:Bounds height="1080" width="1920" y="0" x="0"/>
</tt:VideoSourceConfiguration>
<tt:AudioSourceConfiguration token="AudioSourceConfigToken">
<tt:Name>AudioSourceConfig</tt:Name>
<tt:UseCount>2</tt:UseCount>
<tt:SourceToken>AudioSourceToken</tt:SourceToken>
</tt:AudioSourceConfiguration>
<tt:VideoEncoderConfiguration token="VideoEncoderToken">
<tt:Name>VideoEncoderConfig</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:Encoding>H264</tt:Encoding>
<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>
<tt:Quality>4.000000</tt:Quality>
<tt:RateControl><tt:FrameRateLimit>25</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>4096</tt:BitrateLimit></tt:RateControl>
<tt:H264><tt:GovLength>50</tt:GovLength><tt:H264Profile>Main</tt:H264Profile></tt:H264>
<tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast>
<tt:SessionTimeout>PT60S</tt:SessionTimeout>
</tt:VideoEncoderConfiguration>
<tt:AudioEncoderConfiguration token="AudioEncoderConfigToken">
<tt:Name>AudioEncoderConfig</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:Encoding>G711</tt:Encoding>
<tt:Bitrate>64</tt:Bitrate>
<tt:SampleRate>8</tt:SampleRate>
<tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast>
<tt:SessionTimeout>PT60S</tt:SessionTimeout>
</tt:AudioEncoderConfiguration>
<tt:PTZConfiguration token="PTZConfigurationToken">
<tt:Name>PTZConfiguration</tt:Name>
<tt:UseCount>1</tt:UseCount>
<tt:NodeToken>PTZNodeToken</tt:NodeToken>
<tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
<tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
<tt:DefaultRelativePanTiltTranslationSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:DefaultRelativePanTiltTranslationSpace>
<tt:DefaultRelativeZoomTranslationSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:DefaultRelativeZoomTranslationSpace>
<tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
<tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
<tt:DefaultPTZSpeed><tt:PanTilt space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace" y="1.000000" x="1.000000"/><tt:Zoom space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace" x="1.000000"/></tt:DefaultPTZSpeed>
<tt:DefaultPTZTimeout>PT5S</tt:DefaultPTZTimeout>
<tt:PanTiltLimits><tt:Range><tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:URI><tt:XRange><tt:Min>-1.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:XRange><tt:YRange><tt:Min>-1.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits>
<tt:ZoomLimits><tt:Range><tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:URI><tt:XRange><tt:Min>0.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:XRange></tt:Range></tt:ZoomLimits>
</tt:PTZConfiguration>
</trt:Profiles>
</trt:GetProfilesResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetProfile" in request_text:
            logger.info("Handling GetProfile request")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
    <SOAP-ENV:Body>
    <trt:GetProfileResponse>
    <trt:Profile fixed="true" token="MainStream">
    <tt:Name>MainStream</tt:Name>
    <tt:VideoSourceConfiguration token="VideoSourceToken">
    <tt:Name>VideoSourceConfig</tt:Name>
    <tt:UseCount>2</tt:UseCount>
    <tt:SourceToken>VideoSourceToken</tt:SourceToken>
    <tt:Bounds height="1080" width="1920" y="0" x="0"/>
    </tt:VideoSourceConfiguration>
    <tt:AudioSourceConfiguration token="AudioSourceConfigToken">
    <tt:Name>AudioSourceConfig</tt:Name>
    <tt:UseCount>2</tt:UseCount>
    <tt:SourceToken>AudioSourceToken</tt:SourceToken>
    </tt:AudioSourceConfiguration>
    <tt:VideoEncoderConfiguration token="VideoEncoderToken">
    <tt:Name>VideoEncoderConfig</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:Encoding>H264</tt:Encoding>
    <tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>
    <tt:Quality>4.000000</tt:Quality>
    <tt:RateControl><tt:FrameRateLimit>25</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>4096</tt:BitrateLimit></tt:RateControl>
    <tt:H264><tt:GovLength>50</tt:GovLength><tt:H264Profile>Main</tt:H264Profile></tt:H264>
    <tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast>
    <tt:SessionTimeout>PT60S</tt:SessionTimeout>
    </tt:VideoEncoderConfiguration>
    <tt:AudioEncoderConfiguration token="AudioEncoderConfigToken">
    <tt:Name>AudioEncoderConfig</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:Encoding>G711</tt:Encoding>
    <tt:Bitrate>64</tt:Bitrate>
    <tt:SampleRate>8</tt:SampleRate>
    <tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast>
    <tt:SessionTimeout>PT60S</tt:SessionTimeout>
    </tt:AudioEncoderConfiguration>
    <tt:PTZConfiguration token="PTZConfigurationToken">
    <tt:Name>PTZConfiguration</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:NodeToken>PTZNodeToken</tt:NodeToken>
    <tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
    <tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
    <tt:DefaultRelativePanTiltTranslationSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:DefaultRelativePanTiltTranslationSpace>
    <tt:DefaultRelativeZoomTranslationSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:DefaultRelativeZoomTranslationSpace>
    <tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
    <tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
    <tt:DefaultPTZSpeed><tt:PanTilt space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace" y="1.000000" x="1.000000"/><tt:Zoom space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace" x="1.000000"/></tt:DefaultPTZSpeed>
    <tt:DefaultPTZTimeout>PT5S</tt:DefaultPTZTimeout>
    <tt:PanTiltLimits><tt:Range><tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:URI><tt:XRange><tt:Min>-1.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:XRange><tt:YRange><tt:Min>-1.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits>
    <tt:ZoomLimits><tt:Range><tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:URI><tt:XRange><tt:Min>0.000000</tt:Min><tt:Max>1.000000</tt:Max></tt:XRange></tt:Range></tt:ZoomLimits>
    </tt:PTZConfiguration>
    </trt:Profile>
    </trt:GetProfileResponse>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetVideoSourceConfigurations" in request_text:
            logger.info("Handling GetVideoSourceConfigurations request on /onvif/media")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><trt:GetVideoSourceConfigurationsResponse><trt:Configurations token="VideoSourceMain"><tt:Name>VideoSourceMain</tt:Name><tt:UseCount>2</tt:UseCount><tt:SourceToken>VideoSourceMain</tt:SourceToken><tt:Bounds x="0" y="0" width="640" height="480"></tt:Bounds></trt:Configurations></trt:GetVideoSourceConfigurationsResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetVideoSourceConfiguration" in request_text:
            logger.info("Handling GetVideoSourceConfiguration request")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetVideoSourceConfigurationResponse>
<trt:Configuration token="VideoSourceToken">
<tt:Name>VideoSourceConfig</tt:Name>
<tt:UseCount>2</tt:UseCount>
<tt:SourceToken>VideoSourceToken</tt:SourceToken>
<tt:Bounds height="1080" width="1920" y="0" x="0"/>
</trt:Configuration>
</trt:GetVideoSourceConfigurationResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetVideoEncoderConfigurations" in request_text:
            logger.info("Handling GetVideoEncoderConfigurations request on /onvif/media")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><trt:GetVideoEncoderConfigurationsResponse><trt:Configurations token="VideoEncodeMain"><tt:Name>VideoEncodeMain</tt:Name><tt:UseCount>2</tt:UseCount><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>640</tt:Width><tt:Height>480</tt:Height></tt:Resolution><tt:Quality>50</tt:Quality><tt:RateControl><tt:FrameRateLimit>30</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>4900</tt:BitrateLimit></tt:RateControl><tt:MPEG4><tt:GovLength>0</tt:GovLength><tt:Mpeg4Profile>SP</tt:Mpeg4Profile></tt:MPEG4><tt:H264><tt:GovLength>40</tt:GovLength><tt:H264Profile>High</tt:H264Profile></tt:H264><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>192.168.1.202</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>0</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT00H12M00S</tt:SessionTimeout></trt:Configurations><trt:Configurations token="VideoEncodeSub"><tt:Name>VideoEncodeSub</tt:Name><tt:UseCount>2</tt:UseCount><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>640</tt:Width><tt:Height>360</tt:Height></tt:Resolution><tt:Quality>50</tt:Quality><tt:RateControl><tt:FrameRateLimit>25</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>500</tt:BitrateLimit></tt:RateControl><tt:MPEG4><tt:GovLength>0</tt:GovLength><tt:Mpeg4Profile>SP</tt:Mpeg4Profile></tt:MPEG4><tt:H264><tt:GovLength>40</tt:GovLength><tt:H264Profile>High</tt:H264Profile></tt:H264><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>192.168.1.202</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>0</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT00H12M00S</tt:SessionTimeout></trt:Configurations></trt:GetVideoEncoderConfigurationsResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetVideoEncoderConfigurationOptions" in request_text:
            logger.info("Handling GetVideoEncoderConfigurationOptions request on /onvif/media")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><trt:GetVideoEncoderConfigurationOptionsResponse><trt:Options><tt:QualityRange><tt:Min>10</tt:Min><tt:Max>100</tt:Max></tt:QualityRange><tt:H264><tt:ResolutionsAvailable><tt:Width>640</tt:Width><tt:Height>480</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>2304</tt:Width><tt:Height>1296</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1280</tt:Width><tt:Height>720</tt:Height></tt:ResolutionsAvailable><tt:GovLengthRange><tt:Min>1</tt:Min><tt:Max>200</tt:Max></tt:GovLengthRange><tt:FrameRateRange><tt:Min>1</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:EncodingIntervalRange><tt:Min>1</tt:Min><tt:Max>1</tt:Max></tt:EncodingIntervalRange><tt:H264ProfilesSupported>Baseline</tt:H264ProfilesSupported><tt:H264ProfilesSupported>Main</tt:H264ProfilesSupported><tt:H264ProfilesSupported>High</tt:H264ProfilesSupported></tt:H264><tt:Extension><tt:H264><tt:GovLengthRange xsi:nil="true"/><tt:FrameRateRange xsi:nil="true"/><tt:EncodingIntervalRange xsi:nil="true"/><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>9216</tt:Max></tt:BitrateRange><tt:ResolutionsAvailable><tt:Width>640</tt:Width><tt:Height>480</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>25</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>8192</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>2304</tt:Width><tt:Height>1296</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>8192</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>9216</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable><tt:ResolutionsAvailable><tt:Width>1280</tt:Width><tt:Height>720</tt:Height><tt:FrameRateRange><tt:Min>8</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange><tt:BitrateRange><tt:Min>512</tt:Min><tt:Max>6144</tt:Max></tt:BitrateRange></tt:ResolutionsAvailable></tt:H264></tt:Extension></trt:Options></trt:GetVideoEncoderConfigurationOptionsResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetStreamUri" in request_text:
            logger.info("Handling GetStreamUri request on /onvif/media")
            response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:GetStreamUriResponse>
<trt:MediaUri>
<tt:Uri>rtsp://{LOCAL_IP}:{RTSP_PORT}/stream</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
<tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
<tt:Timeout>PT0S</tt:Timeout>
</trt:MediaUri>
</trt:GetStreamUriResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "SetVideoEncoderConfiguration" in request_text:
            logger.info("Handling SetVideoEncoderConfiguration request on /onvif/media")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics">
<SOAP-ENV:Body>
<trt:SetVideoEncoderConfigurationResponse>
</trt:SetVideoEncoderConfigurationResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        elif "GetVideoEncoderConfiguration" in request_text and "GetVideoEncoderConfigurations" not in request_text:
            logger.info("Handling GetVideoEncoderConfiguration request on /onvif/media")
            response_body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tdn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:trt2="http://www.onvif.org/ver20/media/wsdl" xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tplt="http://www.onvif.org/ver10/plus/schema" xmlns:tpl="http://www.onvif.org/ver10/plus/wsdl" xmlns:ewsd="http://www.onvifext.com/onvif/ext/ver10/wsdl" xmlns:exsd="http://www.onvifext.com/onvif/ext/ver10/schema" xmlns:tnshik="http://www.hikvision.com/2011/event/topics"><SOAP-ENV:Body><trt:GetVideoEncoderConfigurationResponse><trt:Configuration token="VideoEncodeMain"><tt:Name>VideoEncodeMain</tt:Name><tt:UseCount>1</tt:UseCount><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>640</tt:Width><tt:Height>480</tt:Height></tt:Resolution><tt:Quality>50</tt:Quality><tt:RateControl><tt:FrameRateLimit>30</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>4900</tt:BitrateLimit></tt:RateControl><tt:MPEG4><tt:GovLength>0</tt:GovLength><tt:Mpeg4Profile>SP</tt:Mpeg4Profile></tt:MPEG4><tt:H264><tt:GovLength>40</tt:GovLength><tt:H264Profile>High</tt:H264Profile></tt:H264><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>192.168.1.202</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>0</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT00H12M00S</tt:SessionTimeout></trt:Configuration></trt:GetVideoEncoderConfigurationResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            return create_onvif_response(response_body, soap_action)
        else:

            #Return a SOAP fault for unsupported operations
            fault_response = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
    <SOAP-ENV:Body>
        <SOAP-ENV:Fault>
            <SOAP-ENV:Code>
                <SOAP-ENV:Value>SOAP-ENV:Sender</SOAP-ENV:Value>
            </SOAP-ENV:Code>
            <SOAP-ENV:Reason>
                <SOAP-ENV:Text>Action not supported</SOAP-ENV:Text>
            </SOAP-ENV:Reason>
        </SOAP-ENV:Fault>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
            return create_onvif_response(fault_response, soap_action)
            
    except Exception as e:
        logger.error(f"Error handling /onvif/media request: {str(e)}")
        fault_response = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
    <SOAP-ENV:Body>
        <SOAP-ENV:Fault>
            <SOAP-ENV:Code>
                <SOAP-ENV:Value>SOAP-ENV:Receiver</SOAP-ENV:Value>
            </SOAP-ENV:Code>
            <SOAP-ENV:Reason>
                <SOAP-ENV:Text>Internal error</SOAP-ENV:Text>
            </SOAP-ENV:Reason>
        </SOAP-ENV:Fault>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        return create_onvif_response(fault_response, "")

async def init_app():
    """Initialize the aiohttp application"""
    app = web.Application()

    # Device service endpoints
    app.router.add_post('/onvif/device_service', handle_device_service)

    # Media service endpoints
    app.router.add_post('/onvif/media_service', handle_media_service)
    app.router.add_post('/onvif/media', handle_media)

    # Unsupported routes
    app.router.add_route('*', '/{tail:.*}', handle_unsupported_route)

    return app

async def main():
    """Main entry point"""
    logger.info("Starting ONVIF Camera Emulator...")
    
    # Start WS-Discovery service
    discovery_handler = WSDiscoveryHandler()
    await discovery_handler.start()
    
    # Start HTTP server
    app = await init_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, ONVIF_SERVER_HOST, ONVIF_SERVER_PORT)
    
    try:
        await site.start()
        logger.info(f"ONVIF server running at http://{ONVIF_SERVER_HOST}:{ONVIF_SERVER_PORT}")
        logger.info(f"Device UUID: {DEVICE_UUID}")
        logger.info(f"Local IP: {get_local_ip()}")
        
        # Keep the server running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        discovery_handler.stop()
        await runner.cleanup()

if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="ONVIF Camera Emulator")
    parser.add_argument('--onvif-port', type=int, default=int(os.environ.get('ONVIF_PORT', 8000)),
                        help='ONVIF server port')
    parser.add_argument('--local-ip', type=str, default=os.environ.get('LOCAL_IP', '192.168.1.155'),
                        help='Local IP address')
    parser.add_argument('--rtsp-port', type=int, default=int(os.environ.get('RTSP_PORT', 8554)),
                        help='RTSP server port')
    parser.add_argument('--video-width', type=int, default=int(os.environ.get('VIDEO_WIDTH', 1280)),
                        help='Video width in pixels')
    parser.add_argument('--video-height', type=int, default=int(os.environ.get('VIDEO_HEIGHT', 720)),
                        help='Video height in pixels')
    parser.add_argument('--video-framerate', type=int, default=int(os.environ.get('VIDEO_FRAMERATE', 25)),
                        help='Video frame rate in fps')
    args = parser.parse_args()

    # Update global configuration
    ONVIF_SERVER_PORT = args.onvif_port
    LOCAL_IP = args.local_ip
    RTSP_PORT = args.rtsp_port
    VIDEO_WIDTH = args.video_width
    VIDEO_HEIGHT = args.video_height
    VIDEO_FRAMERATE = args.video_framerate

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")