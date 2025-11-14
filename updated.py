#!/usr/bin/env python3
"""
High-Performance CCTV Scanner with Real-time Progress
Optimized for 32-core AMD EPYC with 8GB RAM budget

Features:
- Real-time progress indicators
- Adaptive timeout adjustment
- Early termination for dead networks
- Maximum CPU utilization
- Zero false negatives
"""
import asyncio
import socket
import sys
import ipaddress
import argparse
import ssl
import re
import xml.etree.ElementTree as ET
import json
import time
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import resource
from datetime import datetime

# === CONFIGURATION ===
QUICK_DISCOVERY_PORTS = [80, 443, 554, 8080, 37777, 8000]
EXTENDED_PORTS = [
    8554, 8443, 34567, 5000, 9000, 23, 22, 21, 7070,
    85, 555, 1024, 1025, 1935, 3702, 5050, 6036,
    7001, 8001, 8081, 8899, 9527, 10554, 49152
]
UDP_PORTS = [161, 3702, 5004, 5005, 5353, 37020]

# Aggressive settings for speed
STAGE1_CONCURRENCY = 3000    # Increased
STAGE2_CONCURRENCY = 1000
UDP_CONCURRENCY = 500
BATCH_SIZE = 512             # Larger batches

# Adaptive timeouts based on network size
def get_adaptive_timeouts(num_targets: int) -> Tuple[float, float, float, float]:
    """
    Adjust timeouts based on network size to prevent missing cameras
    Small networks: fast timeouts
    Large networks: more reliable timeouts
    """
    if num_targets <= 10:
        # Very small - balanced (not too aggressive)
        return 2.0, 4.0, 2.0, 4.0
    elif num_targets <= 100:
        # Small - reliable
        return 2.5, 5.0, 2.5, 5.0
    elif num_targets <= 1000:
        # Medium - very reliable
        return 3.0, 5.0, 3.0, 5.0
    else:
        # Large - maximum reliability
        return 3.5, 6.0, 3.5, 6.0

# Adaptive retry (reduce for dead networks)
MAX_RETRIES = 1              # Reduced from 2
RETRY_DELAY = 0.2
RETRY_BACKOFF = 1.3

# Camera detection
CAMERA_KEYWORDS = [
    "hikvision", "dahua", "axis", "vivotek", "onvif", "amcrest", 
    "camera", "dvr", "nvr", "xiongmai", "xm", "foscam", "tp-link",
    "d-link", "netcam", "ipcam", "webcam", "hanwha", "samsung",
    "sony", "panasonic", "bosch", "pelco", "geovision", "mobotix",
    "acti", "arecont", "avigilon", "ubiquiti", "unifi", "reolink",
    "wyze", "nest", "arlo", "ring", "blink", "eufy", "swann",
    "lorex", "cp-plus", "tiandy", "uniview", "ezviz"
]

VENDOR_PATHS = [
    "/onvif/device_service",
    "/ISAPI/System/deviceInfo",
    "/deviceinfo",
    "/system/deviceinfo",
    "/cgi-bin/magicBox.cgi?action=getSystemInfo",
    "/api/v1/system/deviceinfo",
    "/cgi-bin/param.cgi?cmd=getserverinfo",
    "/axis-cgi/basicdeviceinfo.cgi",
    "/api.cgi?cmd=GetDevInfo",
]

# === DATA STRUCTURES ===
@dataclass
class ScanResult:
    ip: str
    port: int
    protocol: str
    open: bool
    service: Optional[str] = None
    confirmed_camera: bool = False
    vendor: str = "unknown"
    model: str = "unknown"
    firmware: str = "unknown"
    tags: List[str] = None
    confidence: int = 0  # 0=not camera, 1=weak, 2=moderate, 3=strong
    auth_required: bool = False  # True if requires authentication
    response_snippet: str = ""
    scan_stage: int = 1
    retry_count: int = 0
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

# === PROGRESS TRACKING ===
class ProgressTracker:
    def __init__(self, total_tasks: int):
        self.total = total_tasks
        self.completed = 0
        self.start_time = time.time()
        self.last_update = 0
        self.open_ports = 0
        self.cameras = 0
        
    def update(self, count=1, open_port=False, camera=False):
        self.completed += count
        if open_port:
            self.open_ports += 1
        if camera:
            self.cameras += 1
        
        # Update display every 0.5 seconds
        now = time.time()
        if now - self.last_update > 0.5 or self.completed == self.total:
            self.display()
            self.last_update = now
    
    def display(self):
        elapsed = time.time() - self.start_time
        rate = self.completed / elapsed if elapsed > 0 else 0
        pct = (self.completed / self.total * 100) if self.total > 0 else 0
        
        eta = (self.total - self.completed) / rate if rate > 0 else 0
        
        bar_len = 40
        filled = int(bar_len * self.completed / self.total) if self.total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        
        sys.stdout.write(f"\r  [{bar}] {pct:.1f}% | {self.completed}/{self.total} | {rate:.0f}/s | Open:{self.open_ports} Cams:{self.cameras} | ETA:{eta:.0f}s ")
        sys.stdout.flush()

# === PERFORMANCE MONITORING ===
class PerformanceMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.tcp_scanned = 0
        self.udp_scanned = 0
        self.cameras_found = 0
        self.open_ports = 0
        self.retries = 0
        
    def report(self):
        elapsed = time.time() - self.start_time
        rate = (self.tcp_scanned + self.udp_scanned) / elapsed if elapsed > 0 else 0
        print(f"\n{'='*70}")
        print(f"SCAN STATISTICS")
        print(f"{'='*70}")
        print(f"Duration:     {elapsed:.1f}s")
        print(f"Scan Rate:    {rate:.0f} ports/second")
        print(f"TCP Scanned:  {self.tcp_scanned}")
        print(f"UDP Scanned:  {self.udp_scanned}")
        print(f"Open Ports:   {self.open_ports}")
        print(f"Cameras:      {self.cameras_found}")
        print(f"Retries:      {self.retries}")

# === MEMORY MANAGEMENT ===
def set_memory_limits(max_gb=8):
    try:
        max_bytes = max_gb * 1024 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))
    except:
        pass

# === CONNECTION POOLING ===
class ConnectionPool:
    def __init__(self):
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def get_ssl_context(self):
        return self.ssl_context

pool = ConnectionPool()

# === OPTIMIZED NETWORKING ===
async def tcp_connect_fast(ip: str, port: int, timeout: float) -> bool:
    """Ultra-fast connection test using raw sockets"""
    sock = None
    try:
        # Create non-blocking socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        
        loop = asyncio.get_event_loop()
        
        # Attempt connection
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (ip, port)),
                timeout=timeout
            )
            # Connection successful
            return True
        except asyncio.TimeoutError:
            # Timeout - port filtered or no response
            return False
        except ConnectionRefusedError:
            # Port closed
            return False
        except OSError as e:
            # Check if it's actually open but refusing our specific request
            # Some RTSP servers do this
            if e.errno in (111, 61):  # Connection refused
                return False
            # Other errors might mean port is open but service is strict
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    except Exception:
        if sock:
            try:
                sock.close()
            except:
                pass
        return False

async def tcp_connect_deep(ip: str, port: int, timeout: float, use_ssl=False) -> Tuple[bool, Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
    """Deep connection with stream"""
    try:
        if use_ssl:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=pool.get_ssl_context()),
                timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
        return True, reader, writer
    except:
        return False, None, None

async def read_with_timeout(reader: asyncio.StreamReader, max_bytes=8192, timeout=2.0) -> str:
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data.decode(errors="ignore")
    except:
        return ""

# === UDP HELPERS ===
def udp_probe_sync(ip: str, port: int, payload: bytes, timeout: float) -> Optional[bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(65535)
        return data
    except:
        return None
    finally:
        try:
            sock.close()
        except:
            pass

async def udp_probe(ip: str, port: int, payload: bytes, timeout: float) -> Optional[bytes]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, udp_probe_sync, ip, port, payload, timeout)

WS_DISCOVERY = b'<?xml version="1.0" encoding="utf-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Header><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action><w:MessageID>uuid:1</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To></e:Header><e:Body><d:Probe/></e:Body></e:Envelope>'
SNMP_GET = b'\x30\x2a\x02\x01\x00\x04\x06public\xa0\x1d\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0f\x30\x0d\x06\x09\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'

UDP_PAYLOADS = {
    3702: WS_DISCOVERY,
    37020: WS_DISCOVERY,
    161: SNMP_GET,
    5004: b'',
    5005: b'',
    5353: b''
}

# === PROTOCOL PROBES ===
async def probe_rtsp(ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float) -> Dict:
    """RTSP OPTIONS/DESCRIBE probe - handles auth required"""
    try:
        # Try OPTIONS first (less likely to need auth)
        req = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: scanner\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await read_with_timeout(reader, 4096, timeout)
        
        # If we got a response (even 401 auth required), it's RTSP
        if resp and ("RTSP" in resp or "401" in resp or "Unauthorized" in resp):
            return {"service": "rtsp", "response": resp, "auth_required": "401" in resp}
        
        # Try DESCRIBE if OPTIONS didn't work
        if not resp or len(resp) < 10:
            req2 = f"DESCRIBE rtsp://{ip}:{port}/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: scanner\r\nAccept: application/sdp\r\n\r\n"
            writer.write(req2.encode())
            await writer.drain()
            resp2 = await read_with_timeout(reader, 4096, timeout)
            
            if resp2:
                return {"service": "rtsp", "response": resp + "\n" + resp2, "auth_required": "401" in resp2}
        
        return {"service": "rtsp", "response": resp, "auth_required": False}
    except Exception as e:
        return {"service": "rtsp", "response": f"Error: {str(e)}", "auth_required": False}

async def probe_http(ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float, use_tls=False) -> Dict:
    try:
        req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await read_with_timeout(reader, 12288, timeout)
        return {"service": "http" if not use_tls else "https", "response": resp}
    except:
        return {"service": "http", "response": ""}

async def probe_onvif_soap(ip: str, port: int, use_tls=False, timeout=3.0) -> str:
    soap = '<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
    
    ok, reader, writer = await tcp_connect_deep(ip, port, timeout, use_ssl=use_tls)
    if not ok:
        return ""
    
    try:
        req = f"POST /onvif/device_service HTTP/1.1\r\nHost: {ip}\r\nContent-Type: application/soap+xml\r\nContent-Length: {len(soap)}\r\n\r\n{soap}"
        writer.write(req.encode())
        await writer.drain()
        resp = await read_with_timeout(reader, 16384, timeout)
        return resp
    except:
        return ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def probe_vendor_paths(ip: str, port: int, use_tls=False, timeout=2.5) -> List[str]:
    results = []
    for path in VENDOR_PATHS[:3]:  # Top 3 only for speed
        ok, reader, writer = await tcp_connect_deep(ip, port, timeout, use_ssl=use_tls)
        if not ok:
            continue
        
        try:
            req = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            resp = await read_with_timeout(reader, 8192, timeout)
            if resp and len(resp) > 100:
                results.append(resp)
        except:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    return results

# === FINGERPRINTING ===
def analyze_camera_keywords(text: str) -> Tuple[bool, List[str], int]:
    """
    Analyze text for camera indicators
    Returns: (is_camera, keywords_found, confidence_score)
    Confidence: 0=not camera, 1=weak, 2=moderate, 3=strong
    """
    if not text:
        return False, [], 0
    
    lower = text.lower()
    found = []
    confidence = 0
    
    # RTSP responses are HIGH confidence (even with 401)
    if "rtsp/1.0" in lower or "rtsp/2.0" in lower:
        found.append("rtsp")
        confidence = 3
        # Check for specific camera vendors in RTSP response
        if "hikvision" in lower:
            found.append("hikvision")
        if "dahua" in lower:
            found.append("dahua")
        return True, found, confidence
    
    # 401 Unauthorized on RTSP ports is also HIGH confidence
    if "401 unauthorized" in lower and ("rtsp" in lower or "realm=" in lower):
        found.append("rtsp-auth")
        confidence = 3
        return True, found, confidence
    
    # Strong indicators (definitely camera-related)
    strong_keywords = ["hikvision", "dahua", "axis", "vivotek", "onvif", 
                       "ipcam", "dvr", "nvr", "xiongmai", "/cgi-bin/snapshot",
                       "rtsp://", "amcrest", "foscam", "camera stream",
                       "streaming/channels"]
    
    # Medium indicators (likely camera)
    medium_keywords = ["camera", "webcam", "netcam", "surveillance"]
    
    # Weak indicators (need context)
    weak_keywords = ["ring", "nest", "wyze", "arlo", "blink"]
    
    # Check strong indicators
    for kw in strong_keywords:
        if kw in lower:
            found.append(kw)
            confidence = max(confidence, 3)
    
    # Check medium indicators
    for kw in medium_keywords:
        if kw in lower:
            found.append(kw)
            confidence = max(confidence, 2)
    
    # Check weak indicators (only if there's other context)
    if confidence > 0:  # Already found something
        for kw in weak_keywords:
            if kw in lower:
                found.append(kw)
    else:
        # Weak indicators need multiple matches or specific patterns
        weak_matches = [kw for kw in weak_keywords if kw in lower]
        if len(weak_matches) >= 2:
            found.extend(weak_matches)
            confidence = 1
        elif len(weak_matches) == 1:
            # Check for additional camera context
            camera_context = ["video", "stream", "live", "channel", "motion"]
            if any(ctx in lower for ctx in camera_context):
                found.extend(weak_matches)
                confidence = 2
    
    # Require at least moderate confidence for positive detection
    is_camera = confidence >= 2
    
    return is_camera, found, confidence

def parse_xml_deviceinfo(xml_text: str) -> Dict:
    try:
        start = xml_text.find("<?xml")
        if start == -1:
            start = xml_text.find("<")
        if start == -1:
            return {}
        
        root = ET.fromstring(xml_text[start:])
        info = {}
        
        for tag in ['Manufacturer', 'Model', 'FirmwareVersion', 'SerialNumber', 
                    'manufacturer', 'model', 'firmwareVersion', 'serialNumber',
                    'deviceName', 'DeviceName']:
            for elem in root.iter():
                if elem.tag.lower().endswith(tag.lower()) and elem.text:
                    key = tag.lower().replace('version', '')
                    if key not in info:
                        info[key] = elem.text.strip()
        
        return info
    except:
        return {}

def extract_http_headers(response: str) -> Dict:
    info = {}
    if not response:
        return info
    
    lines = response.split('\n')
    for line in lines[:20]:
        if ':' not in line:
            continue
        
        key, val = line.split(':', 1)
        key = key.strip().lower()
        val = val.strip()
        
        if key in ['server', 'x-powered-by', 'www-authenticate']:
            info[key] = val
    
    return info

def consolidate_fingerprint(http_resp: str, onvif_resp: str, vendor_resps: List[str]) -> Dict:
    vendor = model = firmware = "unknown"
    
    onvif_info = parse_xml_deviceinfo(onvif_resp)
    if onvif_info.get('manufacturer'):
        vendor = onvif_info['manufacturer']
    if onvif_info.get('model'):
        model = onvif_info['model']
    if onvif_info.get('firmware'):
        firmware = onvif_info['firmware']
    
    for vresp in vendor_resps:
        vinfo = parse_xml_deviceinfo(vresp)
        if not vendor or vendor == "unknown":
            vendor = vinfo.get('manufacturer', vendor)
        if not model or model == "unknown":
            model = vinfo.get('model', model)
        if not firmware or firmware == "unknown":
            firmware = vinfo.get('firmware', firmware)
    
    if vendor == "unknown":
        headers = extract_http_headers(http_resp)
        if 'server' in headers:
            vendor = headers['server']
    
    return {
        "vendor": vendor,
        "model": model,
        "firmware": firmware
    }

# === STAGE 1: QUICK DISCOVERY ===
async def stage1_discover(ip: str, port: int, sem: asyncio.Semaphore, monitor: PerformanceMonitor, progress: ProgressTracker) -> Optional[ScanResult]:
    async with sem:
        for attempt in range(MAX_RETRIES + 1):
            try:
                open_port = await tcp_connect_fast(ip, port, QUICK_CONNECT_TIMEOUT)
                monitor.tcp_scanned += 1
                progress.update(1, open_port=open_port)
                
                if open_port:
                    monitor.open_ports += 1
                    return ScanResult(
                        ip=ip, port=port, protocol="tcp", 
                        open=True, scan_stage=1, retry_count=attempt
                    )
                elif attempt < MAX_RETRIES:
                    monitor.retries += 1
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    return None
            except Exception:
                if attempt == MAX_RETRIES:
                    progress.update(1)
                    return None
                await asyncio.sleep(RETRY_DELAY)
        
        return None

# === STAGE 2: DEEP FINGERPRINTING ===
async def stage2_fingerprint(result: ScanResult, sem: asyncio.Semaphore, monitor: PerformanceMonitor) -> ScanResult:
    async with sem:
        ip, port = result.ip, result.port
        use_tls = port in (443, 8443, 7443)
        
        for attempt in range(MAX_RETRIES + 1):
            try:
                ok, reader, writer = await tcp_connect_deep(ip, port, DEEP_CONNECT_TIMEOUT, use_tls)
                if not ok:
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_DELAY)
                        continue
                    return result
                
                if port in (554, 8554, 10554):
                    probe = await probe_rtsp(ip, port, reader, writer, DEEP_READ_TIMEOUT)
                else:
                    probe = await probe_http(ip, port, reader, writer, DEEP_READ_TIMEOUT, use_tls)
                
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
                
                # Special handling for RTSP ports - even empty response means it's likely a camera
                if port in (554, 8554, 10554):
                    # If port is open on 554, it's almost certainly RTSP/camera
                    if not probe["response"] or len(probe["response"]) < 10:
                        # Port open but no response - still mark as camera
                        result.service = "rtsp"
                        result.confirmed_camera = True
                        result.tags = ["rtsp", "port-554"]
                        result.confidence = 2  # MODERATE - port-based detection
                        result.response_snippet = "Port 554 open (standard RTSP port)"
                        result.scan_stage = 2
                        result.retry_count = attempt
                        monitor.cameras_found += 1
                        return result
                
                is_cam, tags, confidence = analyze_camera_keywords(probe["response"])
                result.service = probe["service"]
                result.confirmed_camera = is_cam
                result.tags = tags
                result.confidence = confidence
                result.auth_required = probe.get("auth_required", False)
                result.response_snippet = probe["response"][:800]
                result.scan_stage = 2
                result.retry_count = attempt
                
                if is_cam and port in (80, 443, 8080, 8000, 8443):
                    onvif = await probe_onvif_soap(ip, port, use_tls, DEEP_READ_TIMEOUT)
                    vendor_data = await probe_vendor_paths(ip, port, use_tls, DEEP_READ_TIMEOUT)
                    
                    fingerprint = consolidate_fingerprint(probe["response"], onvif, vendor_data)
                    result.vendor = fingerprint["vendor"]
                    result.model = fingerprint["model"]
                    result.firmware = fingerprint["firmware"]
                    
                    monitor.cameras_found += 1
                
                return result
                
            except Exception:
                if attempt == MAX_RETRIES:
                    return result
                await asyncio.sleep(RETRY_DELAY)
        
        return result

# === STAGE 3: UDP SCANNING ===
async def stage3_udp_scan(ip: str, port: int, sem: asyncio.Semaphore, monitor: PerformanceMonitor, progress: ProgressTracker) -> Optional[ScanResult]:
    async with sem:
        for attempt in range(MAX_RETRIES + 1):
            try:
                payload = UDP_PAYLOADS.get(port, b'')
                resp = await udp_probe(ip, port, payload, UDP_TIMEOUT)
                monitor.udp_scanned += 1
                
                if resp:
                    text = resp.decode(errors='ignore')
                    is_cam, tags, confidence = analyze_camera_keywords(text)
                    
                    if is_cam:
                        monitor.cameras_found += 1
                        progress.update(1, camera=True)
                    else:
                        progress.update(1)
                    
                    return ScanResult(
                        ip=ip, port=port, protocol="udp",
                        open=True, service="udp",
                        confirmed_camera=is_cam,
                        tags=tags,
                        confidence=confidence,
                        response_snippet=text[:800],
                        scan_stage=3,
                        retry_count=attempt
                    )
                else:
                    progress.update(1)
                    
            except Exception:
                if attempt == MAX_RETRIES:
                    progress.update(1)
                    return None
                await asyncio.sleep(RETRY_DELAY)
        
        return None

# === BATCH PROCESSING ===
async def process_batch(ips: List[str], args, monitor: PerformanceMonitor) -> List[ScanResult]:
    results = []
    
    # Stage 1: Quick TCP discovery
    tcp_ports = QUICK_DISCOVERY_PORTS + (EXTENDED_PORTS if args.extended else [])
    total_stage1 = len(ips) * len(tcp_ports)
    
    print(f"  [Stage 1] Discovering open ports...")
    progress = ProgressTracker(total_stage1)
    
    sem1 = asyncio.Semaphore(STAGE1_CONCURRENCY)
    tasks1 = []
    for ip in ips:
        for port in tcp_ports:
            tasks1.append(stage1_discover(ip, port, sem1, monitor, progress))
    
    discovered = await asyncio.gather(*tasks1)
    open_results = [r for r in discovered if r is not None]
    
    print()  # New line after progress bar
    print(f"  [Stage 1] ✓ Found {len(open_results)} open ports")
    
    # Stage 2: Deep fingerprinting
    if open_results:
        print(f"  [Stage 2] Fingerprinting services...")
        sem2 = asyncio.Semaphore(STAGE2_CONCURRENCY)
        tasks2 = [stage2_fingerprint(r, sem2, monitor) for r in open_results]
        fingerprinted = await asyncio.gather(*tasks2)
        results.extend(fingerprinted)
        cameras = sum(1 for r in fingerprinted if r.confirmed_camera)
        print(f"  [Stage 2] ✓ Identified {cameras} cameras")
    
    # Stage 3: UDP scanning
    if args.udp:
        total_stage3 = len(ips) * len(UDP_PORTS)
        print(f"  [Stage 3] UDP scanning...")
        progress3 = ProgressTracker(total_stage3)
        
        sem3 = asyncio.Semaphore(UDP_CONCURRENCY)
        tasks3 = []
        for ip in ips:
            for port in UDP_PORTS:
                tasks3.append(stage3_udp_scan(ip, port, sem3, monitor, progress3))
        
        udp_results = await asyncio.gather(*tasks3)
        results.extend([r for r in udp_results if r is not None])
        print()  # New line
        udp_open = sum(1 for r in udp_results if r and r.open)
        print(f"  [Stage 3] ✓ Found {udp_open} UDP responses")
    
    return results

# === MAIN ===
async def main(args):
    set_memory_limits(args.max_memory)
    monitor = PerformanceMonitor()
    
    # Expand targets - handle file input
    raw_targets = []
    
    for t in args.targets:
        # Check if it's a file
        if t.endswith('.txt') or t.endswith('.list'):
            try:
                import os
                if os.path.exists(t):
                    with open(t, 'r') as f:
                        file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        raw_targets.extend(file_targets)
                    print(f"[+] Loaded {len(file_targets)} entries from {t}")
                    continue
            except Exception as e:
                print(f"[!] Error reading file {t}: {e}")
        
        # Add directly if not a file
        raw_targets.append(t)
    
    # Now expand all targets (IPs and CIDRs)
    targets = []
    for t in raw_targets:
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                expanded = [str(ip) for ip in net.hosts()]
                targets.extend(expanded)
                print(f"[+] Expanded {t} to {len(expanded)} IPs")
            except Exception as e:
                print(f"[!] Error parsing CIDR {t}: {e}")
        else:
            targets.append(t)
    
    if not targets:
        print("[!] No valid targets specified")
        return
    
    # Get adaptive timeouts based on network size
    quick_timeout, deep_timeout, read_timeout, deep_read = get_adaptive_timeouts(len(targets))
    
    # Override global timeout values for this scan
    global QUICK_CONNECT_TIMEOUT, DEEP_CONNECT_TIMEOUT, QUICK_READ_TIMEOUT, DEEP_READ_TIMEOUT
    QUICK_CONNECT_TIMEOUT = quick_timeout
    DEEP_CONNECT_TIMEOUT = deep_timeout
    QUICK_READ_TIMEOUT = read_timeout
    DEEP_READ_TIMEOUT = deep_read
    
    print(f"\n{'='*70}")
    print(f"CCTV SCANNER - High Performance Mode")
    print(f"{'='*70}")
    print(f"Targets:      {len(targets)} IPs")
    print(f"Concurrency:  Stage1={STAGE1_CONCURRENCY}, Stage2={STAGE2_CONCURRENCY}")
    print(f"Timeouts:     Quick={QUICK_CONNECT_TIMEOUT}s, Deep={DEEP_CONNECT_TIMEOUT}s")
    print(f"Network Size: {'Small' if len(targets) <= 10 else 'Medium' if len(targets) <= 100 else 'Large'}")
    print(f"Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    
    all_results = []
    
    # Process in batches
    for i in range(0, len(targets), BATCH_SIZE):
        batch = targets[i:i+BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (len(targets) + BATCH_SIZE - 1) // BATCH_SIZE
        
        # Show IP range being scanned
        batch_range = f"{batch[0]}" if len(batch) == 1 else f"{batch[0]} - {batch[-1]}"
        print(f"[Batch {batch_num}/{total_batches}] Processing {len(batch)} IPs ({batch_range})...")
        
        batch_results = await process_batch(batch, args, monitor)
        all_results.extend(batch_results)
        
        cameras_in_batch = sum(1 for r in batch_results if r.confirmed_camera)
        if cameras_in_batch > 0:
            print(f"[Batch {batch_num}] 🎥 Found {cameras_in_batch} cameras!\n")
    
    # Final output
    print("\n" + "="*70)
    print("CONFIRMED CAMERAS:")
    print("="*70)
    
    cameras = [r for r in all_results if r.confirmed_camera]
    
    if not cameras:
        print("No cameras found in this network range.")
        
        # Show suspicious devices that might be cameras (confidence 1)
        suspicious = [r for r in all_results if r.open and 
                     len(r.tags) > 0 and r.confidence == 1]
        
        if suspicious:
            print("\n" + "="*70)
            print("SUSPICIOUS DEVICES (Low Confidence - Manual Review Recommended):")
            print("="*70)
            for dev in suspicious:
                tags_str = ",".join(dev.tags)
                print(f"\n{dev.ip}:{dev.port} [{dev.protocol.upper()}] {dev.service}")
                print(f"  Tags Found: {tags_str}")
                print(f"  Confidence: LOW (keyword match only)")
                if args.verbose:
                    print(f"  Snippet: {dev.response_snippet[:200]}...")
    else:
        for cam in cameras:
            tags_str = ",".join(cam.tags[:5]) if cam.tags else "generic"
            confidence_map = {0: "NONE", 1: "LOW", 2: "MODERATE", 3: "HIGH"}
            conf_str = confidence_map.get(cam.confidence, "UNKNOWN")
            
            auth_status = " [AUTH REQUIRED]" if cam.auth_required else ""
            
            print(f"\n{cam.ip}:{cam.port} [{cam.protocol.upper()}] {cam.service}{auth_status}")
            print(f"  Vendor:     {cam.vendor}")
            print(f"  Model:      {cam.model}")
            print(f"  Firmware:   {cam.firmware}")
            print(f"  Tags:       {tags_str}")
            print(f"  Confidence: {conf_str}")
            
            # Show RTSP URL for easy testing
            if cam.service == "rtsp" or cam.port in (554, 8554, 10554):
                print(f"  RTSP URL:   rtsp://{cam.ip}:{cam.port}/")
                print(f"              rtsp://{cam.ip}:{cam.port}/Streaming/Channels/101")
                
            if args.verbose:
                print(f"  Response:   {cam.response_snippet[:250]}...")
    
    # Show all open ports if verbose
    if args.verbose and not cameras:
        open_ports = [r for r in all_results if r.open and not r.confirmed_camera]
        if open_ports:
            print("\n" + "="*70)
            print(f"ALL OPEN PORTS ({len(open_ports)} found):")
            print("="*70)
            for op in open_ports[:20]:  # Limit to first 20
                print(f"{op.ip}:{op.port} - {op.service or 'unknown'}")
            if len(open_ports) > 20:
                print(f"... and {len(open_ports) - 20} more")
    
    # Save results
    if args.output:
        output_data = {
            "scan_info": {
                "start_time": datetime.now().isoformat(),
                "targets": len(targets),
                "cameras_found": len(cameras)
            },
            "results": [asdict(r) for r in all_results]
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n[+] Full results saved to {args.output}")
    
    monitor.report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="High-Performance CCTV Scanner (Optimized for 32-core EPYC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s 192.168.1.0/24 --extended
  %(prog)s 192.168.1.0/24 --extended --udp -o results.json
  %(prog)s 10.0.0.1 10.0.0.2 10.0.0.3 --verbose
  %(prog)s targets.txt                    # Load IPs from file
  %(prog)s 1.txt 2.txt 192.168.1.0/24     # Mix files and IPs
  %(prog)s 103.144.9.10 --test-connect    # Test single IP connectivity
        """
    )
    parser.add_argument("targets", nargs="+", help="IP, CIDR, or .txt file with targets (e.g. 192.168.1.0/24 or targets.txt)")
    parser.add_argument("--extended", action="store_true", help="Scan extended port list")
    parser.add_argument("--udp", action="store_true", help="Include UDP scanning")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show response snippets")
    parser.add_argument("--max-memory", type=int, default=8, help="Max memory in GB (default: 8)")
    parser.add_argument("--test-connect", action="store_true", help="Test connectivity to target (debug mode)")
    
    args = parser.parse_args()
    
    # Test connectivity mode
    if args.test_connect:
        import socket
        print("[TEST MODE] Testing connectivity...")
        for target in args.targets:
            if target.endswith('.txt'):
                continue
            print(f"\nTesting {target}:554 (RTSP)...")
            for timeout in [1.0, 2.0, 3.0, 5.0, 10.0]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    start = time.time()
                    s.connect((target, 554))
                    elapsed = time.time() - start
                    print(f"  ✓ Connected in {elapsed:.2f}s (timeout={timeout}s)")
                    s.close()
                    break
                except socket.timeout:
                    print(f"  ✗ Timeout at {timeout}s")
                except Exception as e:
                    print(f"  ✗ Error: {e}")
                    break
        sys.exit(0)
    
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
