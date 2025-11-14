#!/usr/bin/env python3
"""
cctv_scanner_with_fingerprint.py
Async IP+port scanner with protocol probes for CCTV/webcams.
Adds vendor/model/firmware fingerprinting using:
 - ONVIF GetDeviceInformation (SOAP)
 - Common device info endpoints (Hikvision ISAPI, /deviceinfo)
 - HTTP headers and banner heuristics

Usage: python3 cctv_scanner_with_fingerprint.py 192.168.1.0/24
"""

import asyncio
import socket
import sys
import ipaddress
import argparse
import ssl
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple

# --- Configuration ---
PORTS = [80, 443, 554, 8554, 8000, 8080, 8443, 37777, 34567, 5000, 9000, 23, 22, 21, 7070]
CONCURRENCY = 400
CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 2.0
RETRY = 1

CAMERA_KEYWORDS = ["hikvision", "dahua", "axis", "vivotek", "onvif", "amcrest", "camera", "dvr", "nvr", "xiongmai", "xm"]

# Common info endpoints to try for model/firmware
DEVICE_INFO_PATHS = [
    "/onvif/device_service",
    "/ISAPI/System/deviceInfo",
    "/deviceinfo",
    "/system/deviceinfo",
    "/cgi-bin/admin/getparam",
    "/cgi-bin/viewer/video.jpg",
    "/cgi-bin/snapshot.cgi",
]

# --- Networking helpers ---
async def tcp_connect(ip: str, port: int, timeout=CONNECT_TIMEOUT, use_ssl=False) -> Tuple[bool, asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            coro = asyncio.open_connection(ip, port, ssl=ctx)
        else:
            coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        return True, reader, writer
    except Exception:
        return False, None, None

async def read_banner(reader: asyncio.StreamReader, max_bytes=4096, timeout=READ_TIMEOUT) -> str:
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data.decode(errors="ignore")
    except Exception:
        return ""

# --- Probes ---
async def probe_rtsp(ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Dict:
    path = f"rtsp://{ip}/"
    req = f"OPTIONS {path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: cctv-scanner\r\n\r\n"
    writer.write(req.encode())
    await writer.drain()
    resp = await read_banner(reader)
    return {"protocol":"rtsp", "response": resp}

async def probe_http(ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, use_tls=False, path='/', extra_headers=None) -> Dict:
    hdr_host = ip
    req = f"GET {path} HTTP/1.1\r\nHost: {hdr_host}\r\nUser-Agent: cctv-scanner\r\nConnection: close\r\n"
    if extra_headers:
        for k,v in extra_headers.items():
            req += f"{k}: {v}\r\n"
    req += "\r\n"
    writer.write(req.encode())
    await writer.drain()
    resp = await read_banner(reader, max_bytes=8192)
    return {"protocol":"https" if use_tls else "http", "response": resp}

async def probe_onvif_deviceinfo_http(ip: str, port: int, use_tls=False, path='/onvif/device_service') -> Dict:
    # Build SOAP request for GetDeviceInformation
    soap = ("<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
            "<s:Body>"
            "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>"
            "</s:Body></s:Envelope>")
    content_len = len(soap)
    headers = {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'Content-Length': str(content_len)
    }
    ok, reader, writer = await tcp_connect(ip, port, use_ssl=use_tls)
    if not ok:
        return {"ok": False, "response": ""}
    try:
        req = f"POST {path} HTTP/1.1\r\nHost: {ip}\r\n"
        for k,v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "Connection: close\r\n\r\n"
        writer.write(req.encode() + soap.encode())
        await writer.drain()
        resp = await read_banner(reader, max_bytes=16384)
        return {"ok": True, "response": resp}
    except Exception as e:
        return {"ok": False, "response": ""}
    finally:
        try:
            writer.close()
        except:
            pass

async def probe_device_info_http(ip: str, port: int, use_tls=False, path='/ISAPI/System/deviceInfo') -> Dict:
    ok, reader, writer = await tcp_connect(ip, port, use_ssl=use_tls)
    if not ok:
        return {"ok": False, "response": ""}
    try:
        req = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: cctv-scanner\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await read_banner(reader, max_bytes=16384)
        return {"ok": True, "response": resp}
    except Exception:
        return {"ok": False, "response": ""}
    finally:
        try:
            writer.close()
        except:
            pass

# --- Fingerprinting helpers ---

def analyze_response_for_camera(resp: str) -> Tuple[bool, List[str]]:
    found = []
    lower = (resp or "").lower()
    for kw in CAMERA_KEYWORDS:
        if kw in lower:
            found.append(kw)
    return (len(found) > 0), found


def parse_onvif_deviceinfo(xml_blob: str) -> Dict:
    # attempt to extract Manufacturer, Model, FirmwareVersion from SOAP or raw XML
    try:
        # try to find the XML portion in the HTTP response
        ix = xml_blob.find("<?xml")
        snippet = xml_blob if ix == -1 else xml_blob[ix:]
        root = ET.fromstring(snippet)
    except Exception:
        return {}
    ns = {'tds': 'http://www.onvif.org/ver10/device/wsdl'}
    info = {}
    # Try common tags
    for tag in ['Manufacturer', 'Model', 'FirmwareVersion', 'SerialNumber']:
        el = root.find('.//{' + ns['tds'] + '}' + tag) if ns['tds'] else root.find('.//' + tag)
        if el is not None and el.text:
            info[tag.lower()] = el.text
    # Fallback: search by tag name without namespace
    for tag in ['Manufacturer', 'Model', 'FirmwareVersion', 'SerialNumber']:
        if tag.lower() not in info:
            el = root.find('.//' + tag)
            if el is not None and el.text:
                info[tag.lower()] = el.text
    return info


def parse_generic_deviceinfo(xml_blob: str) -> Dict:
    # Some devices (e.g., Hikvision ISAPI) return simple XML like <DeviceInfo><model>..</model></DeviceInfo>
    try:
        ix = xml_blob.find("<?xml")
        snippet = xml_blob if ix == -1 else xml_blob[ix:]
        root = ET.fromstring(snippet)
    except Exception:
        return {}
    info = {}
    # Common element names
    mapping = {
        'model': 'model',
        'firmwareVersion': 'firmwareversion',
        'firmwareVersion'.lower(): 'firmwareversion',
        'firmware': 'firmware',
        'serialNumber': 'serialnumber',
        'manufacturer': 'manufacturer'
    }
    for child in root.iter():
        tag = child.tag.lower()
        # strip namespace
        if '}' in tag:
            tag = tag.split('}',1)[1]
        if tag in mapping and child.text:
            info[mapping[tag]] = child.text
    return info


def heuristics_from_banner_and_headers(resp: str) -> Dict:
    lower = (resp or "").lower()
    out = {}
    # Server header
    m = re.search(r"server:\s*([^\r\n]+)", lower)
    if m:
        out['server'] = m.group(1).strip()
    # Try vendor keywords
    for kw in CAMERA_KEYWORDS:
        if kw in lower and 'manufacturer' not in out:
            out['manufacturer'] = kw
    return out


def consolidate_info(probe_infos: List[Dict], banner_info: Dict) -> Dict:
    # Merge multiple sources, prefer explicit fields
    vendor = None
    model = None
    firmware = None
    for info in probe_infos:
        if not info:
            continue
        for k in ['manufacturer', 'model', 'firmwareversion', 'firmware']:
            if k in info and info[k]:
                val = info[k]
                if k == 'manufacturer' and not vendor:
                    vendor = val
                if k in ('model',) and not model:
                    model = val
                if k in ('firmwareversion','firmware') and not firmware:
                    firmware = val
    # fallback to banner heuristics
    if not vendor and banner_info.get('manufacturer'):
        vendor = banner_info['manufacturer']
    if not vendor and banner_info.get('server'):
        vendor = banner_info['server']
    return {"vendor": vendor or 'unknown', "model": model or 'unknown', "firmware": firmware or 'unknown'}

# --- Main scanning logic (extended) ---
async def fingerprint_device(ip: str, port: int, use_tls=False) -> Dict:
    probe_infos = []
    banner_info = {}
    # 1) Try ONVIF SOAP GetDeviceInformation (if onvif path exists)
    onvif = await probe_onvif_deviceinfo_http(ip, port, use_tls=use_tls, path='/onvif/device_service')
    if onvif.get('ok') and onvif.get('response'):
        info = parse_onvif_deviceinfo(onvif['response'])
        if info:
            probe_infos.append(info)
    # 2) Try common device info endpoints
    for p in ['/ISAPI/System/deviceInfo', '/deviceinfo', '/system/deviceinfo']:
        res = await probe_device_info_http(ip, port, use_tls=use_tls, path=p)
        if res.get('ok') and res.get('response'):
            gi = parse_generic_deviceinfo(res['response'])
            if gi:
                probe_infos.append(gi)
    # 3) Try a simple HTTP GET root and analyze
    ok, reader, writer = await tcp_connect(ip, port, use_ssl=use_tls)
    if ok:
        try:
            req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: cctv-scanner\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            resp = await read_banner(reader, max_bytes=8192)
            is_cam, found = analyze_response_for_camera(resp)
            banner_info = heuristics_from_banner_and_headers(resp)
            if is_cam and not probe_infos:
                # also store banner-level fields
                probe_infos.append({'manufacturer': found[0] if found else None})
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except:
                pass
    # Consolidate
    return consolidate_info(probe_infos, banner_info)

async def probe_single(ip: str, port: int, sem: asyncio.Semaphore) -> Dict:
    async with sem:
        for attempt in range(RETRY + 1):
            use_tls = (port in (443, 8443, 7443))
            ok, reader, writer = await tcp_connect(ip, port, timeout=CONNECT_TIMEOUT, use_ssl=use_tls)
            if not ok:
                # connection refused or timed out
                return {"ip": ip, "port": port, "open": False}
            # got a connection; decide probe by port
            try:
                result = {"ip": ip, "port": port, "open": True, "confirmed": False, "service": None, "details": None}
                if port in (554, 8554):
                    probe = await probe_rtsp(ip, port, reader, writer)
                    is_cam, found = analyze_response_for_camera(probe["response"])
                    result.update({"service": "rtsp", "details": probe["response"][:1000], "confirmed": is_cam, "tags": found})
                elif port in (80, 8080, 8000, 8443, 443, 8001, 8081):
                    probe = await probe_http(ip, port, reader, writer, use_tls=use_tls)
                    is_cam, found = analyze_response_for_camera(probe["response"])
                    result.update({"service": "http(s)", "details": probe["response"][:1500], "confirmed": is_cam, "tags": found})
                    # attempt fingerprinting (may reopen connections)
                    finfo = await fingerprint_device(ip, port, use_tls=use_tls)
                    result.update({"vendor": finfo.get('vendor'), "model": finfo.get('model'), "firmware": finfo.get('firmware')})
                else:
                    # generic banner read
                    banner = await read_banner(reader, max_bytes=1024)
                    is_cam, found = analyze_response_for_camera(banner)
                    result.update({"service": "banner", "details": banner[:600], "confirmed": is_cam, "tags": found})
                    finfo = await fingerprint_device(ip, port, use_tls=use_tls)
                    result.update({"vendor": finfo.get('vendor'), "model": finfo.get('model'), "firmware": finfo.get('firmware')})
                try:
                    writer.close()
                except:
                    pass
                await asyncio.sleep(0)
                # ensure vendor/model fields exist
                if 'vendor' not in result:
                    result.update({"vendor": 'unknown', "model": 'unknown', "firmware": 'unknown'})
                return result
            except Exception as e:
                try:
                    writer.close()
                except:
                    pass
                if attempt == RETRY:
                    return {"ip": ip, "port": port, "open": True, "confirmed": False, "error": str(e)}
                await asyncio.sleep(0.1)
        return {"ip": ip, "port": port, "open": False}

async def scan_ip_ports(ip: str, ports: List[int], concurrency=CONCURRENCY) -> List[Dict]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [probe_single(ip, p, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    return results

def expand_targets(targets: List[str]) -> List[str]:
    out = []
    for t in targets:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            for ip in net.hosts():
                out.append(str(ip))
        else:
            out.append(t)
    return out

async def main(args):
    targets = expand_targets(args.targets)
    all_results = []
    for ip in targets:
        print(f"[+] Scanning {ip}")
        res = await scan_ip_ports(ip, args.ports, concurrency=args.concurrency)
        for r in res:
            if r.get("open"):
                tag = "CONFIRMED_CAM" if r.get("confirmed") else "OPEN"
                print(f"  {ip}:{r['port']} -> {tag} ({r.get('service')}) vendor={r.get('vendor')} model={r.get('model')} firmware={r.get('firmware')}")
                if args.dump:
                    print("    details:", (r.get("details") or "")[:400].replace("\n", "\\n"))
        all_results.extend(res)
    if args.out:
        import json
        with open(args.out, "w") as f:
            json.dump(all_results, f, indent=2)
        print("[+] Results saved to", args.out)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="+", help="target IP or CIDR (e.g. 192.168.1.0/24 or 10.0.0.5)")
    parser.add_argument("--ports", nargs="*", type=int, default=PORTS)
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--out", default=None, help="save JSON to file")
    parser.add_argument("--dump", action="store_true", help="print details responses")
    args = parser.parse_args()
    asyncio.run(main(args))
