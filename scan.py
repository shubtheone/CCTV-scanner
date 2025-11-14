#!/usr/bin/env python3
"""
cctv_scanner.py
Async IP+port scanner with protocol probes for CCTV/webcams.
Usage: python3 cctv_scanner.py 192.168.1.0/24
"""

import asyncio
import socket
import sys
import ipaddress
import argparse
from typing import List, Dict, Tuple

# --- Configuration ---
PORTS = [80, 443, 554, 8554, 8000, 8080, 8443, 37777, 34567, 5000, 9000, 23, 22, 21, 7070]
CONCURRENCY = 400
CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 2.0
RETRY = 1

CAMERA_KEYWORDS = ["hikvision", "dahua", "axis", "vivotek", "onvif", "amcrest", "camera", "dvr", "nvr"]

# --- Helper probes ---

async def tcp_connect(ip: str, port: int, timeout=CONNECT_TIMEOUT) -> Tuple[bool, asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        return True, reader, writer
    except Exception:
        return False, None, None

async def read_banner(reader: asyncio.StreamReader, max_bytes=1024, timeout=READ_TIMEOUT) -> str:
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data.decode(errors="ignore")
    except Exception:
        return ""

async def probe_rtsp(ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Dict:
    # Send RTSP OPTIONS
    path = f"rtsp://{ip}/"
    req = f"OPTIONS {path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: cctv-scanner\r\n\r\n"
    writer.write(req.encode())
    await writer.drain()
    resp = await read_banner(reader)
    return {"protocol":"rtsp", "response": resp}

async def probe_http(ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, use_tls=False) -> Dict:
    # Simple GET / probe
    req = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: cctv-scanner\r\nConnection: close\r\n\r\n" % ip
    writer.write(req.encode())
    await writer.drain()
    resp = await read_banner(reader, max_bytes=4096)
    return {"protocol":"http" if not use_tls else "https", "response": resp}

async def probe_onvif_try(ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Dict:
    # Try common ONVIF path
    req = "GET /onvif/device_service HTTP/1.1\r\nHost: %s\r\nUser-Agent: cctv-scanner\r\nConnection: close\r\n\r\n" % ip
    writer.write(req.encode())
    await writer.drain()
    resp = await read_banner(reader, max_bytes=4096)
    return {"protocol":"onvif", "response": resp}

# Simple confirmation logic
def analyze_response(resp: str) -> Tuple[bool, List[str]]:
    found = []
    lower = (resp or "").lower()
    for kw in CAMERA_KEYWORDS:
        if kw in lower:
            found.append(kw)
    is_cam = len(found) > 0
    return is_cam, found

# --- Main scanning logic ---

async def probe_single(ip: str, port: int, sem: asyncio.Semaphore) -> Dict:
    async with sem:
        for attempt in range(RETRY + 1):
            ok, reader, writer = await tcp_connect(ip, port)
            if not ok:
                # connection refused or timed out
                return {"ip": ip, "port": port, "open": False}
            # got a connection; decide probe by port
            try:
                result = {"ip": ip, "port": port, "open": True, "confirmed": False, "service": None, "details": None}
                if port in (554, 8554):
                    probe = await probe_rtsp(ip, port, reader, writer)
                    is_cam, found = analyze_response(probe["response"])
                    result.update({"service": "rtsp", "details": probe["response"][:1000], "confirmed": is_cam, "tags": found})
                elif port in (80, 8080, 8000, 8443, 443, 8001, 8081):
                    probe = await probe_http(ip, port, reader, writer, use_tls=(port in (443,8443)))
                    is_cam, found = analyze_response(probe["response"])
                    result.update({"service": "http(s)", "details": probe["response"][:1500], "confirmed": is_cam, "tags": found})
                    # also try ONVIF path if http probe didn't confirm
                    if not is_cam:
                        # reopen small connection for onvif (some servers close after first)
                        writer.close()
                        await asyncio.sleep(0.05)
                        ok2, r2, w2 = await tcp_connect(ip, port)
                        if ok2:
                            probe2 = await probe_onvif_try(ip, port, r2, w2)
                            is2, f2 = analyze_response(probe2["response"])
                            if is2:
                                result.update({"confirmed": True, "tags": f2, "details": (result["details"] or "") + "\nONVIF:" + probe2["response"][:800]})
                            w2.close()
                else:
                    # generic banner read
                    banner = await read_banner(reader, max_bytes=1024)
                    is_cam, found = analyze_response(banner)
                    result.update({"service": "banner", "details": banner[:600], "confirmed": is_cam, "tags": found})
                writer.close()
                await asyncio.sleep(0)
                return result
            except Exception as e:
                # Try again on error (up to RETRY)
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
        # filter results and print
        for r in res:
            if r.get("open"):
                tag = "CONFIRMED_CAM" if r.get("confirmed") else "OPEN"
                print(f"  {ip}:{r['port']} -> {tag} ({r.get('service')}) tags={r.get('tags')}")
                if args.dump:
                    print("    details:", (r.get("details") or "")[:400].replace("\n", "\\n"))
        all_results.extend(res)
    # optionally: write JSON output
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
