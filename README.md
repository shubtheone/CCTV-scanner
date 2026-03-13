## CCTV Scanner Toolkit

This repository contains several related scripts for discovering and fingerprinting IP cameras (CCTV) on a network or across large IP ranges.

### Available tools

- **`scan.py`**  
  Lightweight async TCP scanner for common CCTV-related ports with simple HTTP/RTSP/onvif probes.  
  - **Good for**: quick scans of small networks (home/office LAN).  
  - **Example**:  
    ```bash
    python3 scan.py 192.168.1.0/24 --dump
    ```

- **`latest.py`**  
  High‑performance, fully async scanner with:
  - multi‑stage discovery (fast TCP discovery, deep fingerprinting, optional UDP),
  - real‑time progress display,
  - adaptive timeouts,
  - JSON output summarising confirmed cameras with confidence levels and optional response snippets.
  - **Good for**: serious / larger scans, including loading targets from `.txt` files.
  - **Examples**:  
    ```bash
    # Fast scan of common ports
    python3 latest.py 192.168.1.0/24

    # Extended port set
    python3 latest.py 192.168.1.0/24 --extended

    # Include UDP scanning and save JSON
    python3 latest.py 192.168.1.0/24 --extended --udp -o results.json

    # Load targets from file
    python3 latest.py targets.txt --extended --udp -o results.json
    ```

- **`stages.py`**  
  “Unified CCTV scanner” workflow that orchestrates:
  1. Masscan for very fast port discovery over huge IP ranges (country‑level),
  2. banner grabbing and vendor fingerprinting,
  3. RTSP stream verification with `ffmpeg`,
  4. CSV/JSON reporting and checkpoint/resume.
  - **Good for**: large Internet‑wide / country‑wide scans when you have `masscan` and `ffmpeg` installed and root privileges.

### Recommended usage

- **Small / medium networks (LAN, DC subnets)**: use **`latest.py`**.  
- **Quick ad‑hoc tests**: `scan.py` is simple and easy to run.  
- **Mass‑scale Internet scanning**: use **`stages.py`** with `masscan` and `ffmpeg`.

### Requirements

- Python 3.8+  
- Recommended packages (standard library only is used; no third‑party deps required).  
- For `stages.py`:
  - `masscan` installed and in your `PATH` (root required),
  - `ffmpeg` installed and in your `PATH`.

### Notes

- Older experimental variants have been removed to avoid duplication; `scan.py`, `latest.py` and `stages.py` are the maintained entry points.  
- Always run large or high‑rate scans responsibly and only against networks you are authorised to test.

