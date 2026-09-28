#!/usr/bin/env python3
"""Diagnostic probe script for PiKVM devices.

Connects to a live PiKVM device, authenticates, queries all KVMD API endpoints,
extracts TLS certificate metadata, and displays a comprehensive diagnostic report.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from typing import Any
from urllib.parse import unquote, urlparse

# Ensure src/ is on python path when run from repo root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from pikvm_aio import (
    PiKVMAuthenticationError,
    PiKVMClient,
    PiKVMConnectionError,
    PiKVMError,
    PiKVMTimeoutError,
    fetch_remote_cert,
    format_url,
)
from pikvm_aio.tls import parse_host_port


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Probe and collect comprehensive diagnostics from a real PiKVM device.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s 192.168.1.108 -u admin -p admin -k
  %(prog)s https://admin:admin@192.168.1.108 -k
  %(prog)s 192.168.1.108 -k --output pikvm_report.json
  %(prog)s 192.168.1.108 -k --json | jq .
""",
    )

    parser.add_argument(
        "target",
        nargs="?",
        default=os.environ.get("PIKVM_HOST", "https://admin:admin@192.168.1.108"),
        help="PiKVM host, IP, or full URL (e.g., 192.168.1.108 or https://admin:admin@192.168.1.108)",
    )
    parser.add_argument(
        "-u",
        "--username",
        default=os.environ.get("PIKVM_USERNAME"),
        help="HTTP Basic Auth username (default: admin or parsed from URL)",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=os.environ.get("PIKVM_PASSWORD"),
        help="HTTP Basic Auth password (default: admin or parsed from URL)",
    )
    parser.add_argument(
        "-t",
        "--totp",
        default=os.environ.get("PIKVM_TOTP"),
        help="Optional TOTP base32 seed secret for 2FA",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        default=True,
        help="Allow connection without valid TLS cert (default: True for self-signed IP)",
    )
    parser.add_argument(
        "--secure",
        dest="insecure",
        action="store_false",
        help="Enforce strict SSL/TLS verification against system CA bundle",
    )
    parser.add_argument(
        "--cert",
        help="Path to PEM certificate to trust for SSL verification",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Network timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional path to write full diagnostic report as JSON file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON to stdout instead of formatted text report",
    )

    return parser.parse_args()


async def inspect_tls(target: str, timeout: float) -> dict[str, Any]:
    """Fetch and parse remote TLS certificate details."""
    hostname, port = parse_host_port(target)
    tls_info: dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "available": False,
        "fingerprint_sha256": None,
        "pem_length": 0,
        "pem": None,
        "error": None,
    }

    try:
        pem = await fetch_remote_cert(target, default_port=port, timeout=timeout)
        tls_info["available"] = True
        tls_info["pem_length"] = len(pem)
        tls_info["pem"] = pem

        # Calculate SHA-256 fingerprint from DER
        der = None
        try:
            import ssl

            der = ssl.PEM_cert_to_DER_cert(pem)
        except Exception:
            pass

        if der:
            fingerprint = hashlib.sha256(der).hexdigest()
            # Format as colon-separated hex pairs
            formatted = ":".join(
                fingerprint[i : i + 2].upper() for i in range(0, len(fingerprint), 2)
            )
            tls_info["fingerprint_sha256"] = formatted

    except Exception as err:
        tls_info["error"] = str(err)

    return tls_info


async def probe_device(
    host: str,
    username: str,
    password: str,
    totp: str | None,
    verify_ssl: bool,
    cert: str | None,
    timeout: float,
) -> dict[str, Any]:
    """Connect to PiKVM and query all available endpoints."""
    ssl_cert_content = None
    if cert and os.path.exists(cert):
        with open(cert, encoding="utf-8") as f:
            ssl_cert_content = f.read()
    elif cert:
        ssl_cert_content = cert

    async with PiKVMClient(
        host=host,
        username=username,
        password=password,
        totp_secret=totp,
        verify_ssl=verify_ssl,
        ssl_cert=ssl_cert_content,
        check_hostname=False,
        timeout=timeout,
    ) as client:
        # Check authentication first
        auth_status = {"authenticated": False, "error": None}
        try:
            await client.get_raw_auth_check()
            auth_status["authenticated"] = True
        except PiKVMAuthenticationError as err:
            auth_status["error"] = str(err)
            raise
        except Exception as err:
            auth_status["note"] = f"Auth check note: {err}"
            auth_status["authenticated"] = True

        # Query all endpoints
        info_model = await client.get_info()
        msd_model = await client.get_msd()
        atx_raw = await client.get_raw_atx()
        gpio_raw = await client.get_raw_gpio()
        hid_raw = await client.get_raw_hid()
        streamer_raw = await client.get_raw_streamer()

        return {
            "auth": auth_status,
            "models": {
                "name": info_model.name,
                "model": info_model.model,
                "serial": info_model.serial,
                "kvmd_version": info_model.kvmd_version,
                "cpu_temp": info_model.cpu_temp,
                "cpu_utilization": info_model.cpu_utilization,
                "memory_utilization": info_model.memory_utilization,
                "fan_speed": info_model.fan_speed,
                "is_throttled": info_model.is_throttled,
                "msd_enabled": msd_model.is_enabled,
                "msd_mounted": msd_model.drive.is_mounted,
                "msd_storage_total_mb": msd_model.storage.total_mb,
                "msd_storage_free_mb": msd_model.storage.free_mb,
                "msd_storage_used_mb": msd_model.storage.used_mb,
                "msd_storage_percent_used": msd_model.storage.percent_used,
                "msd_images": msd_model.storage.images,
            },
            "endpoints": {
                "info": info_model.raw,
                "msd": client.get_raw_msd.__name__,
                "atx": atx_raw,
                "gpio": gpio_raw,
                "hid": hid_raw,
                "streamer": streamer_raw,
            },
        }


def print_report(data: dict[str, Any]) -> None:
    """Print a clean, structured diagnostic report to the terminal."""
    models = data.get("models", {})
    endpoints = data.get("endpoints", {})
    info_raw = endpoints.get("info", {})
    tls_info = data.get("tls", {})

    platform_raw = info_raw.get("hw", {}).get("platform", {})
    system_raw = info_raw.get("system", {})
    kernel_raw = system_raw.get("kernel", {})
    uptime_raw = info_raw.get("uptime", {}).get("parts", {})
    atx_raw = endpoints.get("atx", {})
    hid_raw = endpoints.get("hid", {})
    streamer_raw = endpoints.get("streamer", {})

    print("=" * 72)
    print(f"  PiKVM Diagnostic Report: {models.get('name', 'PiKVM')}")
    print("=" * 72)

    print("\n[ Device Identity & Platform ]")
    print(f"  Hostname / Server : {models.get('name')}")
    print(f"  Hardware Model    : {models.get('model')}")
    print(f"  Serial Number     : {models.get('serial')}")
    print(f"  Base Board        : {platform_raw.get('base', 'Unknown')}")
    print(f"  KVMD Version      : {models.get('kvmd_version', 'Unknown')}")
    kernel_desc = (
        f"{kernel_raw.get('system', '')} {kernel_raw.get('release', '')} "
        f"({kernel_raw.get('machine', '')})"
    )
    print(f"  Linux Kernel      : {kernel_desc}")
    if uptime_raw:
        uptime_desc = (
            f"{uptime_raw.get('days', 0)}d {uptime_raw.get('hours', 0)}h "
            f"{uptime_raw.get('minutes', 0)}m {uptime_raw.get('seconds', 0)}s"
        )
        print(f"  System Uptime     : {uptime_desc}")

    print("\n[ TLS & Security ]")
    print(f"  TLS Handshake     : {'OK' if tls_info.get('available') else 'Failed'}")
    if tls_info.get("fingerprint_sha256"):
        print(f"  SHA-256 Fingerprint: {tls_info.get('fingerprint_sha256')}")
    if tls_info.get("error"):
        print(f"  TLS Error         : {tls_info.get('error')}")

    print("\n[ Hardware Health & Performance ]")
    cpu_temp = models.get("cpu_temp")
    print(f"  CPU Temperature   : {f'{cpu_temp:.1f} °C' if cpu_temp is not None else 'N/A'}")
    cpu_util = models.get("cpu_utilization")
    print(f"  CPU Utilization   : {f'{cpu_util}%' if cpu_util is not None else 'N/A'}")
    mem_util = models.get("memory_utilization")
    print(f"  RAM Utilization   : {f'{mem_util}%' if mem_util is not None else 'N/A'}")
    fan_speed = models.get("fan_speed")
    print(f"  Fan Speed         : {f'{fan_speed} RPM' if fan_speed is not None else 'N/A'}")
    print(f"  Throttling Active : {models.get('is_throttled', False)}")

    print("\n[ Virtual Media (MSD) ]")
    print(f"  MSD Subsystem     : {'Enabled' if models.get('msd_enabled') else 'Disabled'}")
    print(f"  Drive Connected   : {models.get('msd_mounted', False)}")
    tot_mb = models.get("msd_storage_total_mb")
    free_mb = models.get("msd_storage_free_mb")
    used_pct = models.get("msd_storage_percent_used")
    if tot_mb is not None:
        print(f"  Storage Capacity  : {tot_mb:,.1f} MB (Free: {free_mb:,.1f} MB, {used_pct}% used)")
    images = models.get("msd_images", {})
    print(f"  Available Images  : {len(images)}")
    for img_name, img_size in images.items():
        size_mb = round(img_size / (1024 * 1024), 1)
        print(f"    - {img_name} ({size_mb:,.1f} MB)")

    print("\n[ ATX Power Controller ]")
    print(f"  Controller Enabled: {atx_raw.get('enabled', False)}")
    leds = atx_raw.get("leds", {})
    print(f"  Power LED State   : {'ON' if leds.get('power') else 'OFF'}")
    print(f"  HDD LED State     : {'ON' if leds.get('hdd') else 'OFF'}")

    print("\n[ HID & Video Streamer ]")
    mouse_mode = hid_raw.get("mouse", {}).get("outputs", {}).get("active", "N/A")
    print(f"  Mouse Active Mode : {mouse_mode}")
    jiggler = hid_raw.get("jiggler", {})
    print(f"  HID Jiggler       : {'Enabled' if jiggler.get('enabled') else 'Disabled'}")

    stream_conf = streamer_raw.get("streamer", {})
    encoder = stream_conf.get("encoder", {}).get("type", "Unknown")
    source = stream_conf.get("source", {})
    res = source.get("resolution", {})
    print(f"  Video Encoder     : {encoder}")
    if res:
        w, h = res.get("width", 0), res.get("height", 0)
        fps = source.get("captured_fps", 0)
        print(f"  Capture Resolution: {w}x{h} @ {fps} FPS")

    print("\n" + "=" * 72)
    print("  Report successfully collected from all KVMD endpoints.")
    print("=" * 72 + "\n")


async def main() -> int:
    """Main execution coroutine."""
    args = parse_arguments()

    # Parse target URL and credentials
    target = args.target.strip()
    parsed = urlparse(target if "://" in target else f"https://{target}")

    username = args.username or (unquote(parsed.username) if parsed.username else "admin")
    password = args.password or (unquote(parsed.password) if parsed.password else "admin")

    clean_host = format_url(target)

    # 1. Fetch TLS details
    tls_details = await inspect_tls(clean_host, args.timeout)

    # 2. Probe device endpoints
    try:
        probe_data = await probe_device(
            host=clean_host,
            username=username,
            password=password,
            totp=args.totp,
            verify_ssl=not args.insecure,
            cert=args.cert,
            timeout=args.timeout,
        )
    except PiKVMAuthenticationError as err:
        print(f"Error: Authentication failed for {clean_host}: {err}", file=sys.stderr)
        return 1
    except (PiKVMConnectionError, PiKVMTimeoutError) as err:
        print(f"Error: Connection failed to {clean_host}: {err}", file=sys.stderr)
        return 1
    except PiKVMError as err:
        print(f"Error: PiKVM API error from {clean_host}: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected error querying {clean_host}: {err}", file=sys.stderr)
        return 2

    # Consolidate complete report
    report: dict[str, Any] = {
        "target": clean_host,
        "tls": tls_details,
        "models": probe_data["models"],
        "endpoints": probe_data["endpoints"],
    }

    # Write output to file if requested
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            if not args.json:
                print(f"[+] Saved diagnostic report to {args.output}")
        except OSError as err:
            print(f"Warning: Could not write output file {args.output}: {err}", file=sys.stderr)

    # Display report
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
