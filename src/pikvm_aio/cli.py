"""Command-line interface (`pikvm-cli`) for PiKVM devices."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from .client import PiKVMClient
from .exceptions import PiKVMError
from .tls import fetch_remote_cert


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="pikvm-cli",
        description="Command-line interface for PiKVM hardware and kvmd REST API.",
    )

    parser.add_argument(
        "-H",
        "--host",
        default=os.environ.get("PIKVM_HOST"),
        help="PiKVM host or URL (env: PIKVM_HOST)",
    )
    parser.add_argument(
        "-u",
        "--username",
        default=os.environ.get("PIKVM_USERNAME", "admin"),
        help="HTTP Basic Auth username (env: PIKVM_USERNAME, default: admin)",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=os.environ.get("PIKVM_PASSWORD", "admin"),
        help="HTTP Basic Auth password (env: PIKVM_PASSWORD, default: admin)",
    )
    parser.add_argument(
        "-t",
        "--totp",
        default=os.environ.get("PIKVM_TOTP"),
        help="TOTP base32 seed secret for 2FA (env: PIKVM_TOTP)",
    )
    parser.add_argument(
        "-c",
        "--cert",
        default=os.environ.get("PIKVM_CERT"),
        help="Path to PEM certificate file or raw PEM string (env: PIKVM_CERT)",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable SSL/TLS certificate verification",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted text",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: info
    subparsers.add_parser("info", help="Show system, hardware, and device information")

    # Subcommand: health
    subparsers.add_parser(
        "health", help="Show hardware health (temperature, throttling, fan speed)"
    )

    # Subcommand: msd
    subparsers.add_parser(
        "msd", help="Show Mass Storage Device (MSD) status and storage partitions"
    )

    # Subcommand: power
    power_parser = subparsers.add_parser("power", help="Execute an ATX power action")
    power_parser.add_argument(
        "action",
        choices=["click", "long", "reset", "off"],
        help="Power action to perform",
    )

    # Subcommand: fetch-cert
    cert_parser = subparsers.add_parser(
        "fetch-cert",
        help="Fetch the remote SSL/TLS certificate from the PiKVM host and print PEM",
    )
    cert_parser.add_argument(
        "-o",
        "--output",
        help="Optional file path to save certificate PEM to",
    )

    return parser


def _load_cert(cert_input: str | None) -> str | None:
    if not cert_input:
        return None
    if os.path.exists(cert_input):
        with open(cert_input, encoding="utf-8") as f:
            return f.read()
    return cert_input


def _print_formatted(data: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
        return

    for key, value in data.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for sub_k, sub_v in value.items():
                print(f"  {sub_k}: {sub_v}")
        else:
            print(f"{key}: {value}")


async def async_main(args: argparse.Namespace) -> int:
    """Async CLI entry point."""
    if not args.host:
        print(
            "Error: PiKVM host not specified. Use --host or set PIKVM_HOST env var.",
            file=sys.stderr,
        )
        return 1

    cert_content = _load_cert(args.cert)

    if args.command == "fetch-cert":
        try:
            pem = await fetch_remote_cert(args.host, timeout=args.timeout)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(pem)
                print(f"Certificate successfully written to {args.output}")
            else:
                print(pem)
            return 0
        except PiKVMError as err:
            print(f"Error fetching certificate: {err}", file=sys.stderr)
            return 1

    client = PiKVMClient(
        host=args.host,
        username=args.username,
        password=args.password,
        totp_secret=args.totp,
        verify_ssl=not args.insecure,
        ssl_cert=cert_content,
        check_hostname=not args.insecure and cert_content is None,
        timeout=args.timeout,
    )

    try:
        async with client:
            if args.command == "info":
                info = await client.get_info()
                output = {
                    "Name": info.name,
                    "Model": info.model,
                    "Serial": info.serial,
                    "KVMD Version": info.kvmd_version or "Unknown",
                    "CPU Temperature": f"{info.cpu_temp} °C" if info.cpu_temp else "N/A",
                    "CPU Utilization": f"{info.cpu_utilization} %"
                    if info.cpu_utilization
                    else "N/A",
                    "Memory Utilization": f"{info.memory_utilization} %"
                    if info.memory_utilization
                    else "N/A",
                    "Throttled": info.is_throttled,
                    "MSD Enabled": info.msd.is_enabled,
                    "MSD Mounted": info.msd.drive.is_mounted,
                }
                _print_formatted(output if not args.json else info.raw, args.json)

            elif args.command == "health":
                info = await client.get_info()
                health = info.hw.health
                output = {
                    "CPU Temperature": f"{health.cpu_temp} °C" if health.cpu_temp else "N/A",
                    "Throttled": health.throttling.is_throttled,
                    "Raw Throttling Flags": hex(health.throttling.raw_flags),
                    "Throttling Flags": list(health.throttling.text_flags),
                    "Undervoltage Now": health.throttling.undervoltage_now,
                    "Undervoltage Past": health.throttling.undervoltage_past,
                    "Fan Speed": f"{info.fan_speed} RPM" if info.fan_speed else "N/A",
                }
                _print_formatted(output, args.json)

            elif args.command == "msd":
                msd = await client.get_msd()
                output = {
                    "Enabled": msd.is_enabled,
                    "Drive Mounted": msd.drive.is_mounted,
                    "Total Storage (MB)": msd.storage.total_mb,
                    "Free Storage (MB)": msd.storage.free_mb,
                    "Used Storage (MB)": msd.storage.used_mb,
                    "Percent Used": f"{msd.storage.percent_used} %"
                    if msd.storage.percent_used
                    else "N/A",
                    "Images Count": len(msd.storage.images),
                    "Images": msd.storage.images,
                }
                _print_formatted(output, args.json)

            elif args.command == "power":
                action = args.action
                success = await client.power_action(action)
                if args.json:
                    print(json.dumps({"success": success, "action": action}))
                else:
                    status = "succeeded" if success else "failed"
                    print(f"ATX power action '{action}' {status}.")
                return 0 if success else 1

        return 0

    except PiKVMError as err:
        print(f"PiKVM Error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected Error: {err}", file=sys.stderr)
        return 2


def main() -> None:
    """CLI script entry point."""
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
