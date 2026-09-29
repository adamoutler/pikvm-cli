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

KNOWN_COMMANDS = {"info", "health", "msd", "power", "fetch-cert", "collect"}


def normalize_cli_args(argv: list[str]) -> list[str]:
    """Normalize CLI arguments to support positional host and flexible placement."""
    if not argv or "-h" in argv or "--help" in argv:
        return argv

    subcommand_value_flags = {"-o", "--output"}
    root_value_flags = {
        "-H",
        "--host",
        "-u",
        "--username",
        "-p",
        "--password",
        "-t",
        "--totp",
        "-c",
        "--cert",
        "--timeout",
    }

    root_flags: list[str] = []
    subcommand_args: list[str] = []
    extracted_target: str | None = None
    command_found: str | None = None
    has_host_flag = False

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in subcommand_value_flags:
            subcommand_args.append(arg)
            if i + 1 < len(argv):
                subcommand_args.append(argv[i + 1])
                i += 2
            else:
                i += 1
            continue
        if arg in root_value_flags:
            if arg in ("-H", "--host"):
                has_host_flag = True
            root_flags.append(arg)
            if i + 1 < len(argv):
                root_flags.append(argv[i + 1])
                i += 2
            else:
                i += 1
            continue
        if arg.startswith("-"):
            # All boolean options (--json, -k, --accept-any-cert, etc.) belong to root
            root_flags.append(arg)
            i += 1
            continue
        if arg in KNOWN_COMMANDS and command_found is None:
            command_found = arg
            i += 1
            continue
        if not has_host_flag and extracted_target is None:
            extracted_target = arg
            i += 1
            continue
        subcommand_args.append(arg)
        i += 1

    final_cmd = command_found or "info"
    result: list[str] = []
    if extracted_target:
        result.extend(["-H", extracted_target])
    result.extend(root_flags)
    result.append(final_cmd)
    result.extend(subcommand_args)
    return result


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
        help="TOTP base32 seed secret or 6/8-digit token (env: PIKVM_TOTP)",
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
        "--accept-any-cert",
        dest="insecure",
        action="store_true",
        default=bool(os.environ.get("PIKVM_INSECURE") or os.environ.get("PIKVM_ACCEPT_ANY_CERT")),
        help=(
            "Accept any SSL/TLS certificate at the host (ignore self-signed, expired, "
            "or hostname mismatches). Env: PIKVM_ACCEPT_ANY_CERT / PIKVM_INSECURE"
        ),
    )
    parser.add_argument(
        "--verify-ssl",
        dest="insecure",
        action="store_false",
        help="Enforce strict SSL/TLS verification (disables --accept-any-cert)",
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

    subparsers = parser.add_subparsers(dest="command", required=False)
    parser.set_defaults(command="info")

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

    # Subcommand: collect
    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect all diagnostic and operational data from the PiKVM device",
    )
    collect_parser.add_argument(
        "-o",
        "--output",
        help="Optional file path to save full diagnostic JSON report to",
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
                if not args.json:
                    print(f"Certificate successfully written to {args.output}")
            if args.json:
                print(json.dumps({"host": args.host, "certificate": pem}, indent=2))
            elif not args.output:
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

            elif args.command == "collect":
                info = await client.get_info()
                msd = await client.get_msd()
                diag = await client.get_all_diagnostics()
                output = {
                    "Device": {
                        "Name": info.name,
                        "Model": info.model,
                        "Serial": info.serial,
                        "KVMD Version": info.kvmd_version,
                    },
                    "Performance": {
                        "CPU Temperature": f"{info.cpu_temp} °C" if info.cpu_temp else "N/A",
                        "CPU Utilization": f"{info.cpu_utilization} %"
                        if info.cpu_utilization
                        else "N/A",
                        "Memory Utilization": f"{info.memory_utilization} %"
                        if info.memory_utilization
                        else "N/A",
                        "Fan Speed": f"{info.fan_speed} RPM" if info.fan_speed else "N/A",
                        "Throttled": info.is_throttled,
                    },
                    "MSD": {
                        "Enabled": msd.is_enabled,
                        "Drive Mounted": msd.drive.is_mounted,
                        "Total Storage (MB)": msd.storage.total_mb,
                        "Free Storage (MB)": msd.storage.free_mb,
                        "Used Storage (MB)": msd.storage.used_mb,
                        "Percent Used": f"{msd.storage.percent_used} %"
                        if msd.storage.percent_used
                        else "N/A",
                        "Images": msd.storage.images,
                    },
                    "ATX": diag.get("atx", {}),
                    "GPIO": diag.get("gpio", {}),
                    "HID": diag.get("hid", {}),
                    "Streamer": diag.get("streamer", {}),
                }
                if getattr(args, "output", None):
                    with open(args.output, "w", encoding="utf-8") as f:
                        json.dump(output, f, indent=2)
                    if not args.json:
                        print(f"Saved diagnostic report to {args.output}")
                _print_formatted(output, args.json)

        return 0

    except PiKVMError as err:
        print(f"PiKVM Error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected Error: {err}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> None:
    """CLI script entry point."""
    if argv is None:
        argv = sys.argv[1:]
    normalized = normalize_cli_args(argv)
    parser = build_parser()
    args = parser.parse_args(normalized)
    sys.exit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
