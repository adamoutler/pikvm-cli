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
from .models import HidMacro, MsdUploadProgress
from .security import scrub_process_argv
from .tls import fetch_remote_cert, get_cert_fingerprint

KNOWN_COMMANDS = {
    "info",
    "health",
    "msd",
    "power",
    "fetch-cert",
    "collect",
    "iso",
    "hid",
    "ocr",
    "gpio",
}


def normalize_cli_args(argv: list[str]) -> list[str]:
    """Normalize CLI arguments to support positional host and flexible placement."""
    if not argv:
        return argv

    subcommand_value_flags = {
        "-o",
        "--output",
        "--name",
        "--chunk-size",
        "--keymap",
        "--delay",
        "--button",
        "--to",
        "--file",
        "--langs",
        "--box",
        "--xywh",
    }
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
    root_boolean_flags = {
        "--json",
        "-k",
        "--insecure",
        "--accept-any-cert",
        "--verify-ssl",
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
        if arg in root_boolean_flags:
            root_flags.append(arg)
            i += 1
            continue
        if arg.startswith("-"):
            if command_found is not None:
                subcommand_args.append(arg)
            else:
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
        description=(
            "PiKVM-CLI: Out-of-band Command-Line Interface and Automation Client "
            "for PiKVM Hardware and kvmd REST API."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  pikvm-cli 192.168.1.50 info\n"
            "  pikvm-cli 192.168.1.50 iso upload /path/to/installer.iso\n"
            "  pikvm-cli 192.168.1.50 iso mount installer.iso\n"
            '  pikvm-cli 192.168.1.50 hid text "uptime"\n'
            "  pikvm-cli 192.168.1.50 hid shortcut ControlLeft AltLeft Delete\n"
            "  pikvm-cli 192.168.1.50 ocr --xywh 0,0,300,100\n"
            "  pikvm-cli 192.168.1.50 gpio read\n"
            "  pikvm-cli 192.168.1.50 gpio pulse power_button\n"
        ),
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
        choices=[
            "click",
            "long",
            "reset",
            "off",
            "power",
            "power_long",
            "on",
            "off_hard",
            "reset_hard",
        ],
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

    # Subcommand: iso
    iso_parser = subparsers.add_parser("iso", help="Manage virtual ISO images and MSD drive")
    iso_sub = iso_parser.add_subparsers(dest="iso_action", required=True)

    iso_upload = iso_sub.add_parser(
        "upload", help="Stream a local ISO/IMG file to PiKVM MSD storage"
    )
    iso_upload.add_argument("file", help="Path to local .iso or .img file")
    iso_upload.add_argument("--name", help="Custom destination filename on PiKVM")
    iso_upload.add_argument(
        "--no-remove-incomplete",
        dest="remove_incomplete",
        action="store_false",
        default=True,
        help="Keep partial file if upload fails (default: remove incomplete)",
    )

    iso_dl = iso_sub.add_parser(
        "download", help="Trigger PiKVM to download an ISO from a remote URL"
    )
    iso_dl.add_argument("url", help="HTTP(S) download URL")
    iso_dl.add_argument("--name", help="Destination image filename")

    iso_mount = iso_sub.add_parser("mount", help="Mount and connect an ISO into the virtual drive")
    iso_mount.add_argument("image", help="Image filename already stored in MSD")
    iso_mount.add_argument("--rw", action="store_true", help="Mount in read-write mode")
    iso_mount.add_argument(
        "--flash", action="store_true", help="Emulate Flash drive instead of CD-ROM"
    )
    iso_mount.add_argument(
        "--no-connect", action="store_true", help="Mount without connecting USB drive to target"
    )

    iso_unmount = iso_sub.add_parser("unmount", help="Disconnect and eject current virtual drive")
    iso_unmount.add_argument(
        "--keep-connected", action="store_true", help="Eject image without disconnecting USB drive"
    )

    iso_rm = iso_sub.add_parser("remove", help="Delete an ISO image from PiKVM storage")
    iso_rm.add_argument("image", help="Image filename to delete")

    iso_sub.add_parser("reset", help="Reset MSD to default factory configuration")

    # Subcommand: hid
    hid_parser = subparsers.add_parser("hid", help="Remote keyboard and mouse automation")
    hid_sub = hid_parser.add_subparsers(dest="hid_action", required=True)

    hid_key = hid_sub.add_parser("key", help="Send a single key press or release event")
    hid_key.add_argument("key", help="Key name (e.g. Enter, KeyA, Escape, Backspace, ControlLeft)")
    hid_key.add_argument("--release", action="store_true", help="Release key instead of pressing")
    hid_key.add_argument("--finish", action="store_true", help="Mark event as finish")

    hid_tap = hid_sub.add_parser("tap", help="Tap a key (press and immediate release)")
    hid_tap.add_argument("key", help="Key to tap (e.g. Enter, KeyA, Tab)")
    hid_tap.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Key hold duration in seconds (default: 0.05)",
    )

    hid_text = hid_sub.add_parser("text", help="Type arbitrary text remotely")
    hid_text.add_argument("text", help="Text string to type")
    hid_text.add_argument("--keymap", help="Target keyboard layout (e.g. en-us, de, fr)")
    hid_text.add_argument("--delay", type=float, help="Inter-keystroke delay in seconds")
    hid_text.add_argument("--slow", action="store_true", help="Enable slow typing mode")

    hid_sc = hid_sub.add_parser(
        "shortcut", help="Send a hotkey combination (e.g. ControlLeft AltLeft Delete)"
    )
    hid_sc.add_argument("keys", nargs="+", help="Keys in combination")

    hid_click = hid_sub.add_parser("click", help="Click mouse button with optional coordinate move")
    hid_click.add_argument(
        "--button",
        choices=["left", "right", "middle"],
        default="left",
        help="Mouse button (default: left)",
    )
    hid_click.add_argument("--to", help="Target coordinate X,Y (e.g. 100,200)")
    hid_click.add_argument("--double", action="store_true", help="Perform double click")

    hid_macro = hid_sub.add_parser("macro", help="Manage and replay PiKVM recorder scripts")
    hid_macro_sub = hid_macro.add_subparsers(dest="macro_action", required=True)
    macro_run = hid_macro_sub.add_parser("run", help="Replay a PiKVM UI recorder script JSON file")
    macro_run.add_argument("file", help="Path to script.json file downloaded from PiKVM Web UI")

    # Subcommand: ocr
    ocr_parser = subparsers.add_parser("ocr", help="Extract text from screen via PiKVM OCR")
    ocr_parser.add_argument("--box", help="Bounding box as left,top,right,bottom (e.g. 0,2,281,81)")
    ocr_parser.add_argument("--xywh", help="Bounding box as x,y,width,height (e.g. 0,2,281,79)")
    ocr_parser.add_argument("--langs", default="eng", help="OCR languages (default: eng)")

    # Subcommand: gpio
    gpio_parser = subparsers.add_parser("gpio", help="Inspect and control user GPIO channels")
    gpio_sub = gpio_parser.add_subparsers(dest="gpio_action", required=True)

    gpio_sub.add_parser("read", help="Read raw GPIO state and scheme")

    gpio_sw = gpio_sub.add_parser("switch", help="Switch an output GPIO channel on or off")
    gpio_sw.add_argument("channel", help="Channel identifier")
    gpio_sw.add_argument(
        "state", choices=["on", "off", "1", "0", "true", "false"], help="Target state"
    )
    gpio_sw.add_argument("--wait", action="store_true", help="Wait for operation to complete")

    gpio_pulse = gpio_sub.add_parser(
        "pulse", help="Send a momentary pulse to an output GPIO channel"
    )
    gpio_pulse.add_argument("channel", help="Channel identifier")
    gpio_pulse.add_argument("--delay", type=float, help="Pulse duration in seconds")
    gpio_pulse.add_argument("--wait", action="store_true", help="Wait for operation to complete")

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

    # Support reading password from stdin via '-p -'
    if args.password == "-":
        args.password = sys.stdin.readline().rstrip("\r\n")

    # Support reading TOTP token from stdin via '-t -'
    if args.totp == "-":
        args.totp = sys.stdin.readline().rstrip("\r\n")

    # Security warning on Linux /proc/<pid>/cmdline exposure when raw password passed via CLI flag
    if any(arg in ("-p", "--password") or arg.startswith("--password=") for arg in sys.argv):
        if args.password and args.password != "-":
            print(
                "Security Warning: Passing passwords via command-line flags is insecure. "
                "Credentials can be viewed via /proc/<pid>/cmdline and 'ps aux'. "
                "Use the PIKVM_PASSWORD environment variable or '-p -' (stdin) instead.",
                file=sys.stderr,
            )

    cert_content = _load_cert(args.cert)

    if args.command == "fetch-cert":
        try:
            pem = await fetch_remote_cert(args.host, timeout=args.timeout)
            fingerprint = get_cert_fingerprint(pem)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(pem)
                if not args.json:
                    print(f"Certificate successfully written to {args.output}")
                    print(f"SHA256 Fingerprint: {fingerprint}")
            if args.json:
                print(
                    json.dumps(
                        {"host": args.host, "certificate": pem, "fingerprint": fingerprint},
                        indent=2,
                    )
                )
            elif not args.output:
                print(pem)
                print(f"SHA256 Fingerprint: {fingerprint}")
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

            elif args.command == "iso":
                action = args.iso_action
                if action == "upload":

                    def progress_cb(p: MsdUploadProgress) -> None:
                        if not args.json:
                            print(
                                f"\rUploading {os.path.basename(args.file)}: {p.percent}% "
                                f"({p.speed_mbps} MB/s)",
                                end="",
                                flush=True,
                            )

                    success = await client.upload_msd_image(
                        file_path=args.file,
                        image_name=args.name,
                        remove_incomplete=args.remove_incomplete,
                        progress_callback=progress_cb,
                    )
                    if not args.json:
                        print("\nUpload completed successfully." if success else "\nUpload failed.")
                    else:
                        print(json.dumps({"success": success, "file": args.file}))
                    return 0 if success else 1

                elif action == "download":
                    async for prog in client.download_msd_remote(
                        url=args.url, image_name=args.name
                    ):
                        if args.json:
                            print(json.dumps(prog.raw))
                        else:
                            pct_str = f"{prog.percent}%" if prog.percent is not None else ""
                            print(
                                f"\rDownloading: {prog.written_bytes} bytes {pct_str}",
                                end="",
                                flush=True,
                            )
                    if not args.json:
                        print("\nDownload finished.")
                    return 0

                elif action == "mount":
                    success = await client.mount_msd_image(
                        image=args.image,
                        cdrom=not args.flash,
                        rw=args.rw,
                        connect=not args.no_connect,
                    )
                    if args.json:
                        print(json.dumps({"success": success, "image": args.image}))
                    else:
                        status = "mounted" if success else "failed to mount"
                        print(f"Image '{args.image}' {status}.")
                    return 0 if success else 1

                elif action == "unmount":
                    success = await client.unmount_msd_image(disconnect=not args.keep_connected)
                    if args.json:
                        print(json.dumps({"success": success}))
                    else:
                        status = "unmounted" if success else "failed to unmount"
                        print(f"Virtual drive {status}.")
                    return 0 if success else 1

                elif action == "remove":
                    success = await client.remove_msd_image(args.image)
                    if args.json:
                        print(json.dumps({"success": success, "image": args.image}))
                    else:
                        status = "removed" if success else "failed to remove"
                        print(f"Image '{args.image}' {status}.")
                    return 0 if success else 1

                elif action == "reset":
                    success = await client.reset_msd()
                    if args.json:
                        print(json.dumps({"success": success}))
                    else:
                        status = "succeeded" if success else "failed"
                        print(f"MSD reset {status}.")
                    return 0 if success else 1

            elif args.command == "hid":
                action = args.hid_action
                if action == "key":
                    state = False if args.release else True
                    success = await client.send_key(args.key, state=state, finish=args.finish)
                    if args.json:
                        print(json.dumps({"success": success, "key": args.key}))
                    else:
                        status = "sent" if success else "failed"
                        print(f"Key '{args.key}' {status}.")
                    return 0 if success else 1

                elif action == "tap":
                    success = await client.tap_key(args.key, delay=args.delay)
                    if args.json:
                        print(json.dumps({"success": success, "key": args.key}))
                    else:
                        status = "tapped" if success else "failed"
                        print(f"Key '{args.key}' {status}.")
                    return 0 if success else 1

                elif action == "text":
                    success = await client.print_text(
                        text=args.text, keymap=args.keymap, delay=args.delay, slow=args.slow
                    )
                    if args.json:
                        print(json.dumps({"success": success, "text": args.text}))
                    else:
                        status = "typed" if success else "failed"
                        print(f"Text {status}.")
                    return 0 if success else 1

                elif action == "shortcut":
                    success = await client.send_shortcut(args.keys)
                    if args.json:
                        print(json.dumps({"success": success, "keys": args.keys}))
                    else:
                        status = "sent" if success else "failed"
                        print(f"Shortcut {' '.join(args.keys)} {status}.")
                    return 0 if success else 1

                elif action == "click":
                    to_x = to_y = None
                    if args.to:
                        parts = args.to.split(",")
                        to_x, to_y = int(parts[0]), int(parts[1])
                    success = await client.click_mouse(
                        button=args.button, to_x=to_x, to_y=to_y, double_click=args.double
                    )
                    if args.json:
                        print(json.dumps({"success": success, "button": args.button}))
                    else:
                        status = "clicked" if success else "failed"
                        print(f"Mouse button '{args.button}' {status}.")
                    return 0 if success else 1

                elif action == "macro":
                    if args.macro_action == "run":
                        with open(args.file, encoding="utf-8") as f:
                            raw_steps = json.load(f)
                        macro = HidMacro.from_list(raw_steps)
                        results = await client.play_macro(macro)
                        all_ok = all(results)
                        if args.json:
                            print(json.dumps({"success": all_ok, "steps": len(results)}))
                        else:
                            status = "completed" if all_ok else "encountered errors"
                            print(f"Macro replay {status} ({len(results)} steps executed).")
                        return 0 if all_ok else 1

            elif args.command == "ocr":
                left = top = right = bottom = -1
                if args.box:
                    parts = [int(p.strip()) for p in args.box.split(",")]
                    left, top, right, bottom = parts[0], parts[1], parts[2], parts[3]
                elif args.xywh:
                    parts = [int(p.strip()) for p in args.xywh.split(",")]
                    x, y, w, h = parts[0], parts[1], parts[2], parts[3]
                    left, top, right, bottom = x, y, x + w, y + h

                text = await client.get_ocr_text(
                    left=left, top=top, right=right, bottom=bottom, langs=args.langs
                )
                if args.json:
                    print(
                        json.dumps(
                            {
                                "text": text,
                                "langs": args.langs,
                                "box": {"left": left, "top": top, "right": right, "bottom": bottom},
                            },
                            indent=2,
                        )
                    )
                else:
                    print(text)
                return 0

            elif args.command == "gpio":
                action = args.gpio_action
                if action == "read":
                    gpio_data = await client.read_gpio()
                    _print_formatted(gpio_data, args.json)
                    return 0

                elif action == "switch":
                    target_state = args.state in ("on", "1", "true")
                    success = await client.switch_gpio(
                        args.channel, state=target_state, wait=args.wait
                    )
                    if args.json:
                        payload = {
                            "success": success,
                            "channel": args.channel,
                            "state": target_state,
                        }
                        print(json.dumps(payload))
                    else:
                        status = "switched" if success else "failed"
                        print(f"GPIO '{args.channel}' {status} to {args.state}.")
                    return 0 if success else 1

                elif action == "pulse":
                    success = await client.pulse_gpio(
                        args.channel, delay=args.delay, wait=args.wait
                    )
                    if args.json:
                        print(json.dumps({"success": success, "channel": args.channel}))
                    else:
                        status = "pulsed" if success else "failed"
                        print(f"GPIO '{args.channel}' {status}.")
                    return 0 if success else 1

        return 0

    except PiKVMError as err:
        print(f"PiKVM Error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected Error: {err}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> None:
    """CLI script entry point."""
    raw_argv = argv if argv is not None else sys.argv[1:]
    normalized = normalize_cli_args(raw_argv)
    parser = build_parser()
    args = parser.parse_args(normalized)

    # Scrub process memory arguments AFTER parse_args has extracted credentials
    # into the args namespace.
    scrub_process_argv()
    if argv is not None:
        scrub_process_argv(argv)

    sys.exit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
