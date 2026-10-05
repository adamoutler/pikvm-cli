"""Command-line interface entrypoints for PiKVM-CLI."""

from __future__ import annotations

from pikvm_aio.cli import async_main, build_parser, main

__all__ = [
    "async_main",
    "build_parser",
    "main",
]

if __name__ == "__main__":
    main()
