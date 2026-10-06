"""Unit tests for the pikvm_cli top-level package and CLI re-exports."""

from __future__ import annotations

import pikvm_cli
from pikvm_cli import PiKVMClient, PiKVMError, async_main, build_parser, main
from pikvm_cli.cli import (
    async_main as cli_async_main,
)
from pikvm_cli.cli import (
    build_parser as cli_build_parser,
)
from pikvm_cli.cli import (
    main as cli_main,
)
from pikvm_cli.client import PiKVMClient as ClientReExport


def test_pikvm_cli_exports() -> None:
    """Verify pikvm_cli top-level exports match expected public interface."""
    assert PiKVMClient is not None
    assert ClientReExport is PiKVMClient
    assert issubclass(PiKVMError, Exception)
    assert callable(main)
    assert callable(async_main)
    assert callable(build_parser)
    assert "PiKVMClient" in pikvm_cli.__all__
    assert "main" in pikvm_cli.__all__

    # Verify cli module re-exports
    assert cli_main is main
    assert cli_async_main is async_main
    assert cli_build_parser is build_parser
    parser = cli_build_parser()
    assert parser is not None


def test_pikvm_cli_main_invocation(monkeypatch) -> None:
    """Verify running pikvm_cli.cli as __main__ invokes main."""
    import runpy
    import sys
    from unittest.mock import MagicMock

    mock_main = MagicMock()
    monkeypatch.setattr("pikvm_aio.cli.main", mock_main)
    sys.modules.pop("pikvm_cli.cli", None)
    runpy.run_module("pikvm_cli.cli", run_name="__main__")
    assert mock_main.called


def test_pikvm_client_exports() -> None:
    """Verify pikvm_client top-level exports match expected public interface."""
    import pikvm_client
    from pikvm_client import PiKVMClient as ClientImport
    from pikvm_client.cli import main as client_main
    from pikvm_client.client import PiKVMClient as DirectClient

    assert ClientImport is PiKVMClient
    assert DirectClient is PiKVMClient
    assert callable(client_main)
    assert "PiKVMClient" in pikvm_client.__all__


def test_pikvm_client_main_invocation(monkeypatch) -> None:
    """Verify running pikvm_client.cli as __main__ invokes main."""
    import runpy
    import sys
    from unittest.mock import MagicMock

    mock_main = MagicMock()
    monkeypatch.setattr("pikvm_aio.cli.main", mock_main)
    sys.modules.pop("pikvm_client.cli", None)
    runpy.run_module("pikvm_client.cli", run_name="__main__")
    assert mock_main.called
