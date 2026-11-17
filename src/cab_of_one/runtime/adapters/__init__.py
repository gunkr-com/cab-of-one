"""Write-surface adapters for the S3 classifier.

Each module exposes ``NAME``, ``matches(argv, ctx)``, ``classify(argv, ctx) -> Result``
and ``scan_text(text) -> list[Result]``. ``argv`` is a sequence of
``classification_types.Arg`` whose first item is the program word. All functions
are pure; the only I/O path is ``ctx.load_script``, which the guard supplies.
``scan_text`` is for opaque text and always returns unknown-admin results.
"""

from __future__ import annotations

from . import azure_cli, graph_http, m365_powershell, simtenant

ADAPTERS = (simtenant, m365_powershell, azure_cli, graph_http)
ADAPTER_NAMES = tuple(a.NAME for a in ADAPTERS)

__all__ = ["ADAPTERS", "ADAPTER_NAMES", "azure_cli", "graph_http", "m365_powershell", "simtenant"]
